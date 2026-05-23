//! The risk engine. Owns the http client and orchestrates parallel signal fetches.

use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;

use crate::scoring::{compute_level, Thresholds};
use crate::signals::{self, registry::NpmRegistryClient, PackageMetadata};
use crate::types::{PackageRef, RiskVerdict, SignalKind, SignalSetHash};

pub struct RiskEngine {
    registry: NpmRegistryClient,
    /// Shared HTTP client. A single pool covers registry, OSV, and GitHub
    /// calls: one set of connections, one timeout/UA configuration.
    http: Arc<reqwest::Client>,
    thresholds: Thresholds,
    /// Active signal kinds, in evaluation order. Drives the cache hash.
    active: Vec<SignalKind>,
}

impl RiskEngine {
    pub fn new() -> Result<Self> {
        let http = Arc::new(
            reqwest::Client::builder()
                .user_agent(concat!("npmguard/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
        );
        Ok(Self {
            registry: NpmRegistryClient::with_client(Arc::clone(&http)),
            http,
            thresholds: Thresholds::default(),
            active: vec![
                SignalKind::LifecycleScripts,
                SignalKind::PackageAge,
                SignalKind::MaintainerChurn,
                SignalKind::SoleMaintainer,
                SignalKind::RepoHealth,
                SignalKind::Typosquat,
                SignalKind::KnownCve,
                SignalKind::Deprecated,
                SignalKind::ReleaseAnomaly,
            ],
        })
    }

    pub fn with_thresholds(mut self, t: Thresholds) -> Self {
        self.thresholds = t;
        self
    }

    pub fn thresholds(&self) -> &Thresholds {
        &self.thresholds
    }

    pub fn signal_set_hash(&self) -> String {
        SignalSetHash::compute(&self.active, &self.thresholds)
    }

    /// Fetch the registry packument and project it into `PackageMetadata`.
    /// Exposed so callers can layer a cache lookup between metadata fetch and
    /// the full evaluation (which also fires OSV + GitHub HTTP).
    pub async fn fetch_metadata(&self, pkg: &PackageRef) -> Result<PackageMetadata> {
        self.registry.fetch(&pkg.name, pkg.version.as_deref()).await
    }

    /// Compose a verdict from a pre-fetched `PackageMetadata`. Runs OSV +
    /// GitHub signals concurrently. Use this with `fetch_metadata` when you
    /// want to consult a cache between the two steps.
    pub async fn evaluate_from_metadata(
        &self,
        pkg: &PackageRef,
        meta: PackageMetadata,
    ) -> Result<RiskVerdict> {
        // Pure-from-metadata signals.
        let mut signals = Vec::new();
        signals.extend(signals::lifecycle::evaluate(&meta));
        signals.extend(signals::age::evaluate(&meta));
        signals.extend(signals::maintainers::evaluate(&meta));
        signals.extend(signals::deprecated::evaluate(&meta));
        signals.extend(signals::release_anomaly::evaluate(&meta));
        signals.extend(signals::typosquat::evaluate(pkg));

        // Network-dependent signals; run concurrently.
        let osv_fut = signals::osv::evaluate(&self.http, pkg, &meta.resolved_version);
        let gh_fut = signals::github::evaluate(&self.http, &meta);
        let (osv_res, gh_res) = futures::future::join(osv_fut, gh_fut).await;
        match osv_res {
            Ok(s) => signals.extend(s),
            Err(e) => tracing::warn!("osv signal failed: {}", e),
        }
        match gh_res {
            Ok(s) => signals.extend(s),
            Err(e) => tracing::warn!("github signal failed: {}", e),
        }

        let score: u32 = signals.iter().map(|s| s.points).sum::<u32>().min(200);
        let level = compute_level(score, &self.thresholds);
        Ok(RiskVerdict {
            package: pkg.clone(),
            resolved_version: meta.resolved_version,
            score,
            level,
            signals,
            fetched_at: Utc::now(),
            published_at: meta.published_at,
            signal_set_hash: self.signal_set_hash(),
        })
    }

    /// Convenience: fetch metadata + evaluate in one call. No cache.
    pub async fn evaluate(&self, pkg: &PackageRef) -> Result<RiskVerdict> {
        let meta = self.fetch_metadata(pkg).await?;
        self.evaluate_from_metadata(pkg, meta).await
    }
}
