//! The risk engine. Owns the http client and orchestrates parallel signal fetches.

use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;

use crate::closure::{self, ClosureReport};
use crate::resolver::{self, ResolveOpts};
use crate::scoring::{compute_level, Thresholds};
use crate::signals::{self, registry::NpmRegistryClient, PackageMetadata};
use crate::types::{PackageRef, RiskVerdict, Signal, SignalKind, SignalSetHash};

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
                SignalKind::SecurityHolding,
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
        signals.extend(signals::security_holding::evaluate(&meta));
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

    /// Build a hard-block verdict for a package the npm registry no longer serves
    /// (HTTP 404 / [`PackageNotFound`](crate::signals::registry::PackageNotFound))
    /// when OSV confirms the name is malware.
    ///
    /// A 404 is what npm returns after taking a malicious package down, so rather
    /// than degrading to "could not verify" the caller consults OSV by name: a
    /// `MAL-*` advisory for a removed package is unambiguous and blocks.
    ///
    /// Returns `Ok(None)` when OSV has no malicious-package advisory for the name
    /// (a genuinely unknown / never-published package), so the caller can keep its
    /// existing not-found handling (a soft "could not verify").
    pub async fn malware_verdict_for_removed(
        &self,
        pkg: &PackageRef,
    ) -> Result<Option<RiskVerdict>> {
        let mal_ids = signals::osv::malware_advisories_for_name(&self.http, &pkg.name).await?;
        Ok(build_removed_malware_verdict(
            pkg,
            &mal_ids,
            &self.thresholds,
            self.signal_set_hash(),
        ))
    }

    /// Scan the package's full transitive dependency closure for malware.
    ///
    /// Resolves the root version (the same way `evaluate` does), walks its
    /// direct and transitive runtime dependencies into a deduped, bounded
    /// closure, batch-queries OSV for malicious-package advisories, and folds in
    /// the local `-security` takedown-stub check. The root itself is not part of
    /// the returned closure; callers evaluate the root separately. All network
    /// work is best-effort: a failed fetch is logged and skipped, never aborting
    /// the scan.
    pub async fn evaluate_closure(
        &self,
        pkg: &PackageRef,
        opts: &ResolveOpts,
    ) -> Result<ClosureReport> {
        let meta = self.fetch_metadata(pkg).await?;
        let nodes =
            resolver::resolve_closure(&self.registry, &pkg.name, &meta.resolved_version, opts)
                .await?;
        closure::evaluate_closure_nodes(&self.http, nodes).await
    }
}

/// Pure constructor for the removed-package malware verdict. Given the OSV
/// malicious-package advisory ids for a name npm no longer serves, build a
/// hard-block verdict, or `None` when there are no such advisories. Kept pure
/// (no I/O) so the block decision is unit-testable without a network round-trip.
fn build_removed_malware_verdict(
    pkg: &PackageRef,
    mal_ids: &[String],
    thresholds: &Thresholds,
    signal_set_hash: String,
) -> Option<RiskVerdict> {
    if mal_ids.is_empty() {
        return None;
    }
    let shown = mal_ids
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let extra = if mal_ids.len() > 3 {
        format!(" (+{} more)", mal_ids.len() - 3)
    } else {
        String::new()
    };
    let signal = Signal {
        kind: SignalKind::KnownCve,
        // Max points: removed from npm AND OSV-confirmed malware is the most
        // certain block the engine can issue.
        points: 200,
        detail: format!(
            "npm has removed this package (404); OSV confirms {} malicious-package advisory(ies): {}{}",
            mal_ids.len(),
            shown,
            extra
        ),
    };
    let score = signal.points.min(200);
    let level = compute_level(score, thresholds);
    Some(RiskVerdict {
        package: pkg.clone(),
        resolved_version: pkg.version.clone().unwrap_or_else(|| "removed".to_string()),
        score,
        level,
        signals: vec![signal],
        fetched_at: Utc::now(),
        published_at: None,
        signal_set_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RiskLevel;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn detail(v: &RiskVerdict) -> String {
        v.signals
            .iter()
            .map(|s| s.detail.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn no_malware_ids_yields_no_verdict() {
        let pkg = PackageRef::new("ghost-pkg", None);
        assert!(
            build_removed_malware_verdict(&pkg, &[], &Thresholds::default(), "h".into()).is_none()
        );
    }

    #[test]
    fn confirmed_malware_removal_blocks() {
        let pkg = PackageRef::new("evil-pkg", Some("1.0.0".into()));
        let v = build_removed_malware_verdict(
            &pkg,
            &ids(&["MAL-2025-1"]),
            &Thresholds::default(),
            "h".into(),
        )
        .expect("a removed + malicious package must produce a verdict");
        assert_eq!(v.level, RiskLevel::Block);
        assert_eq!(v.score, 200);
        assert_eq!(v.resolved_version, "1.0.0");
        assert_eq!(v.signals.len(), 1);
        assert_eq!(v.signals[0].kind, SignalKind::KnownCve);
        assert!(detail(&v).contains("MAL-2025-1"));
        assert!(detail(&v).contains("removed"));
    }

    #[test]
    fn resolved_version_defaults_when_unpinned() {
        let pkg = PackageRef::new("evil-pkg", None);
        let v = build_removed_malware_verdict(
            &pkg,
            &ids(&["MAL-2025-1"]),
            &Thresholds::default(),
            "h".into(),
        )
        .unwrap();
        assert_eq!(v.resolved_version, "removed");
    }

    #[test]
    fn many_advisories_summarised_with_overflow() {
        let pkg = PackageRef::new("evil-pkg", None);
        let v = build_removed_malware_verdict(
            &pkg,
            &ids(&["MAL-1", "MAL-2", "MAL-3", "MAL-4", "MAL-5"]),
            &Thresholds::default(),
            "h".into(),
        )
        .unwrap();
        assert!(detail(&v).contains("+2 more"));
        assert_eq!(v.level, RiskLevel::Block);
    }
}
