//! npm registry client. Wraps `https://registry.npmjs.org`.
//!
//! Fetches the abbreviated packument plus the per-version metadata needed by
//! downstream signals.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const REGISTRY_BASE: &str = "https://registry.npmjs.org";
const USER_AGENT: &str = concat!("npmguard/", env!("CARGO_PKG_VERSION"));

/// Subset of the npm packument we care about. Many fields are intentionally
/// untyped (`serde_json::Value`) — we only deserialize what we score on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub resolved_version: String,
    pub published_at: Option<DateTime<Utc>>,
    pub maintainers: Vec<Maintainer>,
    pub scripts: HashMap<String, String>,
    pub repository_url: Option<String>,
    pub deprecated: Option<String>,
    /// All known version strings, sorted by publish time descending if available.
    pub all_versions: Vec<String>,
    /// publish time for *each* version (ISO8601) — used to detect ownership-churn windows.
    pub time_map: HashMap<String, DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Maintainer {
    pub name: String,
    pub email: Option<String>,
}

pub struct NpmRegistryClient {
    http: reqwest::Client,
}

impl NpmRegistryClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("building reqwest client")?;
        Ok(Self { http })
    }

    /// Fetch the full packument and project it into `PackageMetadata` for the
    /// requested version (or `latest` dist-tag if `version` is `None`).
    pub async fn fetch(&self, name: &str, version: Option<&str>) -> Result<PackageMetadata> {
        // Use the verbose packument (no Accept: application/vnd.npm.install-v1+json)
        // because we need `time` and `maintainers` per version.
        let url = format!("{}/{}", REGISTRY_BASE, encode_pkg_name(name));
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {}", url))?;
        if !resp.status().is_success() {
            anyhow::bail!("registry returned {} for {}", resp.status(), name);
        }
        let raw: serde_json::Value = resp.json().await.context("parsing registry json")?;
        project_metadata(name, version, &raw)
    }
}

fn encode_pkg_name(name: &str) -> String {
    // Scoped packages: '@scope/name' is sent as '@scope%2Fname'.
    if let Some(stripped) = name.strip_prefix('@') {
        if let Some((scope, rest)) = stripped.split_once('/') {
            return format!("@{}%2F{}", scope, rest);
        }
    }
    name.to_string()
}

fn project_metadata(
    name: &str,
    requested_version: Option<&str>,
    raw: &serde_json::Value,
) -> Result<PackageMetadata> {
    let dist_tags = raw.get("dist-tags").and_then(|v| v.get("latest"));
    let resolved_version = match requested_version {
        Some(v) => v.to_string(),
        None => dist_tags
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .context("registry response missing dist-tags.latest")?,
    };

    let version_obj = raw
        .get("versions")
        .and_then(|v| v.get(&resolved_version))
        .with_context(|| {
            format!(
                "version {} not found in registry packument",
                resolved_version
            )
        })?;

    let scripts = version_obj
        .get("scripts")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();

    let maintainers = version_obj
        .get("maintainers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    let name = m.get("name")?.as_str()?.to_string();
                    let email = m
                        .get("email")
                        .and_then(|e| e.as_str())
                        .map(|s| s.to_string());
                    Some(Maintainer { name, email })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let repository_url = version_obj
        .get("repository")
        .and_then(|r| match r {
            serde_json::Value::Object(o) => o.get("url").and_then(|u| u.as_str()),
            serde_json::Value::String(s) => Some(s.as_str()),
            _ => None,
        })
        .map(normalize_repo_url);

    let deprecated = version_obj
        .get("deprecated")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let time_obj = raw.get("time").and_then(|v| v.as_object());
    let time_map: HashMap<String, DateTime<Utc>> = time_obj
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| {
                    let s = v.as_str()?;
                    let parsed = DateTime::parse_from_rfc3339(s).ok()?.with_timezone(&Utc);
                    Some((k.clone(), parsed))
                })
                .collect()
        })
        .unwrap_or_default();

    let published_at = time_map.get(&resolved_version).cloned();

    let mut all_versions: Vec<String> = raw
        .get("versions")
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    // Sort by publish time desc when known, else lexicographic.
    all_versions.sort_by(|a, b| match (time_map.get(a), time_map.get(b)) {
        (Some(ta), Some(tb)) => tb.cmp(ta),
        _ => b.cmp(a),
    });

    Ok(PackageMetadata {
        name: name.to_string(),
        resolved_version,
        published_at,
        maintainers,
        scripts,
        repository_url,
        deprecated,
        all_versions,
        time_map,
    })
}

fn normalize_repo_url(s: &str) -> String {
    // Strip common prefixes: 'git+', 'git://', trailing '.git'.
    let mut out = s.trim().to_string();
    if let Some(rest) = out.strip_prefix("git+") {
        out = rest.to_string();
    }
    if let Some(rest) = out.strip_prefix("git://") {
        out = format!("https://{}", rest);
    }
    if let Some(rest) = out.strip_prefix("git@github.com:") {
        out = format!("https://github.com/{}", rest);
    }
    if let Some(rest) = out.strip_suffix(".git") {
        out = rest.to_string();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_scoped_name() {
        assert_eq!(encode_pkg_name("lodash"), "lodash");
        assert_eq!(encode_pkg_name("@ctrl/tinycolor"), "@ctrl%2Ftinycolor");
    }

    #[test]
    fn normalizes_repo_url() {
        assert_eq!(
            normalize_repo_url("git+https://github.com/lodash/lodash.git"),
            "https://github.com/lodash/lodash"
        );
        assert_eq!(
            normalize_repo_url("git@github.com:foo/bar.git"),
            "https://github.com/foo/bar"
        );
    }
}
