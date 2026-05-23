//! npm registry client. Wraps `https://registry.npmjs.org`.
//!
//! Fetches the abbreviated packument plus the per-version metadata needed by
//! downstream signals.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

const REGISTRY_BASE: &str = "https://registry.npmjs.org";

/// Hard cap on registry packument response body size (16 MiB).
/// Packuments for even the busiest monorepos top out well below this; anything
/// larger is almost certainly a misconfigured proxy or an adversarial response.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Subset of the npm packument we care about. Many fields are intentionally
/// untyped (`serde_json::Value`); we only deserialize what we score on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub resolved_version: String,
    pub published_at: Option<DateTime<Utc>>,
    pub maintainers: Vec<Maintainer>,
    pub scripts: HashMap<String, String>,
    /// Top-level runtime dependencies of the resolved version (name → range).
    pub dependencies: HashMap<String, String>,
    pub repository_url: Option<String>,
    pub deprecated: Option<String>,
    /// All known version strings, sorted by publish time descending if available.
    pub all_versions: Vec<String>,
    /// publish time for *each* version (ISO8601), used to detect ownership-churn windows.
    pub time_map: HashMap<String, DateTime<Utc>>,
    /// The version published immediately before the resolved one (by publish
    /// time), projected for release-to-release diffing. `None` when the resolved
    /// version is the first release or publish times are unavailable.
    pub previous_version: Option<PreviousVersion>,
}

/// A prior published version, projected down to the fields the release-anomaly
/// signal diffs against the resolved version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousVersion {
    pub version: String,
    pub scripts: HashMap<String, String>,
    pub dependencies: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Maintainer {
    pub name: String,
    pub email: Option<String>,
}

pub struct NpmRegistryClient {
    /// Shared HTTP client, owned by the engine, borrowed here via `Arc` so
    /// the entire workspace uses a single connection pool with uniform
    /// timeout / User-Agent configuration.
    http: Arc<reqwest::Client>,
}

impl NpmRegistryClient {
    /// Construct a client that borrows the engine's shared `reqwest::Client`.
    pub fn with_client(http: Arc<reqwest::Client>) -> Self {
        Self { http }
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

        // Guard against oversized responses before deserializing. A packument
        // that exceeds the cap is either malformed or adversarial; bail loudly
        // rather than materialising the whole body in memory.
        if let Some(len) = resp.content_length() {
            if len as usize > MAX_BODY_BYTES {
                anyhow::bail!(
                    "registry response for {} is {} bytes, exceeds {} MiB cap",
                    name,
                    len,
                    MAX_BODY_BYTES / 1024 / 1024
                );
            }
        }
        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("reading registry body for {}", name))?;
        if bytes.len() > MAX_BODY_BYTES {
            anyhow::bail!(
                "registry response body for {} is {} bytes, exceeds {} MiB cap",
                name,
                bytes.len(),
                MAX_BODY_BYTES / 1024 / 1024
            );
        }
        let raw: serde_json::Value =
            serde_json::from_slice(&bytes).context("parsing registry json")?;
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

    let scripts = extract_string_map(version_obj, "scripts");
    let dependencies = extract_string_map(version_obj, "dependencies");

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

    let previous_version = select_previous_version(raw, &resolved_version, &time_map);

    Ok(PackageMetadata {
        name: name.to_string(),
        resolved_version,
        published_at,
        maintainers,
        scripts,
        dependencies,
        repository_url,
        deprecated,
        all_versions,
        time_map,
        previous_version,
    })
}

/// Project a JSON `version_obj`'s string-valued `key` map (e.g. `scripts`,
/// `dependencies`) into a `HashMap`. Non-string values are skipped.
fn extract_string_map(version_obj: &serde_json::Value, key: &str) -> HashMap<String, String> {
    version_obj
        .get(key)
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// A semver version is a prerelease when its core (before any `+build`) carries
/// a `-` suffix, e.g. `1.2.0-rc.1`.
fn is_prerelease(v: &str) -> bool {
    v.split('+').next().is_some_and(|core| core.contains('-'))
}

/// Pick the version published immediately before `resolved` (strictly older by
/// publish time) and project the fields the release-anomaly signal needs.
///
/// Prefers a stable (non-prerelease) predecessor so a stable release is diffed
/// against the prior stable release rather than an intervening canary; falls
/// back to any predecessor when the resolved version is itself a prerelease or
/// no stable predecessor exists. Compares `time_map` values directly rather than
/// trusting `all_versions` adjacency, whose lexicographic fallback is unreliable
/// when some versions lack a publish time.
fn select_previous_version(
    raw: &serde_json::Value,
    resolved: &str,
    time_map: &HashMap<String, DateTime<Utc>>,
) -> Option<PreviousVersion> {
    let resolved_time = time_map.get(resolved)?;
    let versions = raw.get("versions").and_then(|v| v.as_object())?;

    let mut best: Option<(&String, &DateTime<Utc>)> = None;
    let mut best_stable: Option<(&String, &DateTime<Utc>)> = None;
    for (ver, t) in time_map.iter() {
        // `time` carries "created"/"modified" keys and possibly versions absent
        // from `versions`; only real, strictly-older versions are candidates.
        if ver == resolved || t >= resolved_time || !versions.contains_key(ver) {
            continue;
        }
        if best.map_or(true, |(_, bt)| t > bt) {
            best = Some((ver, t));
        }
        if !is_prerelease(ver) && best_stable.map_or(true, |(_, bt)| t > bt) {
            best_stable = Some((ver, t));
        }
    }

    let (prev_ver, _) = if is_prerelease(resolved) {
        best
    } else {
        best_stable.or(best)
    }?;
    let prev_obj = versions.get(prev_ver)?;
    Some(PreviousVersion {
        version: prev_ver.clone(),
        scripts: extract_string_map(prev_obj, "scripts"),
        dependencies: extract_string_map(prev_obj, "dependencies"),
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
