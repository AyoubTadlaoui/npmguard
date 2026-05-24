//! npm registry client. Wraps `https://registry.npmjs.org`.
//!
//! Fetches the abbreviated packument plus the per-version metadata needed by
//! downstream signals.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
        let raw = self.fetch_raw(name).await?;
        project_metadata(name, version, &raw)
    }

    /// Fetch the full packument and project it into a `Packument`: the per
    /// version `dependencies` / `optionalDependencies` maps plus `dist-tags`,
    /// which is all the dependency-closure resolver needs. Reuses the same
    /// fetch path (and 16 MiB guard) as `fetch`.
    pub async fn fetch_packument(&self, name: &str) -> Result<Packument> {
        // Closure resolution only needs each version's dependency maps and the
        // dist-tags, so request the abbreviated packument
        // (`application/vnd.npm.install-v1+json`). It is far smaller than the
        // verbose document, which keeps popular packages (e.g. `next`, `npm`)
        // under the body cap instead of being skipped, and cuts bandwidth.
        let raw = self.fetch_raw_abbreviated(name).await?;
        Ok(project_packument(&raw))
    }

    /// Fetch the verbose packument JSON. Used by `fetch` because its projection
    /// needs per-version `time` and `maintainers`, which the abbreviated
    /// document omits.
    async fn fetch_raw(&self, name: &str) -> Result<serde_json::Value> {
        self.get_packument(name, false).await
    }

    /// Fetch the abbreviated packument (`application/vnd.npm.install-v1+json`):
    /// versions with their dependency maps plus dist-tags. Used by the
    /// dependency-closure resolver.
    async fn fetch_raw_abbreviated(&self, name: &str) -> Result<serde_json::Value> {
        self.get_packument(name, true).await
    }

    /// Shared GET, body-cap guard, and JSON parse for both packument flavours.
    /// A packument that exceeds the cap is either malformed or adversarial, so
    /// we bail rather than materialise the whole body in memory.
    async fn get_packument(&self, name: &str, abbreviated: bool) -> Result<serde_json::Value> {
        let url = format!("{}/{}", REGISTRY_BASE, encode_pkg_name(name));
        let mut req = self.http.get(&url);
        if abbreviated {
            req = req.header(
                reqwest::header::ACCEPT,
                "application/vnd.npm.install-v1+json",
            );
        }
        let resp = req.send().await.with_context(|| format!("GET {}", url))?;
        if !resp.status().is_success() {
            anyhow::bail!("registry returned {} for {}", resp.status(), name);
        }
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
        serde_json::from_slice(&bytes).context("parsing registry json")
    }
}

/// A parsed packument projection for dependency-closure resolution. Carries only
/// what the resolver scores on: each published version's runtime and optional
/// dependency ranges, plus the `dist-tags` map (so a `latest` / `*` range can be
/// resolved without a second fetch).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Packument {
    /// Published version string to its dependency maps. `BTreeMap` so the key
    /// set is deterministic; range resolution parses keys into semver `Version`s.
    pub versions: BTreeMap<String, VersionDeps>,
    /// dist-tag name (e.g. `latest`, `next`) to the version it points at.
    pub dist_tags: HashMap<String, String>,
}

/// One published version's dependency maps, as declared in its package.json.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionDeps {
    /// Runtime dependencies (name to semver range).
    pub dependencies: HashMap<String, String>,
    /// Optional dependencies (name to semver range).
    pub optional_dependencies: HashMap<String, String>,
}

/// Project the raw packument JSON into a `Packument`. Tolerant of missing
/// fields: a packument with no `versions` yields an empty map rather than an
/// error, so a malformed entry never aborts the closure walk.
fn project_packument(raw: &serde_json::Value) -> Packument {
    let versions = raw
        .get("versions")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .map(|(ver, obj)| {
                    (
                        ver.clone(),
                        VersionDeps {
                            dependencies: extract_string_map(obj, "dependencies"),
                            optional_dependencies: extract_string_map(obj, "optionalDependencies"),
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let dist_tags = raw
        .get("dist-tags")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Packument {
        versions,
        dist_tags,
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

    #[test]
    fn projects_packument_versions_and_tags() {
        let raw = serde_json::json!({
            "dist-tags": { "latest": "2.0.0", "next": "3.0.0-rc.1" },
            "versions": {
                "1.0.0": {
                    "dependencies": { "left-pad": "^1.0.0" },
                    "optionalDependencies": { "fsevents": "~2.3.0" }
                },
                "2.0.0": {
                    "dependencies": { "left-pad": "^1.3.0" }
                }
            }
        });
        let p = project_packument(&raw);
        assert_eq!(p.dist_tags.get("latest").map(String::as_str), Some("2.0.0"));
        assert_eq!(p.versions.len(), 2);
        assert_eq!(
            p.versions["1.0.0"].dependencies.get("left-pad").unwrap(),
            "^1.0.0"
        );
        assert_eq!(
            p.versions["1.0.0"]
                .optional_dependencies
                .get("fsevents")
                .unwrap(),
            "~2.3.0"
        );
        // A version without optionalDependencies projects to an empty map, not
        // a missing key.
        assert!(p.versions["2.0.0"].optional_dependencies.is_empty());
    }

    #[test]
    fn projects_empty_packument_without_panicking() {
        let p = project_packument(&serde_json::json!({}));
        assert!(p.versions.is_empty());
        assert!(p.dist_tags.is_empty());
    }
}
