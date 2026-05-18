//! Shared types used across the workspace. Keep this surface small and stable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A reference to an npm package, optionally pinned to a specific version.
/// `version = None` means "evaluate the latest version published to the registry".
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageRef {
    pub name: String,
    pub version: Option<String>,
}

impl PackageRef {
    pub fn new(name: impl Into<String>, version: Option<String>) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }

    /// Parse `name`, `name@version`, or `@scope/name@version`.
    pub fn parse(spec: &str) -> anyhow::Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            anyhow::bail!("empty package spec");
        }
        // Handle scoped packages: split on the LAST '@' only if it isn't at index 0.
        let last_at = spec.rmatch_indices('@').next().map(|(i, _)| i);
        match last_at {
            Some(0) | None => Ok(Self {
                name: spec.to_string(),
                version: None,
            }),
            Some(i) => {
                let (name, ver) = spec.split_at(i);
                let version = ver.trim_start_matches('@').to_string();
                if version.is_empty() {
                    Ok(Self {
                        name: name.to_string(),
                        version: None,
                    })
                } else {
                    Ok(Self {
                        name: name.to_string(),
                        version: Some(version),
                    })
                }
            }
        }
    }

    pub fn display(&self) -> String {
        match &self.version {
            Some(v) => format!("{}@{}", self.name, v),
            None => self.name.clone(),
        }
    }
}

/// Verdict bucket. Drives the CLI's exit code and prompt behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Ok,
    Warn,
    Block,
}

impl RiskLevel {
    pub fn exit_code(self) -> i32 {
        match self {
            RiskLevel::Ok => 0,
            RiskLevel::Warn => 0, // prompt may still abort
            RiskLevel::Block => 2,
        }
    }
}

/// Categories of risk signal. Adding a variant is a public API change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    LifecycleScripts,
    PackageAge,
    MaintainerChurn,
    RepoHealth,
    Typosquat,
    KnownCve,
    SoleMaintainer,
    Deprecated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    pub kind: SignalKind,
    pub points: u32,
    pub detail: String,
}

/// A composite risk verdict for a single (package, version) pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskVerdict {
    pub package: PackageRef,
    /// Resolved version that was actually evaluated.
    pub resolved_version: String,
    /// Sum of signal points. 0..=200 in practice.
    pub score: u32,
    pub level: RiskLevel,
    pub signals: Vec<Signal>,
    /// When the verdict was computed.
    pub fetched_at: DateTime<Utc>,
    /// Hash of the active signal set, for cache invalidation when scoring changes.
    pub signal_set_hash: String,
}

/// Stable hash for the active signal configuration. Cached verdicts computed
/// under a different signal set are considered stale.
#[derive(Debug, Clone, Copy)]
pub struct SignalSetHash;

impl SignalSetHash {
    /// Compute a hash over the active signal kinds and the scoring thresholds.
    pub fn compute(kinds: &[SignalKind], thresholds: &crate::scoring::Thresholds) -> String {
        let mut h = Sha256::new();
        h.update(b"npmguard-risk:v1\n");
        let mut sorted: Vec<&SignalKind> = kinds.iter().collect();
        sorted.sort_by_key(|k| format!("{:?}", k));
        for k in sorted {
            h.update(format!("{:?}\n", k).as_bytes());
        }
        h.update(format!("warn={},block={}\n", thresholds.warn, thresholds.block).as_bytes());
        hex::encode(&h.finalize()[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_name() {
        let p = PackageRef::parse("lodash").unwrap();
        assert_eq!(p.name, "lodash");
        assert_eq!(p.version, None);
    }

    #[test]
    fn parses_name_version() {
        let p = PackageRef::parse("lodash@4.17.21").unwrap();
        assert_eq!(p.name, "lodash");
        assert_eq!(p.version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn parses_scoped_no_version() {
        let p = PackageRef::parse("@ctrl/tinycolor").unwrap();
        assert_eq!(p.name, "@ctrl/tinycolor");
        assert_eq!(p.version, None);
    }

    #[test]
    fn parses_scoped_with_version() {
        let p = PackageRef::parse("@ctrl/tinycolor@4.0.0").unwrap();
        assert_eq!(p.name, "@ctrl/tinycolor");
        assert_eq!(p.version.as_deref(), Some("4.0.0"));
    }

    #[test]
    fn rejects_empty() {
        assert!(PackageRef::parse("").is_err());
        assert!(PackageRef::parse("   ").is_err());
    }
}
