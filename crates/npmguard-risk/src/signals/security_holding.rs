//! npm security-holding placeholder detection.
//!
//! When npm removes a package (almost always after malware is reported), the
//! name is not deleted: a placeholder version with a `-security` prerelease tag
//! is published in its place, with a README explaining the original code was
//! removed. The resolved version therefore ends in `-security`.
//!
//! This is a strong, network-independent malware signal. It also covers the
//! case where OSV is unreachable or has not yet indexed the takedown: the
//! `-security` suffix is set by npm's own security team at removal time.

use crate::signals::registry::PackageMetadata;
use crate::types::{Signal, SignalKind};

/// npm's security-holding placeholder convention: the resolved version carries
/// a `-security` prerelease tag.
const SECURITY_HOLDING_SUFFIX: &str = "-security";

pub fn evaluate(meta: &PackageMetadata) -> Vec<Signal> {
    if !meta.resolved_version.ends_with(SECURITY_HOLDING_SUFFIX) {
        return Vec::new();
    }
    vec![Signal {
        kind: SignalKind::SecurityHolding,
        // Single-signal block; see scoring thresholds (block = 70).
        points: 80,
        detail: format!(
            "npm security-holding placeholder version `{}`. the original package was removed, typically after malware. this name resolves to a dead stub, not real code.",
            meta.resolved_version
        ),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::registry::PackageMetadata;
    use std::collections::HashMap;

    fn meta_with_version(version: &str) -> PackageMetadata {
        PackageMetadata {
            name: "lodahs".into(),
            resolved_version: version.into(),
            published_at: None,
            maintainers: Vec::new(),
            scripts: HashMap::new(),
            dependencies: HashMap::new(),
            repository_url: None,
            deprecated: None,
            all_versions: Vec::new(),
            time_map: HashMap::new(),
            previous_version: None,
        }
    }

    #[test]
    fn security_placeholder_fires_block_tier() {
        let sigs = evaluate(&meta_with_version("0.0.1-security"));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::SecurityHolding);
        assert_eq!(sigs[0].points, 80);
    }

    #[test]
    fn another_security_placeholder_fires() {
        let sigs = evaluate(&meta_with_version("2.0.0-security"));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].points, 80);
    }

    #[test]
    fn plain_release_is_silent() {
        assert!(evaluate(&meta_with_version("1.2.3")).is_empty());
    }

    #[test]
    fn unrelated_prerelease_is_silent() {
        // Only the `-security` suffix is npm's holding convention; a normal
        // prerelease tag must not trip this.
        assert!(evaluate(&meta_with_version("1.0.0-beta.1")).is_empty());
        assert!(evaluate(&meta_with_version("3.1.0-rc.2")).is_empty());
    }
}
