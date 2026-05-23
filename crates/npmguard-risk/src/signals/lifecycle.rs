//! Lifecycle script signals.
//!
//! npm runs `preinstall`, `install`, and `postinstall` automatically. These are
//! the primary attack vector in Shai-Hulud-style incidents; code in any of
//! these executes the moment a downstream project runs `npm install`.

use crate::signals::registry::PackageMetadata;
use crate::types::{Signal, SignalKind};

const LIFECYCLE_KEYS: &[&str] = &["preinstall", "install", "postinstall"];

pub fn evaluate(meta: &PackageMetadata) -> Vec<Signal> {
    let present: Vec<&str> = LIFECYCLE_KEYS
        .iter()
        .filter(|k| meta.scripts.contains_key(**k))
        .copied()
        .collect();
    if present.is_empty() {
        return Vec::new();
    }

    // De-duplication rule: when *every* present lifecycle script was absent
    // from the previous release, the release_anomaly signal already scores
    // those additions (+40 for the newly-added-script fingerprint).  Awarding
    // the lifecycle signal on top (+30) would double-count the same fact.
    //
    // Suppression condition: there is a previous version AND all currently
    // present lifecycle keys were absent from it (i.e. every script is newly
    // added this release).  A package that had a pre-existing install script
    // AND added a new one in this release falls outside this condition;
    // at least one script existed before, so lifecycle scores the unchanged
    // presence while release_anomaly scores the addition.
    if let Some(prev) = &meta.previous_version {
        let all_are_new = present.iter().all(|k| !prev.scripts.contains_key(*k));
        if all_are_new {
            // Every present lifecycle script is a newly-added one; the
            // release_anomaly signal covers this with +40.  Skip lifecycle
            // to avoid double-counting the same install-script presence.
            return Vec::new();
        }
    }

    // 30 points if any pre-existing lifecycle scripts are present.
    // We do not weight by count; one bad script is enough.
    let detail = format!(
        "lifecycle scripts present: {} (these run automatically on npm install)",
        present.join(", ")
    );
    vec![Signal {
        kind: SignalKind::LifecycleScripts,
        points: 30,
        detail,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::registry::PreviousVersion;
    use std::collections::HashMap;

    fn meta_with_scripts(scripts: &[(&str, &str)]) -> PackageMetadata {
        PackageMetadata {
            name: "x".into(),
            resolved_version: "1.0.0".into(),
            published_at: None,
            maintainers: vec![],
            scripts: scripts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            dependencies: HashMap::new(),
            repository_url: None,
            deprecated: None,
            all_versions: vec!["1.0.0".into()],
            time_map: HashMap::new(),
            previous_version: None,
        }
    }

    fn with_prev(mut meta: PackageMetadata, prev_scripts: &[(&str, &str)]) -> PackageMetadata {
        meta.previous_version = Some(PreviousVersion {
            version: "0.9.0".into(),
            scripts: prev_scripts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            dependencies: HashMap::new(),
        });
        meta
    }

    #[test]
    fn no_scripts_means_no_signal() {
        let m = meta_with_scripts(&[]);
        assert!(evaluate(&m).is_empty());
    }

    #[test]
    fn build_script_alone_is_ignored() {
        let m = meta_with_scripts(&[("build", "tsc")]);
        assert!(evaluate(&m).is_empty());
    }

    #[test]
    fn postinstall_triggers_signal_when_no_previous_version() {
        // No previous version present; no suppression applies.
        let m = meta_with_scripts(&[("postinstall", "node ./build.js")]);
        let sigs = evaluate(&m);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::LifecycleScripts);
        assert_eq!(sigs[0].points, 30);
    }

    #[test]
    fn preexisting_lifecycle_script_still_scores() {
        // Script was already present in the previous release.
        // release_anomaly will NOT fire (no addition), so lifecycle must score.
        let m = with_prev(
            meta_with_scripts(&[("postinstall", "node-gyp rebuild")]),
            &[("postinstall", "node-gyp rebuild")],
        );
        let sigs = evaluate(&m);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].points, 30);
    }

    #[test]
    fn newly_added_script_suppressed_to_avoid_double_count() {
        // The script is brand-new this release (absent from previous).
        // release_anomaly covers it with +40; lifecycle must be silent.
        let m = with_prev(
            meta_with_scripts(&[("postinstall", "node ./setup.js")]),
            &[], // no lifecycle scripts in previous version
        );
        assert!(
            evaluate(&m).is_empty(),
            "lifecycle must not double-count a newly-added script already scored by release_anomaly"
        );
    }

    #[test]
    fn mixed_old_and_new_scripts_still_scores() {
        // One script pre-existed, one was added in this release.
        // release_anomaly fires for the addition; lifecycle fires for the
        // pre-existing script; they score different facts, no double-count.
        let m = with_prev(
            meta_with_scripts(&[("preinstall", "old-cmd"), ("postinstall", "new-cmd")]),
            &[("preinstall", "old-cmd")],
        );
        let sigs = evaluate(&m);
        assert_eq!(
            sigs.len(),
            1,
            "lifecycle should fire for the pre-existing preinstall"
        );
        assert_eq!(sigs[0].points, 30);
    }
}
