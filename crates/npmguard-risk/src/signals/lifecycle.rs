//! Lifecycle script signals.
//!
//! npm runs `preinstall`, `install`, and `postinstall` automatically. These are
//! the primary attack vector in Shai-Hulud-style incidents — code in any of
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
    // 30 points if any are present. We do not weight by count — one bad
    // script is enough.
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
    fn postinstall_triggers_signal() {
        let m = meta_with_scripts(&[("postinstall", "node ./build.js")]);
        let sigs = evaluate(&m);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::LifecycleScripts);
        assert_eq!(sigs[0].points, 30);
    }
}
