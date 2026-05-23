//! Deprecation signal: npm marks packages or versions as deprecated with a message.

use crate::signals::registry::PackageMetadata;
use crate::types::{Signal, SignalKind};

pub fn evaluate(meta: &PackageMetadata) -> Vec<Signal> {
    let Some(msg) = meta.deprecated.as_deref() else {
        return Vec::new();
    };
    // Truncate on a char boundary, not a byte index. `msg` is attacker-
    // controlled registry JSON, and `&msg[..120]` panics (process abort under
    // `panic = "abort"`) when byte 120 lands inside a multibyte character.
    let truncated = if msg.chars().count() > 120 {
        let head: String = msg.chars().take(120).collect();
        format!("{}...", head)
    } else {
        msg.to_string()
    };
    vec![Signal {
        kind: SignalKind::Deprecated,
        points: 10,
        detail: format!("version is deprecated: {}", truncated),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::registry::PackageMetadata;
    use std::collections::HashMap;

    fn meta_with_deprecated(msg: Option<&str>) -> PackageMetadata {
        PackageMetadata {
            name: "x".into(),
            resolved_version: "1.0.0".into(),
            published_at: None,
            maintainers: vec![],
            scripts: HashMap::new(),
            dependencies: HashMap::new(),
            repository_url: None,
            deprecated: msg.map(|s| s.to_string()),
            all_versions: vec!["1.0.0".into()],
            time_map: HashMap::new(),
            previous_version: None,
        }
    }

    #[test]
    fn absent_deprecation_yields_no_signal() {
        assert!(evaluate(&meta_with_deprecated(None)).is_empty());
    }

    #[test]
    fn long_multibyte_message_truncates_without_panicking() {
        // A multibyte char (emoji = 4 bytes) straddling byte 120 panics under
        // the old `&msg[..120]` slice. Padding 119 ASCII chars + an emoji puts
        // the char boundary right at the cut point.
        let msg = format!(
            "{}🦀 and more text after the truncation point",
            "a".repeat(119)
        );
        let sigs = evaluate(&meta_with_deprecated(Some(&msg)));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::Deprecated);
        assert!(sigs[0].detail.ends_with("..."));
    }

    #[test]
    fn short_message_is_not_truncated() {
        let sigs = evaluate(&meta_with_deprecated(Some("use foo instead")));
        assert_eq!(sigs.len(), 1);
        assert!(sigs[0].detail.contains("use foo instead"));
        assert!(!sigs[0].detail.ends_with("..."));
    }
}
