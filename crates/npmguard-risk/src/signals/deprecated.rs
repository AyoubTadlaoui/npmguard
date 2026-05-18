//! Deprecation signal — npm marks packages or versions as deprecated with a message.

use crate::signals::registry::PackageMetadata;
use crate::types::{Signal, SignalKind};

pub fn evaluate(meta: &PackageMetadata) -> Vec<Signal> {
    let Some(msg) = meta.deprecated.as_deref() else {
        return Vec::new();
    };
    let truncated = if msg.len() > 120 {
        format!("{}...", &msg[..120])
    } else {
        msg.to_string()
    };
    vec![Signal {
        kind: SignalKind::Deprecated,
        points: 10,
        detail: format!("version is deprecated: {}", truncated),
    }]
}
