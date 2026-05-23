//! Package age signal.
//!
//! Brand-new packages are over-represented in supply chain attacks: typosquats,
//! freshly published malicious clones, and compromised maintainer accounts
//! usually publish new versions, not edit old ones.

use chrono::{Duration, Utc};

use crate::signals::registry::PackageMetadata;
use crate::types::{Signal, SignalKind};

pub fn evaluate(meta: &PackageMetadata) -> Vec<Signal> {
    let Some(published) = meta.published_at else {
        return Vec::new();
    };
    let age = Utc::now().signed_duration_since(published);
    if age < Duration::days(7) {
        vec![Signal {
            kind: SignalKind::PackageAge,
            points: 25,
            detail: format!(
                "version published {} day(s) ago, under 7d",
                age.num_days().max(0)
            ),
        }]
    } else if age < Duration::days(30) {
        vec![Signal {
            kind: SignalKind::PackageAge,
            points: 10,
            detail: format!("version published {} day(s) ago, under 30d", age.num_days()),
        }]
    } else {
        Vec::new()
    }
}
