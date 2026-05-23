//! Maintainer-related signals.
//!
//! - Sole maintainer: bus-factor 1, single point of compromise.
//! - Maintainer churn: a previous version had a different maintainer set
//!   within the last 14 days, which is the Shai-Hulud takeover pattern.

use chrono::{Duration, Utc};

use crate::signals::registry::PackageMetadata;
use crate::types::{Signal, SignalKind};

pub fn evaluate(meta: &PackageMetadata) -> Vec<Signal> {
    let mut out = Vec::new();

    if meta.maintainers.len() == 1 {
        out.push(Signal {
            kind: SignalKind::SoleMaintainer,
            points: 10,
            detail: format!("single maintainer: {}", meta.maintainers[0].name),
        });
    }

    // Detect a recent prior version (within 14 days). We do NOT have per-version
    // maintainer history from the abbreviated packument, so this is a coarse
    // proxy: "version published recently after a long-stable package," combined
    // with `age` signal it amplifies the warn.
    if let Some(current_pub) = meta.published_at {
        let prior_pub: Option<chrono::DateTime<Utc>> = meta
            .time_map
            .iter()
            .filter_map(|(v, t)| (v != &meta.resolved_version).then_some(*t))
            .filter(|t| *t < current_pub)
            .max();
        if let Some(prior) = prior_pub {
            let gap = current_pub.signed_duration_since(prior);
            // If the gap from the previous publish is > 180 days AND this version
            // is younger than 14 days, flag potential takeover/dormant-package
            // resurrection.
            let recent = Utc::now().signed_duration_since(current_pub) < Duration::days(14);
            if recent && gap > Duration::days(180) {
                out.push(Signal {
                    kind: SignalKind::MaintainerChurn,
                    points: 20,
                    detail: format!(
                        "dormant package resurrected: {} day gap before this publish",
                        gap.num_days()
                    ),
                });
            }
        }
    }

    out
}
