//! Scoring thresholds and bucket mapping.
//!
//! Weights live with the individual signals in `signals/`. This module only
//! turns a final composite score into a `RiskLevel`.

use serde::{Deserialize, Serialize};

use crate::types::RiskLevel;

/// Tunable thresholds. Defaults reflect the design doc starting values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    pub warn: u32,
    pub block: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            warn: 30,
            block: 70,
        }
    }
}

pub fn compute_level(score: u32, t: &Thresholds) -> RiskLevel {
    if score >= t.block {
        RiskLevel::Block
    } else if score >= t.warn {
        RiskLevel::Warn
    } else {
        RiskLevel::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_at_boundaries() {
        let t = Thresholds::default();
        assert_eq!(compute_level(0, &t), RiskLevel::Ok);
        assert_eq!(compute_level(29, &t), RiskLevel::Ok);
        assert_eq!(compute_level(30, &t), RiskLevel::Warn);
        assert_eq!(compute_level(69, &t), RiskLevel::Warn);
        assert_eq!(compute_level(70, &t), RiskLevel::Block);
        assert_eq!(compute_level(200, &t), RiskLevel::Block);
    }
}
