//! Map a risk verdict (or absence of packages / error state) to a
//! Claude Code `PreToolUse` permission decision.
//!
//! This module is pure: no I/O, no network, no async. All branching is
//! exercisable through unit tests.

use std::cmp::Reverse;

use npmguard_risk::{RiskLevel, RiskVerdict, Signal};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Output types (Claude Code PreToolUse JSON schema)
// ---------------------------------------------------------------------------

/// Top-level response written to stdout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HookResponse {
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    pub hook_event_name: String,
    pub permission_decision: PermissionDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
}

/// The three values Claude Code recognises for PreToolUse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionDecision {
    Allow,
    Deny,
    Ask,
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl HookResponse {
    pub fn allow() -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".into(),
                permission_decision: PermissionDecision::Allow,
                permission_decision_reason: None,
            },
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".into(),
                permission_decision: PermissionDecision::Deny,
                permission_decision_reason: Some(reason.into()),
            },
        }
    }

    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".into(),
                permission_decision: PermissionDecision::Ask,
                permission_decision_reason: Some(reason.into()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Decision logic
// ---------------------------------------------------------------------------

/// A single package check outcome: either a completed verdict or an error.
pub enum PackageOutcome {
    Checked(RiskVerdict),
    Error { spec: String, message: String },
}

/// Aggregate a list of per-package outcomes into a single hook decision.
///
/// Rules (applied in priority order):
/// 1. Any `Block` verdict → `deny` (names the package, top signals, score).
/// 2. Any `Warn` verdict  → `ask`  (surfaces signals).
/// 3. Any network/check error → `ask` with caution message (fail to human
///    judgment; never silently allow an unverified package).
/// 4. All `Ok` → `allow`.
///
/// An empty `outcomes` list (no packages detected) maps to `allow`.
pub fn aggregate_decision(outcomes: &[PackageOutcome]) -> HookResponse {
    if outcomes.is_empty() {
        return HookResponse::allow();
    }

    let mut block_reasons: Vec<String> = Vec::new();
    let mut warn_reasons: Vec<String> = Vec::new();
    let mut error_reasons: Vec<String> = Vec::new();

    for outcome in outcomes {
        match outcome {
            PackageOutcome::Checked(verdict) => match verdict.level {
                RiskLevel::Block => {
                    block_reasons.push(format_block_reason(verdict));
                }
                RiskLevel::Warn => {
                    warn_reasons.push(format_warn_reason(verdict));
                }
                RiskLevel::Ok => {}
            },
            PackageOutcome::Error { spec, message } => {
                error_reasons.push(format!(
                    "npmguard could not verify `{}` ({}) — proceed with caution",
                    spec, message
                ));
            }
        }
    }

    if !block_reasons.is_empty() {
        return HookResponse::deny(block_reasons.join("\n"));
    }
    if !warn_reasons.is_empty() || !error_reasons.is_empty() {
        let mut all = warn_reasons;
        all.extend(error_reasons);
        return HookResponse::ask(all.join("\n"));
    }
    HookResponse::allow()
}

// ---------------------------------------------------------------------------
// Reason formatters
// ---------------------------------------------------------------------------

fn format_block_reason(v: &RiskVerdict) -> String {
    let top = top_signals(&v.signals, 3);
    format!(
        "npmguard blocked `{}` (score {}/200): {}",
        v.package.display(),
        v.score,
        top
    )
}

fn format_warn_reason(v: &RiskVerdict) -> String {
    let top = top_signals(&v.signals, 3);
    format!(
        "npmguard warns about `{}` (score {}/200): {}",
        v.package.display(),
        v.score,
        top
    )
}

/// Return a human-readable summary of the top N signals by point value.
fn top_signals(signals: &[Signal], n: usize) -> String {
    if signals.is_empty() {
        return "no signals".into();
    }
    let mut sorted = signals.to_vec();
    sorted.sort_by_key(|s| Reverse(s.points));
    sorted
        .iter()
        .take(n)
        .map(|s| format!("{:?}({}pts): {}", s.kind, s.points, s.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use npmguard_risk::{PackageRef, Signal, SignalKind};

    fn make_verdict(name: &str, score: u32, level: RiskLevel) -> RiskVerdict {
        let signals = if score > 0 {
            vec![Signal {
                kind: SignalKind::KnownCve,
                points: score,
                detail: "test signal".into(),
            }]
        } else {
            vec![]
        };
        RiskVerdict {
            package: PackageRef::new(name, None),
            resolved_version: "1.0.0".into(),
            score,
            level,
            signals,
            fetched_at: Utc::now(),
            published_at: None,
            signal_set_hash: "testhash".into(),
        }
    }

    #[test]
    fn empty_outcomes_allows() {
        let resp = aggregate_decision(&[]);
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Allow
        );
        assert!(resp
            .hook_specific_output
            .permission_decision_reason
            .is_none());
    }

    #[test]
    fn ok_verdict_allows() {
        let outcomes = vec![PackageOutcome::Checked(make_verdict(
            "lodash",
            0,
            RiskLevel::Ok,
        ))];
        let resp = aggregate_decision(&outcomes);
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Allow
        );
    }

    #[test]
    fn block_verdict_denies() {
        let outcomes = vec![PackageOutcome::Checked(make_verdict(
            "evil-pkg",
            90,
            RiskLevel::Block,
        ))];
        let resp = aggregate_decision(&outcomes);
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Deny
        );
        let reason = resp
            .hook_specific_output
            .permission_decision_reason
            .unwrap();
        assert!(reason.contains("evil-pkg"));
        assert!(reason.contains("90/200"));
    }

    #[test]
    fn warn_verdict_asks() {
        let outcomes = vec![PackageOutcome::Checked(make_verdict(
            "suspicious",
            45,
            RiskLevel::Warn,
        ))];
        let resp = aggregate_decision(&outcomes);
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Ask
        );
        let reason = resp
            .hook_specific_output
            .permission_decision_reason
            .unwrap();
        assert!(reason.contains("suspicious"));
    }

    #[test]
    fn error_asks_not_blocks() {
        let outcomes = vec![PackageOutcome::Error {
            spec: "unknown-pkg".into(),
            message: "connection timeout".into(),
        }];
        let resp = aggregate_decision(&outcomes);
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Ask
        );
        let reason = resp
            .hook_specific_output
            .permission_decision_reason
            .unwrap();
        assert!(reason.contains("unknown-pkg"));
        assert!(reason.contains("connection timeout"));
        assert!(reason.contains("proceed with caution"));
    }

    #[test]
    fn block_takes_priority_over_warn() {
        let outcomes = vec![
            PackageOutcome::Checked(make_verdict("warn-pkg", 45, RiskLevel::Warn)),
            PackageOutcome::Checked(make_verdict("block-pkg", 90, RiskLevel::Block)),
        ];
        let resp = aggregate_decision(&outcomes);
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Deny
        );
        let reason = resp
            .hook_specific_output
            .permission_decision_reason
            .unwrap();
        assert!(reason.contains("block-pkg"));
    }

    #[test]
    fn warn_takes_priority_over_error() {
        let outcomes = vec![
            PackageOutcome::Checked(make_verdict("warn-pkg", 45, RiskLevel::Warn)),
            PackageOutcome::Error {
                spec: "err-pkg".into(),
                message: "timeout".into(),
            },
        ];
        let resp = aggregate_decision(&outcomes);
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Ask
        );
    }

    #[test]
    fn hook_response_serialization_shape() {
        let resp = HookResponse::deny("test block reason");
        let json = serde_json::to_value(&resp).unwrap();
        // Verify exact key names required by Claude Code.
        assert!(json.get("hookSpecificOutput").is_some());
        let inner = json.get("hookSpecificOutput").unwrap();
        assert_eq!(inner.get("hookEventName").unwrap(), "PreToolUse");
        assert_eq!(inner.get("permissionDecision").unwrap(), "deny");
        assert_eq!(
            inner.get("permissionDecisionReason").unwrap(),
            "test block reason"
        );
    }

    #[test]
    fn allow_does_not_emit_reason_field() {
        let resp = HookResponse::allow();
        let json = serde_json::to_value(&resp).unwrap();
        let inner = json.get("hookSpecificOutput").unwrap();
        assert!(inner.get("permissionDecisionReason").is_none());
    }
}
