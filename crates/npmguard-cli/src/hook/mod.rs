//! `npmguard hook` — Claude Code PreToolUse gate.
//!
//! Subcommands:
//! * `handle` — read a PreToolUse JSON event from stdin, write a decision
//!   JSON to stdout. Run by Claude Code's harness; never by the model directly.
//! * `install` — merge npmguard into the Claude Code settings file.
//! * `uninstall` — remove only npmguard's hook entry, preserve everything else.

pub mod decision;
pub mod parser;
pub mod settings;

use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use serde::Deserialize;

use decision::{aggregate_decision, HookResponse, PackageOutcome};
use npmguard_cache::VerdictCache;
use npmguard_risk::{PackageRef, RiskEngine};

// ---------------------------------------------------------------------------
// CLI argument types (used by main.rs)
// ---------------------------------------------------------------------------

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Scope {
    #[default]
    User,
    Project,
}

// ---------------------------------------------------------------------------
// PreToolUse stdin JSON shape
// ---------------------------------------------------------------------------

/// The subset of the PreToolUse JSON we actually need. Unknown fields are
/// silently ignored (`deny_unknown_fields` is deliberately absent).
#[derive(Debug, Deserialize)]
struct PreToolUseEvent {
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct BashToolInput {
    command: String,
}

// ---------------------------------------------------------------------------
// handle
// ---------------------------------------------------------------------------

/// Read one PreToolUse event from stdin, decide, write to stdout.
///
/// Exit 0 in all cases — we communicate exclusively via the JSON response.
/// The only fatal path is if we cannot write to stdout (which would mean the
/// harness is broken regardless).
pub async fn handle(no_cache: bool) -> Result<()> {
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .context("could not read PreToolUse event from stdin")?;

    let response = compute_response(&raw, no_cache).await;
    let out = serde_json::to_string(&response).context("could not serialise hook response")?;

    let stdout = io::stdout();
    let mut lock = stdout.lock();
    writeln!(lock, "{}", out).context("could not write hook response to stdout")?;
    Ok(())
}

/// Pure decision computation from a raw JSON string. Extracted so tests can
/// drive it without touching stdin/stdout.
///
/// Always returns a valid `HookResponse` — errors are surfaced as `ask`
/// decisions, never as Rust errors propagated to the caller.
pub async fn compute_response(raw: &str, no_cache: bool) -> HookResponse {
    // 1. Parse the event.
    let event: PreToolUseEvent = match serde_json::from_str(raw) {
        Ok(e) => e,
        Err(_) => {
            // Unknown/malformed event — fail open (allow). We must never block
            // unrelated Claude Code operations due to a parse failure.
            return HookResponse::allow();
        }
    };

    // 2. Only gate Bash calls.
    if event.tool_name != "Bash" {
        return HookResponse::allow();
    }

    // 3. Extract the command string.
    let bash_input: BashToolInput = match serde_json::from_value(event.tool_input) {
        Ok(b) => b,
        Err(_) => return HookResponse::allow(), // no command field — allow
    };

    // 4. Parse the command for package-install invocations.
    let packages = parser::extract_packages(&bash_input.command);

    // 5. No install detected → allow (pass-through).
    if packages.is_empty() {
        return HookResponse::allow();
    }

    // 6. Risk-check each detected package.
    let engine = match RiskEngine::new() {
        Ok(e) => e,
        Err(err) => {
            // Engine init failed (shouldn't happen, but fail to human judgment).
            let reasons: Vec<String> = packages
                .iter()
                .map(|p| {
                    format!(
                        "npmguard could not verify `{}` (engine init failed: {}) — proceed with caution",
                        p.spec, err
                    )
                })
                .collect();
            return HookResponse::ask(reasons.join("\n"));
        }
    };

    let cache = if no_cache {
        None
    } else {
        VerdictCache::default_path()
            .ok()
            .and_then(|p| VerdictCache::open(&p).ok())
    };

    let mut outcomes: Vec<PackageOutcome> = Vec::new();
    for pkg_spec in &packages {
        let outcome = check_package(&engine, cache.as_ref(), &pkg_spec.spec).await;
        outcomes.push(outcome);
    }

    // 7. Aggregate into a single decision.
    aggregate_decision(&outcomes)
}

async fn check_package(
    engine: &RiskEngine,
    cache: Option<&VerdictCache>,
    spec: &str,
) -> PackageOutcome {
    let pkg = match PackageRef::parse(spec) {
        Ok(p) => p,
        Err(e) => {
            return PackageOutcome::Error {
                spec: spec.to_string(),
                message: format!("invalid package spec: {}", e),
            };
        }
    };

    match resolve_verdict(engine, cache, &pkg).await {
        Ok(verdict) => PackageOutcome::Checked(verdict),
        Err(e) => PackageOutcome::Error {
            spec: spec.to_string(),
            message: e.to_string(),
        },
    }
}

async fn resolve_verdict(
    engine: &RiskEngine,
    cache: Option<&VerdictCache>,
    pkg: &PackageRef,
) -> Result<npmguard_risk::RiskVerdict> {
    let meta = engine.fetch_metadata(pkg).await?;
    let signal_hash = engine.signal_set_hash();
    if let Some(c) = cache {
        match c.get(pkg, &meta.resolved_version, &signal_hash) {
            Ok(Some(cached)) => return Ok(cached),
            Ok(None) => {}
            Err(e) => tracing::warn!("cache get: {}", e),
        }
    }
    let verdict = engine.evaluate_from_metadata(pkg, meta).await?;
    if let Some(c) = cache {
        if let Err(e) = c.put(&verdict) {
            tracing::warn!("cache put: {}", e);
        }
    }
    Ok(verdict)
}

// ---------------------------------------------------------------------------
// install / uninstall
// ---------------------------------------------------------------------------

pub fn install(scope: Scope) -> Result<()> {
    let path = match scope {
        Scope::User => settings::user_settings_path()?,
        Scope::Project => settings::project_settings_path()?,
    };
    let msg = settings::install(&path)?;
    println!("{}", msg);
    Ok(())
}

pub fn uninstall(scope: Scope) -> Result<()> {
    let path = match scope {
        Scope::User => settings::user_settings_path()?,
        Scope::Project => settings::project_settings_path()?,
    };
    let msg = settings::uninstall(&path)?;
    println!("{}", msg);
    Ok(())
}

// ---------------------------------------------------------------------------
// Integration-level tests (deterministic, no network)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use decision::PermissionDecision;
    use npmguard_risk::{PackageRef, RiskLevel, RiskVerdict, Signal, SignalKind};

    // Helper: build a synthetic HookResponse by injecting pre-built outcomes
    // directly into aggregate_decision (avoids any network call).
    fn make_verdict(name: &str, score: u32, level: RiskLevel) -> RiskVerdict {
        RiskVerdict {
            package: PackageRef::new(name, None),
            resolved_version: "1.0.0".into(),
            score,
            level,
            signals: vec![Signal {
                kind: SignalKind::KnownCve,
                points: score,
                detail: "synthetic".into(),
            }],
            fetched_at: chrono::Utc::now(),
            published_at: None,
            signal_set_hash: "test".into(),
        }
    }

    // --- handle()-equivalent tests driven through compute_response ---

    #[tokio::test]
    async fn non_bash_tool_allows() {
        let event = r#"{"tool_name":"Edit","tool_input":{"file_path":"foo.ts"}}"#;
        // compute_response makes no network calls for non-Bash tools.
        let resp = compute_response(event, true).await;
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Allow
        );
    }

    #[tokio::test]
    async fn ls_command_allows() {
        let event = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
        let resp = compute_response(event, true).await;
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Allow
        );
    }

    #[tokio::test]
    async fn bare_npm_install_allows() {
        let event = r#"{"tool_name":"Bash","tool_input":{"command":"npm install"}}"#;
        let resp = compute_response(event, true).await;
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Allow
        );
    }

    #[tokio::test]
    async fn malformed_stdin_allows() {
        // A completely invalid JSON → fail open.
        let resp = compute_response("not json at all", true).await;
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Allow
        );
    }

    // --- Block verdict → deny with correct JSON shape ---

    #[test]
    fn block_verdict_produces_deny_with_correct_shape() {
        let outcomes = vec![PackageOutcome::Checked(make_verdict(
            "evil-pkg",
            90,
            RiskLevel::Block,
        ))];
        let resp = aggregate_decision(&outcomes);

        // Verify JSON serialisation matches the exact Claude Code schema.
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("hookSpecificOutput").is_some());
        let inner = &json["hookSpecificOutput"];
        assert_eq!(inner["hookEventName"], "PreToolUse");
        assert_eq!(inner["permissionDecision"], "deny");
        let reason = inner["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("evil-pkg"), "reason: {}", reason);
        assert!(reason.contains("90/200"), "reason: {}", reason);
    }

    // --- Warn verdict → ask ---

    #[test]
    fn warn_verdict_produces_ask() {
        let outcomes = vec![PackageOutcome::Checked(make_verdict(
            "risky-pkg",
            45,
            RiskLevel::Warn,
        ))];
        let resp = aggregate_decision(&outcomes);
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Ask
        );
        assert!(resp
            .hook_specific_output
            .permission_decision_reason
            .as_deref()
            .unwrap()
            .contains("risky-pkg"));
    }

    // --- Error → ask (never hard-deny on infra failure) ---

    #[test]
    fn check_error_produces_ask_not_deny() {
        let outcomes = vec![PackageOutcome::Error {
            spec: "some-pkg".into(),
            message: "connection refused".into(),
        }];
        let resp = aggregate_decision(&outcomes);
        assert_eq!(
            resp.hook_specific_output.permission_decision,
            PermissionDecision::Ask
        );
    }

    // --- Ok verdict → allow ---

    #[test]
    fn ok_verdict_produces_allow() {
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
}
