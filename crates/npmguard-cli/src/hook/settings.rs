//! Read-merge-write helpers for Claude Code `settings.json` hook management.
//!
//! The invariants this module upholds:
//! * Installing is idempotent — calling `install` twice does not duplicate
//!   the hook entry.
//! * Uninstalling only removes npmguard's own hook entry; every other setting
//!   and hook is preserved exactly as found.
//! * Neither function clobbers the full file; both read-then-merge-then-write.
//! * File and parent directories are created when missing.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

/// The matcher string Claude Code uses to route Bash tool calls to our hook.
const MATCHER: &str = "Bash";

/// Build the hook command string from the absolute path of the current binary.
pub fn hook_command() -> Result<String> {
    let exe = std::env::current_exe().context("could not determine current executable path")?;
    let exe_str = exe
        .to_str()
        .context("executable path contains non-UTF-8 characters")?;
    Ok(format!("{} hook handle", exe_str))
}

/// Return the path to the Claude Code user-level settings file.
pub fn user_settings_path() -> Result<PathBuf> {
    let home = dirs_home()?;
    Ok(home.join(".claude").join("settings.json"))
}

/// Return the path to the Claude Code project-level settings file.
pub fn project_settings_path() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("could not determine current directory")?;
    Ok(cwd.join(".claude").join("settings.json"))
}

fn dirs_home() -> Result<PathBuf> {
    // `directories` crate is not in the workspace deps, so we use std env.
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .context("could not determine home directory (HOME / USERPROFILE not set)")?;
    Ok(PathBuf::from(home))
}

/// Install npmguard as a PreToolUse hook in `settings_path`.
///
/// Returns a human-readable description of what was done.
pub fn install(settings_path: &Path) -> Result<String> {
    let cmd = hook_command()?;
    let mut root = read_or_empty(settings_path)?;

    if is_already_installed(&root, &cmd) {
        return Ok(format!(
            "npmguard hook already present in {} — nothing changed.",
            settings_path.display()
        ));
    }

    inject_hook(&mut root, &cmd);
    write_settings(settings_path, &root)?;

    Ok(format!(
        "npmguard hook installed in {}.\n\
         Restart Claude Code (or reload the window) for the hook to take effect.",
        settings_path.display()
    ))
}

/// Remove only npmguard's hook entry from `settings_path`.
///
/// Returns a human-readable description of what was done.
pub fn uninstall(settings_path: &Path) -> Result<String> {
    let cmd = hook_command()?;

    if !settings_path.exists() {
        return Ok(format!(
            "{} does not exist — nothing to remove.",
            settings_path.display()
        ));
    }

    let mut root = read_or_empty(settings_path)?;
    let removed = remove_hook(&mut root, &cmd);

    if removed {
        write_settings(settings_path, &root)?;
        Ok(format!(
            "npmguard hook removed from {}.\n\
             Restart Claude Code for the change to take effect.",
            settings_path.display()
        ))
    } else {
        Ok(format!(
            "No npmguard hook found in {} — nothing changed.",
            settings_path.display()
        ))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_or_empty(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(json!({}));
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&text).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn write_settings(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create directory {}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(value).context("could not serialise settings")?;
    std::fs::write(path, text).with_context(|| format!("could not write {}", path.display()))
}

/// Return `true` if a hook entry with our command string already exists.
fn is_already_installed(root: &Value, cmd: &str) -> bool {
    let Some(blocks) = root
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|v| v.as_array())
    else {
        return false;
    };

    for block in blocks {
        if block.get("matcher").and_then(|m| m.as_str()) != Some(MATCHER) {
            continue;
        }
        if let Some(hooks) = block.get("hooks").and_then(|h| h.as_array()) {
            for hook in hooks {
                if hook.get("command").and_then(|c| c.as_str()) == Some(cmd) {
                    return true;
                }
            }
        }
    }
    false
}

/// Inject our hook entry into the JSON, merging into an existing Bash matcher
/// block if one already exists, otherwise appending a new block.
///
/// This function is idempotent: if a hook entry with the same command is
/// already present it is not duplicated.
fn inject_hook(root: &mut Value, cmd: &str) {
    // Guard: already present — nothing to do.
    if is_already_installed(root, cmd) {
        return;
    }

    let new_hook = json!({
        "type": "command",
        "command": cmd,
        "timeout": 60
    });

    // Ensure hooks.PreToolUse is an array.
    let hooks_obj = root
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let pre_tool_use = hooks_obj
        .as_object_mut()
        .unwrap()
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));

    if let Some(blocks) = pre_tool_use.as_array_mut() {
        // Look for an existing block with matcher == "Bash".
        for block in blocks.iter_mut() {
            if block.get("matcher").and_then(|m| m.as_str()) == Some(MATCHER) {
                // Append to its hooks array.
                if let Some(inner) = block.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                    inner.push(new_hook);
                    return;
                }
            }
        }
        // No Bash block yet — append a new one.
        blocks.push(json!({
            "matcher": MATCHER,
            "hooks": [new_hook]
        }));
    }
}

/// Remove every hook entry whose `command` matches `cmd`.
/// Returns `true` if anything was removed.
fn remove_hook(root: &mut Value, cmd: &str) -> bool {
    let Some(pre_tool_use) = root
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
        .and_then(|v| v.as_array_mut())
    else {
        return false;
    };

    let mut removed = false;
    for block in pre_tool_use.iter_mut() {
        if block.get("matcher").and_then(|m| m.as_str()) != Some(MATCHER) {
            continue;
        }
        if let Some(inner) = block.get_mut("hooks").and_then(|h| h.as_array_mut()) {
            let before = inner.len();
            inner.retain(|h| h.get("command").and_then(|c| c.as_str()) != Some(cmd));
            if inner.len() < before {
                removed = true;
            }
        }
    }
    removed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fake_cmd() -> &'static str {
        "/usr/local/bin/npmguard hook handle"
    }

    #[test]
    fn inject_into_empty_root() {
        let mut root = json!({});
        inject_hook(&mut root, fake_cmd());
        assert!(!is_already_installed(&root, "/other/binary hook handle"));
        assert!(is_already_installed(&root, fake_cmd()));
    }

    #[test]
    fn inject_is_idempotent() {
        let mut root = json!({});
        inject_hook(&mut root, fake_cmd());
        inject_hook(&mut root, fake_cmd());
        // Must not duplicate entries.
        let hooks = root["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn inject_preserves_other_hooks() {
        let mut root = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "/other/hook" }
                        ]
                    }
                ]
            }
        });
        inject_hook(&mut root, fake_cmd());
        let hooks = root["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap();
        // Other hook preserved + ours added.
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0]["command"], "/other/hook");
        assert_eq!(hooks[1]["command"], fake_cmd());
    }

    #[test]
    fn inject_preserves_non_bash_matchers() {
        let mut root = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Write",
                        "hooks": [
                            { "type": "command", "command": "/write/hook" }
                        ]
                    }
                ]
            }
        });
        inject_hook(&mut root, fake_cmd());
        let blocks = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(blocks.len(), 2);
        // Write block untouched.
        assert_eq!(blocks[0]["matcher"], "Write");
    }

    #[test]
    fn remove_hook_cleans_entry() {
        let mut root = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": fake_cmd() },
                            { "type": "command", "command": "/other/hook" }
                        ]
                    }
                ]
            }
        });
        let removed = remove_hook(&mut root, fake_cmd());
        assert!(removed);
        let hooks = root["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["command"], "/other/hook");
    }

    #[test]
    fn remove_hook_returns_false_when_not_present() {
        let mut root = json!({});
        assert!(!remove_hook(&mut root, fake_cmd()));
    }

    #[test]
    fn preserves_other_top_level_settings() {
        let mut root = json!({
            "theme": "dark",
            "model": "claude-opus-4-5",
            "hooks": {}
        });
        inject_hook(&mut root, fake_cmd());
        assert_eq!(root["theme"], "dark");
        assert_eq!(root["model"], "claude-opus-4-5");
    }
}
