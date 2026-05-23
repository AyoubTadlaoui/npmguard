//! Parse a shell command string and extract npm/yarn/pnpm package-install
//! invocations from it.
//!
//! This module is intentionally kept pure (no I/O, no network). Every public
//! function is unit-testable without a runtime.
//!
//! # Scope limitations (v1)
//!
//! * Bare `npm install` (no package arguments) is treated as a lockfile
//!   restore. It is NOT gated. This is a conscious v1 choice.
//! * A sufficiently obfuscated or indirected command (shell variable expansion,
//!   heredoc, eval, etc.) can evade the parser. Full enforcement requires the
//!   v0.2 npm-wrapper + sandbox layer.
//! * Only the three major package managers are recognised: npm, yarn, pnpm.
//!   Bun's `bun add` and others are not gated in v1.

/// A package spec extracted from a detected install invocation.
///
/// Retains the original string as typed by the caller (e.g. `lodash@4.17.21`,
/// `@scope/pkg`, `foo`). Version pins are preserved so the risk engine can
/// evaluate the exact version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedPackage {
    pub spec: String,
}

/// Analyse a shell command string and return every package spec that should be
/// risk-checked.
///
/// Returns an empty `Vec` when:
/// * the command contains no recognisable package-install subcommand, OR
/// * the install subcommand carries no explicit package arguments (bare
///   `npm install` = lockfile restore), OR
/// * parsing fails for any reason (fail-open: non-install commands must never
///   be blocked).
pub fn extract_packages(command: &str) -> Vec<ExtractedPackage> {
    // Split on shell separators: `&&`, `;`, `|` (pipe). We scan each resulting
    // fragment independently so `cd x && npm install evil` is caught.
    let fragments = split_shell_fragments(command);
    let mut out = Vec::new();
    for fragment in fragments {
        out.extend(packages_from_fragment(fragment.trim()));
    }
    out
}

/// Split a command string on `&&`, `;`, and `|` (but NOT `||`).
///
/// We split on `|` carefully: only when it is not followed by another `|`.
fn split_shell_fragments(cmd: &str) -> Vec<&str> {
    let bytes = cmd.as_bytes();
    let mut parts: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        // `&&`
        if i + 1 < bytes.len() && bytes[i] == b'&' && bytes[i + 1] == b'&' {
            parts.push(&cmd[start..i]);
            i += 2;
            start = i;
            continue;
        }
        // `;`
        if bytes[i] == b';' {
            parts.push(&cmd[start..i]);
            i += 1;
            start = i;
            continue;
        }
        // `|` but NOT `||`
        if bytes[i] == b'|' {
            let next_is_pipe = i + 1 < bytes.len() && bytes[i + 1] == b'|';
            if !next_is_pipe {
                parts.push(&cmd[start..i]);
                i += 1;
                start = i;
                continue;
            }
            // `||`: skip both characters so the next iteration sees clean input
            i += 2;
            continue;
        }
        i += 1;
    }
    parts.push(&cmd[start..]);
    parts
}

/// Attempt to extract package specs from a single shell fragment (no
/// separators). Returns empty when the fragment is not a recognised
/// package-install command.
fn packages_from_fragment(fragment: &str) -> Vec<ExtractedPackage> {
    let tokens: Vec<&str> = fragment.split_whitespace().collect();
    if tokens.is_empty() {
        return vec![];
    }

    // The binary may be prefixed with a path: `/usr/bin/npm`, `./node_modules/.bin/npm`.
    let bin = tokens[0];

    // Normalise binary name (basename).
    let bin_base = bin.rsplit('/').next().unwrap_or(bin);

    match bin_base {
        "npm" | "npm.cmd" => parse_npm(&tokens),
        "yarn" => parse_yarn(&tokens),
        "pnpm" => parse_pnpm(&tokens),
        _ => vec![],
    }
}

/// Parse an `npm` invocation.
///
/// Recognised subcommands that install packages from the registry:
/// `install`, `i`, `add` (npm>=9 alias).
///
/// NOT recognised (intentionally not gated in v1):
/// `npm run`, `npm ci`, `npm update`, etc.
fn parse_npm(tokens: &[&str]) -> Vec<ExtractedPackage> {
    // tokens[0] = "npm"
    // tokens[1] = subcommand (maybe)
    let subcmd = tokens.get(1).copied().unwrap_or("");
    if !matches!(subcmd, "install" | "i" | "add") {
        return vec![];
    }
    collect_pkg_args(&tokens[2..])
}

/// Parse a `yarn` invocation.
///
/// Recognised: `yarn add`.
/// NOT recognised: `yarn`, `yarn install` (lockfile).
fn parse_yarn(tokens: &[&str]) -> Vec<ExtractedPackage> {
    let subcmd = tokens.get(1).copied().unwrap_or("");
    if subcmd != "add" {
        return vec![];
    }
    collect_pkg_args(&tokens[2..])
}

/// Parse a `pnpm` invocation.
///
/// Recognised: `pnpm add`.
/// Also matches `pnpm install <pkgs>` when explicit packages follow.
fn parse_pnpm(tokens: &[&str]) -> Vec<ExtractedPackage> {
    let subcmd = tokens.get(1).copied().unwrap_or("");
    if !matches!(subcmd, "add" | "install" | "i") {
        return vec![];
    }
    collect_pkg_args(&tokens[2..])
}

/// Collect explicit package specs from the tail of a tokenised command,
/// skipping flags (`-D`, `--save-dev`, `-g`, `--global`, etc.) and any
/// non-package-looking tokens.
///
/// Returns empty when no package arguments are found (e.g. bare `npm install`).
fn collect_pkg_args(args: &[&str]) -> Vec<ExtractedPackage> {
    let mut packages = Vec::new();
    for &arg in args {
        if arg.starts_with('-') {
            // Skip flags.
            continue;
        }
        // Skip redirection tokens that sometimes appear in chained commands.
        if matches!(arg, ">" | ">>" | "<") {
            continue;
        }
        // A valid npm package name:
        // - unscoped: lowercase letters, digits, hyphens, underscores, dots
        // - scoped: starts with `@` followed by scope/name
        // - may include `@version` suffix
        //
        // We apply a lightweight filter: must start with `@` (scoped) or an
        // alphanumeric character. This rejects paths (`./foo`), URLs, etc.
        if looks_like_package_spec(arg) {
            packages.push(ExtractedPackage {
                spec: arg.to_string(),
            });
        }
    }
    packages
}

/// Heuristic: does this token look like an npm package spec?
fn looks_like_package_spec(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.as_bytes()[0];
    // Scoped: `@scope/name` or `@scope/name@version`
    if first == b'@' {
        return s.contains('/');
    }
    // Unscoped: must start with a letter or digit.
    first.is_ascii_alphanumeric() || first == b'_'
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn specs(pkgs: &[ExtractedPackage]) -> Vec<&str> {
        pkgs.iter().map(|p| p.spec.as_str()).collect()
    }

    // --- install subcommand forms ---

    #[test]
    fn npm_install_single() {
        let pkgs = extract_packages("npm install lodash");
        assert_eq!(specs(&pkgs), vec!["lodash"]);
    }

    #[test]
    fn npm_i_shorthand() {
        let pkgs = extract_packages("npm i lodash");
        assert_eq!(specs(&pkgs), vec!["lodash"]);
    }

    #[test]
    fn npm_install_dev_flag() {
        let pkgs = extract_packages("npm i -D typescript");
        assert_eq!(specs(&pkgs), vec!["typescript"]);
    }

    #[test]
    fn npm_install_save_dev_flag() {
        let pkgs = extract_packages("npm install --save-dev typescript");
        assert_eq!(specs(&pkgs), vec!["typescript"]);
    }

    #[test]
    fn npm_install_global_flag() {
        let pkgs = extract_packages("npm install -g nodemon");
        assert_eq!(specs(&pkgs), vec!["nodemon"]);
    }

    #[test]
    fn npm_install_multiple() {
        let pkgs = extract_packages("npm install lodash express react");
        assert_eq!(specs(&pkgs), vec!["lodash", "express", "react"]);
    }

    #[test]
    fn npm_install_scoped_with_version() {
        let pkgs = extract_packages("npm install @scope/pkg@1.2.3 foo");
        assert_eq!(specs(&pkgs), vec!["@scope/pkg@1.2.3", "foo"]);
    }

    #[test]
    fn yarn_add() {
        let pkgs = extract_packages("yarn add bar");
        assert_eq!(specs(&pkgs), vec!["bar"]);
    }

    #[test]
    fn pnpm_add() {
        let pkgs = extract_packages("pnpm add baz");
        assert_eq!(specs(&pkgs), vec!["baz"]);
    }

    // --- chaining ---

    #[test]
    fn chained_and_npm_install() {
        let pkgs = extract_packages("cd x && npm install evil");
        assert_eq!(specs(&pkgs), vec!["evil"]);
    }

    #[test]
    fn chained_semicolon() {
        let pkgs = extract_packages("echo hi; npm install malware");
        assert_eq!(specs(&pkgs), vec!["malware"]);
    }

    #[test]
    fn chained_pipe() {
        let pkgs = extract_packages("cat list | npm install badpkg");
        assert_eq!(specs(&pkgs), vec!["badpkg"]);
    }

    // --- MUST return empty ---

    #[test]
    fn ls_returns_empty() {
        assert!(extract_packages("ls -la").is_empty());
    }

    #[test]
    fn bare_npm_install_returns_empty() {
        assert!(extract_packages("npm install").is_empty());
    }

    #[test]
    fn npm_run_build_returns_empty() {
        assert!(extract_packages("npm run build").is_empty());
    }

    #[test]
    fn git_commit_returns_empty() {
        assert!(extract_packages("git commit -m 'fix'").is_empty());
    }

    #[test]
    fn npm_ci_returns_empty() {
        // `npm ci` is a lockfile install, never gated in v1.
        assert!(extract_packages("npm ci").is_empty());
    }

    #[test]
    fn yarn_install_no_args_returns_empty() {
        // `yarn install` (no args) = lockfile restore, not gated.
        assert!(extract_packages("yarn install").is_empty());
    }

    // --- edge cases ---

    #[test]
    fn scoped_no_version() {
        let pkgs = extract_packages("npm install @babel/core");
        assert_eq!(specs(&pkgs), vec!["@babel/core"]);
    }

    #[test]
    fn npm_add_alias() {
        let pkgs = extract_packages("npm add chalk");
        assert_eq!(specs(&pkgs), vec!["chalk"]);
    }

    #[test]
    fn pnpm_install_with_package() {
        let pkgs = extract_packages("pnpm install express");
        assert_eq!(specs(&pkgs), vec!["express"]);
    }

    #[test]
    fn flags_only_returns_empty() {
        // `npm install -D` with no package: treat as bare install.
        assert!(extract_packages("npm install -D").is_empty());
    }
}
