//! Parse a shell command string and extract npm/yarn/pnpm/bun package-install
//! and on-the-fly package-runner invocations from it.
//!
//! This module is intentionally kept pure (no I/O, no network). Every public
//! function is unit-testable without a runtime.
//!
//! # Coverage
//!
//! Installs: `npm install`/`i`/`add`, `yarn add`, `pnpm add`/`install`/`i`,
//! `bun add`/`install`/`i`.
//!
//! Runners (fetch-and-execute a package that is not in any manifest, the exact
//! vector an agent uses to pull code without a lockfile entry): `npx`, `bunx`,
//! `npm exec`/`x`, `pnpm dlx`, `yarn dlx`, `bun x`. For a runner only the
//! *executed* package is checked, never the arguments passed to it.
//!
//! # Scope limitations
//!
//! * Bare `npm install` (no package arguments) is treated as a lockfile
//!   restore. It is NOT gated. This is a conscious choice.
//! * A sufficiently obfuscated or indirected command (shell variable expansion,
//!   heredoc, eval, etc.) can evade the parser. Full enforcement requires the
//!   v0.2 npm-wrapper + sandbox layer.

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
        "bun" => parse_bun(&tokens),
        // Bare runners: the binary itself is the runner, packages follow directly.
        "npx" | "npx.cmd" | "bunx" | "bunx.cmd" => parse_runner(&tokens[1..]),
        _ => vec![],
    }
}

/// Parse an `npm` invocation.
///
/// Install subcommands (registry install): `install`, `i`, `add` (npm>=9 alias).
/// Runner subcommands (fetch-and-execute): `exec`, `x`.
///
/// NOT recognised (intentionally not gated):
/// `npm run`, `npm ci`, `npm update`, etc.
fn parse_npm(tokens: &[&str]) -> Vec<ExtractedPackage> {
    // tokens[0] = "npm"
    // tokens[1] = subcommand (maybe)
    let subcmd = tokens.get(1).copied().unwrap_or("");
    match subcmd {
        "install" | "i" | "add" => collect_pkg_args(&tokens[2..]),
        "exec" | "x" => parse_runner(&tokens[2..]),
        _ => vec![],
    }
}

/// Parse a `yarn` invocation.
///
/// Recognised: `yarn add` (install), `yarn dlx` (runner).
/// NOT recognised: `yarn`, `yarn install` (lockfile).
fn parse_yarn(tokens: &[&str]) -> Vec<ExtractedPackage> {
    let subcmd = tokens.get(1).copied().unwrap_or("");
    match subcmd {
        "add" => collect_pkg_args(&tokens[2..]),
        "dlx" => parse_runner(&tokens[2..]),
        _ => vec![],
    }
}

/// Parse a `pnpm` invocation.
///
/// Recognised: `pnpm add`, `pnpm install <pkgs>`/`i <pkgs>` (install when
/// explicit packages follow), `pnpm dlx` (runner).
fn parse_pnpm(tokens: &[&str]) -> Vec<ExtractedPackage> {
    let subcmd = tokens.get(1).copied().unwrap_or("");
    match subcmd {
        "add" | "install" | "i" => collect_pkg_args(&tokens[2..]),
        "dlx" => parse_runner(&tokens[2..]),
        _ => vec![],
    }
}

/// Parse a `bun` invocation.
///
/// Recognised: `bun add`/`install`/`i` (install when explicit packages follow),
/// `bun x` (the `bunx` runner).
/// NOT recognised: bare `bun install` (lockfile), `bun run`, `bun remove`.
fn parse_bun(tokens: &[&str]) -> Vec<ExtractedPackage> {
    let subcmd = tokens.get(1).copied().unwrap_or("");
    match subcmd {
        "add" | "install" | "i" => collect_pkg_args(&tokens[2..]),
        "x" => parse_runner(&tokens[2..]),
        _ => vec![],
    }
}

/// Parse the arguments of a package *runner* (`npx`, `bunx`, `npm exec`,
/// `pnpm dlx`, `yarn dlx`, `bun x`).
///
/// `args` is everything after the runner keyword. A runner downloads and
/// executes one package on the fly, so only the *executed* package is a risk
/// target; the tokens after it are arguments to that program and must not be
/// treated as packages (`npx create-react-app my-app` checks `create-react-app`,
/// never `my-app`).
///
/// `-p`/`--package`/`--package=` name explicit packages to fetch; when present,
/// the trailing bare token is the command to run *from* those packages, not a
/// package itself.
fn parse_runner(args: &[&str]) -> Vec<ExtractedPackage> {
    let mut packages = Vec::new();
    let mut saw_explicit_package = false;
    let mut i = 0usize;

    while i < args.len() {
        let arg = args[i];

        // `-p pkg` / `--package pkg`: explicit package, value is the next token.
        if arg == "-p" || arg == "--package" {
            if let Some(&val) = args.get(i + 1) {
                if looks_like_package_spec(val) {
                    packages.push(ExtractedPackage {
                        spec: val.to_string(),
                    });
                    saw_explicit_package = true;
                }
            }
            i += 2;
            continue;
        }
        // `--package=pkg`: explicit package, value is inline.
        if let Some(val) = arg.strip_prefix("--package=") {
            if looks_like_package_spec(val) {
                packages.push(ExtractedPackage {
                    spec: val.to_string(),
                });
                saw_explicit_package = true;
            }
            i += 1;
            continue;
        }
        // Any other flag (`-y`, `--yes`, `--`, ...): skip the flag token only.
        if arg.starts_with('-') {
            i += 1;
            continue;
        }

        // First bare token. If `--package` already named the target(s), this is
        // the command to execute, not a package. Otherwise it IS the package.
        if !saw_explicit_package && looks_like_package_spec(arg) {
            packages.push(ExtractedPackage {
                spec: arg.to_string(),
            });
        }
        // Everything after the executed token is its own arguments: stop.
        break;
    }

    packages
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

    // --- bun installs ---

    #[test]
    fn bun_add() {
        let pkgs = extract_packages("bun add left-pad");
        assert_eq!(specs(&pkgs), vec!["left-pad"]);
    }

    #[test]
    fn bun_install_with_package() {
        let pkgs = extract_packages("bun install react");
        assert_eq!(specs(&pkgs), vec!["react"]);
    }

    #[test]
    fn bun_i_shorthand() {
        let pkgs = extract_packages("bun i -d typescript");
        assert_eq!(specs(&pkgs), vec!["typescript"]);
    }

    #[test]
    fn bare_bun_install_returns_empty() {
        // Lockfile restore, never gated.
        assert!(extract_packages("bun install").is_empty());
    }

    #[test]
    fn bun_run_returns_empty() {
        assert!(extract_packages("bun run build").is_empty());
    }

    // --- runners: npx / bunx / bun x / npm exec / dlx ---

    #[test]
    fn npx_single() {
        let pkgs = extract_packages("npx cowsay");
        assert_eq!(specs(&pkgs), vec!["cowsay"]);
    }

    #[test]
    fn npx_only_executed_pkg_not_its_args() {
        // `my-app` is an argument to create-react-app, not a package.
        let pkgs = extract_packages("npx create-react-app my-app");
        assert_eq!(specs(&pkgs), vec!["create-react-app"]);
    }

    #[test]
    fn npx_skips_leading_flags() {
        let pkgs = extract_packages("npx -y cowsay moo");
        assert_eq!(specs(&pkgs), vec!["cowsay"]);
    }

    #[test]
    fn npx_explicit_package_flag() {
        // `-p foo cmd`: foo is the package, cmd runs from it.
        let pkgs = extract_packages("npx -p typescript tsc --init");
        assert_eq!(specs(&pkgs), vec!["typescript"]);
    }

    #[test]
    fn npx_explicit_package_eq_form() {
        let pkgs = extract_packages("npx --package=@scope/tool run");
        assert_eq!(specs(&pkgs), vec!["@scope/tool"]);
    }

    #[test]
    fn bunx_single() {
        let pkgs = extract_packages("bunx prettier --write .");
        assert_eq!(specs(&pkgs), vec!["prettier"]);
    }

    #[test]
    fn bun_x_runner() {
        let pkgs = extract_packages("bun x eslint .");
        assert_eq!(specs(&pkgs), vec!["eslint"]);
    }

    #[test]
    fn npm_exec_runner() {
        let pkgs = extract_packages("npm exec create-react-app my-app");
        assert_eq!(specs(&pkgs), vec!["create-react-app"]);
    }

    #[test]
    fn npm_x_runner() {
        let pkgs = extract_packages("npm x cowsay");
        assert_eq!(specs(&pkgs), vec!["cowsay"]);
    }

    #[test]
    fn pnpm_dlx_runner() {
        let pkgs = extract_packages("pnpm dlx create-vite my-app");
        assert_eq!(specs(&pkgs), vec!["create-vite"]);
    }

    #[test]
    fn yarn_dlx_runner() {
        let pkgs = extract_packages("yarn dlx create-vite my-app");
        assert_eq!(specs(&pkgs), vec!["create-vite"]);
    }

    #[test]
    fn npx_scoped_with_version() {
        let pkgs = extract_packages("npx @angular/cli@17 new app");
        assert_eq!(specs(&pkgs), vec!["@angular/cli@17"]);
    }

    #[test]
    fn chained_npx_after_cd() {
        let pkgs = extract_packages("cd /tmp && npx evil-tool");
        assert_eq!(specs(&pkgs), vec!["evil-tool"]);
    }

    // --- runners that must NOT extract anything ---

    #[test]
    fn bare_npx_returns_empty() {
        assert!(extract_packages("npx").is_empty());
    }

    #[test]
    fn npx_local_path_not_a_package() {
        // `npx ./scripts/foo` runs a local file, not a registry package.
        assert!(extract_packages("npx ./scripts/build.js").is_empty());
    }
}
