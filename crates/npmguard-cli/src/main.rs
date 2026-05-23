//! npmguard CLI.
//!
//! v0.1 scope: `check` and `install` both compute a risk verdict and surface it.
//! `install` will gain real `npm install` subprocess execution in v0.2 along with
//! the sandbox layer. Today, it tells you what would happen and exits.
//!
//! `hook` subcommand: deterministic Claude Code PreToolUse gate. The harness
//! runs the hook binary; the model cannot skip it.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;

use npmguard_cache::VerdictCache;
use npmguard_risk::{PackageRef, RiskEngine, RiskLevel, RiskVerdict, Thresholds};

mod hook;

/// Color enablement, decided once at startup. Bare `.bold()`/`.red()` calls
/// from `owo_colors` always emit ANSI; we gate them through the `color` module
/// below so `--no-color`, the `NO_COLOR` env var, and a non-TTY stdout all
/// turn into actual plain text.
mod color {
    use super::*;

    static DISABLED: AtomicBool = AtomicBool::new(false);

    pub fn configure(no_color_flag: bool) {
        let env_no_color = std::env::var_os("NO_COLOR").is_some();
        let not_a_tty = !std::io::stdout().is_terminal();
        if no_color_flag || env_no_color || not_a_tty {
            DISABLED.store(true, Ordering::Relaxed);
        }
        // Keep owo_colors' own auto-detect in sync for any caller that uses
        // `if_supports_color`.
        owo_colors::set_override(!DISABLED.load(Ordering::Relaxed));
    }

    pub fn enabled() -> bool {
        !DISABLED.load(Ordering::Relaxed)
    }

    pub fn bold<T: std::fmt::Display + OwoColorize>(t: T) -> String {
        if enabled() {
            t.bold().to_string()
        } else {
            t.to_string()
        }
    }

    pub fn red_bold<T: std::fmt::Display + OwoColorize>(t: T) -> String {
        if enabled() {
            t.red().bold().to_string()
        } else {
            t.to_string()
        }
    }

    pub fn yellow_bold<T: std::fmt::Display + OwoColorize>(t: T) -> String {
        if enabled() {
            t.yellow().bold().to_string()
        } else {
            t.to_string()
        }
    }

    pub fn blue_bold<T: std::fmt::Display + OwoColorize>(t: T) -> String {
        if enabled() {
            t.blue().bold().to_string()
        } else {
            t.to_string()
        }
    }

    pub fn green<T: std::fmt::Display + OwoColorize>(t: T) -> String {
        if enabled() {
            t.green().to_string()
        } else {
            t.to_string()
        }
    }

    pub fn yellow<T: std::fmt::Display + OwoColorize>(t: T) -> String {
        if enabled() {
            t.yellow().to_string()
        } else {
            t.to_string()
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "npmguard",
    version,
    about = "A risk gate for npm install. Stops compromised packages before they run."
)]
struct Cli {
    /// Increase log verbosity (-v, -vv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Disable terminal color output.
    #[arg(long, global = true)]
    no_color: bool,

    /// Skip the local verdict cache.
    #[arg(long, global = true)]
    no_cache: bool,

    /// Emit verdict as JSON instead of text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Evaluate risk for one or more packages without installing.
    Check {
        /// One or more package specs. Examples: `lodash`, `lodash@4.17.21`, `@ctrl/tinycolor@4.0.0`.
        #[arg(required = true, num_args = 1..)]
        packages: Vec<String>,
    },

    /// Evaluate risk and (in v0.1) print what `npm install` would do. v0.2 will
    /// actually execute `npm install` inside the sandbox layer.
    Install {
        #[arg(required = true, num_args = 1..)]
        packages: Vec<String>,

        /// Auto-accept warn-level verdicts. Block-level still refuses.
        #[arg(long)]
        yes: bool,
    },

    /// Claude Code PreToolUse hook management.
    ///
    /// `hook handle` is called by the Claude Code harness on every Bash tool
    /// invocation. It reads a PreToolUse JSON event from stdin and writes a
    /// permission decision JSON to stdout. The model cannot skip this gate.
    Hook {
        #[command(subcommand)]
        sub: HookCommand,
    },
}

#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Gate called by the Claude Code harness. Reads PreToolUse JSON from
    /// stdin; writes a decision JSON to stdout.
    Handle,

    /// Install npmguard as a PreToolUse hook in the Claude Code settings file.
    /// Idempotent. Safe to run more than once.
    Install {
        /// Which settings file to target.
        #[arg(long, value_enum, default_value_t = hook::Scope::User)]
        scope: hook::Scope,
    },

    /// Remove only npmguard's hook entry from the Claude Code settings file.
    /// All other settings and hooks are preserved.
    Uninstall {
        #[arg(long, value_enum, default_value_t = hook::Scope::User)]
        scope: hook::Scope,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => "warn,npmguard=info",
        1 => "info,npmguard=debug",
        _ => "debug",
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .try_init();

    color::configure(cli.no_color);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start runtime: {}", e);
            return ExitCode::from(1);
        }
    };

    let code = rt.block_on(async {
        match run(cli).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{} {}", color::red_bold("error:"), e);
                1
            }
        }
    });
    ExitCode::from(code as u8)
}

async fn run(cli: Cli) -> Result<i32> {
    // The `hook handle` subcommand is a special path: it owns stdin/stdout and
    // must produce machine-readable JSON. Skip the normal engine/cache setup.
    if let Command::Hook { sub } = &cli.command {
        match sub {
            HookCommand::Handle => {
                hook::handle(cli.no_cache).await?;
                return Ok(0);
            }
            HookCommand::Install { scope } => {
                hook::install(*scope)?;
                return Ok(0);
            }
            HookCommand::Uninstall { scope } => {
                hook::uninstall(*scope)?;
                return Ok(0);
            }
        }
    }

    let engine = RiskEngine::new()?;
    let cache = if cli.no_cache {
        None
    } else {
        let path = VerdictCache::default_path()?;
        match VerdictCache::open(&path) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!("disabling cache: {}", e);
                None
            }
        }
    };

    let (packages, install_mode, auto_yes) = match cli.command {
        Command::Check { packages } => (packages, false, false),
        Command::Install { packages, yes } => (packages, true, yes),
        Command::Hook { .. } => unreachable!("handled above"),
    };

    let mut worst: i32 = 0;
    for spec in packages {
        let pkg = PackageRef::parse(&spec)?;
        let verdict = resolve_verdict(&engine, cache.as_ref(), &pkg).await?;
        let code = present(
            &verdict,
            cli.json,
            install_mode,
            auto_yes,
            engine.thresholds(),
        )?;
        worst = worst.max(code);
    }
    Ok(worst)
}

/// Cache-aware verdict resolution: fetch metadata first, consult the cache by
/// resolved version, full-evaluate only on miss, then write back.
async fn resolve_verdict(
    engine: &RiskEngine,
    cache: Option<&VerdictCache>,
    pkg: &PackageRef,
) -> Result<RiskVerdict> {
    let meta = engine.fetch_metadata(pkg).await?;
    let signal_hash = engine.signal_set_hash();
    if let Some(c) = cache {
        match c.get(pkg, &meta.resolved_version, &signal_hash) {
            Ok(Some(cached)) => {
                tracing::debug!(
                    "cache hit: {}@{}",
                    cached.package.name,
                    cached.resolved_version
                );
                return Ok(cached);
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("cache get failed (continuing without): {}", e),
        }
    }
    let verdict = engine.evaluate_from_metadata(pkg, meta).await?;
    if let Some(c) = cache {
        if let Err(e) = c.put(&verdict) {
            tracing::warn!("cache put failed (verdict still returned): {}", e);
        }
    }
    Ok(verdict)
}

fn present(
    verdict: &RiskVerdict,
    as_json: bool,
    install_mode: bool,
    auto_yes: bool,
    thresholds: &Thresholds,
) -> Result<i32> {
    if as_json {
        let out = serde_json::to_string_pretty(verdict)?;
        println!("{}", out);
        return Ok(verdict.level.exit_code());
    }

    print_verdict(verdict, thresholds);

    if !install_mode {
        return Ok(verdict.level.exit_code());
    }

    match verdict.level {
        RiskLevel::Block => {
            eprintln!(
                "{} refusing to install {} (score {} ≥ block threshold {})",
                color::red_bold("blocked:"),
                verdict.package.display(),
                verdict.score,
                thresholds.block
            );
            Ok(2)
        }
        RiskLevel::Warn => {
            if auto_yes {
                println!(
                    "{} install requested with --yes; would proceed in v0.2.",
                    color::yellow_bold("warn:")
                );
                Ok(notice_pending_install())
            } else if std::io::stdin().is_terminal() {
                let proceed = prompt_yes_no(&format!(
                    "Proceed with install of {}? [y/N] ",
                    verdict.package.display()
                ))?;
                if proceed {
                    Ok(notice_pending_install())
                } else {
                    println!("{} aborted by user.", color::yellow_bold("warn:"));
                    Ok(1)
                }
            } else {
                eprintln!(
                    "{} non-TTY; auto-declining warn-level install. Re-run with --yes to override.",
                    color::yellow_bold("warn:")
                );
                Ok(1)
            }
        }
        RiskLevel::Ok => Ok(notice_pending_install()),
    }
}

fn notice_pending_install() -> i32 {
    println!(
        "\n{} v0.1 prints verdicts but does NOT yet execute `npm install`. \n  → v0.2 will run the install inside the sandbox layer.",
        color::blue_bold("note:")
    );
    0
}

fn print_verdict(v: &RiskVerdict, t: &Thresholds) {
    let (label, color_score) = match v.level {
        RiskLevel::Ok => (color::green("ok"), color::green(v.score)),
        RiskLevel::Warn => (color::yellow("warn"), color::yellow(v.score)),
        RiskLevel::Block => (color::red_bold("block"), color::red_bold(v.score)),
    };
    println!(
        "\n{}  {}@{}  →  score {} / 200  ({}, thresholds warn={} block={})",
        color::bold("npmguard"),
        color::bold(&v.package.name),
        v.resolved_version,
        color_score,
        label,
        t.warn,
        t.block
    );
    if v.signals.is_empty() {
        println!("  no risk signals triggered.");
    } else {
        for s in &v.signals {
            println!(
                "  {:>3} pts  {:<20} {}",
                s.points,
                format!("{:?}", s.kind),
                s.detail
            );
        }
    }
}

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
