//! npmguard CLI.
//!
//! v0.1 scope: `check` and `install` both compute a risk verdict and surface it.
//! `install` will gain real `npm install` subprocess execution in v0.2 along with
//! the sandbox layer. Today, it tells you what would happen and exits.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;

use npmguard_cache::VerdictCache;
use npmguard_risk::{PackageRef, RiskEngine, RiskLevel, RiskVerdict, Thresholds};

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

    if cli.no_color {
        owo_colors::set_override(false);
    }

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
                eprintln!("{} {}", "error:".red().bold(), e);
                1
            }
        }
    });
    ExitCode::from(code as u8)
}

async fn run(cli: Cli) -> Result<i32> {
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
    };

    let mut worst: i32 = 0;
    for spec in packages {
        let pkg = PackageRef::parse(&spec)?;
        let verdict = engine.evaluate(&pkg).await?;
        if let Some(c) = &cache {
            let _ = c.put(&verdict);
        }
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
                "blocked:".red().bold(),
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
                    "warn:".yellow().bold()
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
                    println!("{} aborted by user.", "warn:".yellow().bold());
                    Ok(1)
                }
            } else {
                eprintln!(
                    "{} non-TTY; auto-declining warn-level install. Re-run with --yes to override.",
                    "warn:".yellow().bold()
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
        "note:".blue().bold()
    );
    0
}

fn print_verdict(v: &RiskVerdict, t: &Thresholds) {
    let (label, color_score) = match v.level {
        RiskLevel::Ok => ("ok".green().to_string(), v.score.green().to_string()),
        RiskLevel::Warn => ("warn".yellow().to_string(), v.score.yellow().to_string()),
        RiskLevel::Block => (
            "block".red().bold().to_string(),
            v.score.red().bold().to_string(),
        ),
    };
    println!(
        "\n{}  {}@{}  →  score {} / 200  ({}, thresholds warn={} block={})",
        "npmguard".bold(),
        v.package.name.bold(),
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
