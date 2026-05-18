//! Corpus integration test.
//!
//! Live network test. Hits registry.npmjs.org + OSV.dev + api.github.com.
//! Skipped by default — run with `NPMGUARD_CORPUS=1 cargo test --test corpus -- --nocapture`.
//!
//! Pass criteria:
//! - Every entry in `known-good.json` resolves to a verdict that is NOT `Block`.
//! - Every entry in `known-bad.json` either fails to resolve (registry 404 / unpublished)
//!   OR resolves and emits at least one of the `expected_signals`.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use npmguard_risk::{PackageRef, RiskEngine, RiskLevel, SignalKind};

#[derive(Deserialize, Debug)]
struct GoodCorpus {
    entries: Vec<GoodEntry>,
}

#[derive(Deserialize, Debug)]
struct GoodEntry {
    name: String,
    version: String,
}

#[derive(Deserialize, Debug)]
struct BadCorpus {
    entries: Vec<BadEntry>,
}

#[derive(Deserialize, Debug)]
struct BadEntry {
    name: String,
    version: String,
    #[allow(dead_code)]
    incident: String,
    expected_signals: Vec<String>,
}

fn corpus_path(name: &str) -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("corpus")
        .join(name)
}

fn enabled() -> bool {
    std::env::var("NPMGUARD_CORPUS").ok().as_deref() == Some("1")
}

fn parse_signal_kind(s: &str) -> Option<SignalKind> {
    match s {
        "LifecycleScripts" => Some(SignalKind::LifecycleScripts),
        "PackageAge" => Some(SignalKind::PackageAge),
        "MaintainerChurn" => Some(SignalKind::MaintainerChurn),
        "RepoHealth" => Some(SignalKind::RepoHealth),
        "Typosquat" => Some(SignalKind::Typosquat),
        "KnownCve" => Some(SignalKind::KnownCve),
        "SoleMaintainer" => Some(SignalKind::SoleMaintainer),
        "Deprecated" => Some(SignalKind::Deprecated),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn known_good_corpus_does_not_block() {
    if !enabled() {
        eprintln!("skipping corpus test (set NPMGUARD_CORPUS=1 to enable)");
        return;
    }
    let raw = fs::read_to_string(corpus_path("known-good.json")).unwrap();
    let corpus: GoodCorpus = serde_json::from_str(&raw).unwrap();
    let engine = RiskEngine::new().unwrap();

    let mut failures = Vec::new();
    for e in corpus.entries {
        let pkg = PackageRef::new(e.name.clone(), Some(e.version.clone()));
        match engine.evaluate(&pkg).await {
            Ok(v) => {
                if v.level == RiskLevel::Block {
                    failures.push(format!(
                        "{}@{} unexpectedly BLOCKED (score {}): {:?}",
                        e.name, e.version, v.score, v.signals
                    ));
                } else {
                    eprintln!(
                        "  ok: {}@{} → {:?} score={}",
                        e.name, e.version, v.level, v.score
                    );
                }
            }
            Err(err) => failures.push(format!("{}@{}: fetch failed: {}", e.name, e.version, err)),
        }
    }
    assert!(
        failures.is_empty(),
        "known-good false positives:\n{}",
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn known_bad_corpus_surfaces_expected_signals() {
    if !enabled() {
        eprintln!("skipping corpus test (set NPMGUARD_CORPUS=1 to enable)");
        return;
    }
    let raw = fs::read_to_string(corpus_path("known-bad.json")).unwrap();
    let corpus: BadCorpus = serde_json::from_str(&raw).unwrap();
    let engine = RiskEngine::new().unwrap();

    let mut failures = Vec::new();
    for e in corpus.entries {
        let expected: Vec<SignalKind> = e
            .expected_signals
            .iter()
            .filter_map(|s| parse_signal_kind(s))
            .collect();
        let pkg = PackageRef::new(e.name.clone(), Some(e.version.clone()));
        match engine.evaluate(&pkg).await {
            Ok(v) => {
                let got: Vec<SignalKind> = v.signals.iter().map(|s| s.kind).collect();
                let any_match = expected.iter().any(|e| got.contains(e));
                if !any_match {
                    failures.push(format!(
                        "{}@{}: expected any of {:?}, got {:?} (score {})",
                        e.name, e.version, expected, got, v.score
                    ));
                } else {
                    eprintln!(
                        "  ok: {}@{} → {:?} score={} signals={:?}",
                        e.name, e.version, v.level, v.score, got
                    );
                }
            }
            Err(err) => {
                // Unpublished / 404 is acceptable — that IS a confirmed-bad signal.
                eprintln!("  ok (unresolvable): {}@{}: {}", e.name, e.version, err);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "known-bad missed signals:\n{}",
        failures.join("\n")
    );
}
