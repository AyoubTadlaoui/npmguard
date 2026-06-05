//! OSV.dev vulnerability lookup.
//!
//! Queries the OSV API for known advisories affecting (name, version) in the
//! npm ecosystem. We only report severity: presence of an advisory is enough.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::types::{PackageRef, Signal, SignalKind};

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const USER_AGENT: &str = concat!("npmguard/", env!("CARGO_PKG_VERSION"));

#[derive(Serialize)]
struct OsvQuery<'a> {
    package: OsvPackage<'a>,
    // Omitted entirely for a package-level query. OSV treats a missing
    // `version` as "return every advisory for this package".
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
}

#[derive(Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Deserialize, Debug)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize, Debug)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct OsvSeverity {
    #[serde(rename = "type", default)]
    severity_type: String,
    #[serde(default)]
    score: String,
}

pub async fn evaluate(
    http: &reqwest::Client,
    pkg: &PackageRef,
    resolved_version: &str,
) -> Result<Vec<Signal>> {
    // Two queries, run concurrently:
    //  * versioned     - OSV server-side matches the resolved version against
    //                    advisory ranges. Authoritative for both CVEs and
    //                    malware that actually affect this version.
    //  * package-level - no version, so OSV returns every advisory for the
    //                    name. Used as a malware fallback ONLY when the resolved
    //                    version is a prerelease: semver range matching excludes
    //                    a prerelease (e.g. an npm `-security` takedown stub)
    //                    from an `introduced: 0` range, silently dropping a
    //                    whole-package MAL advisory on the versioned query.
    let (versioned, package_level) = futures::future::join(
        query(http, &pkg.name, Some(resolved_version)),
        query(http, &pkg.name, None),
    )
    .await;
    let versioned = versioned?;
    let package_level = package_level?;
    // A prerelease tag is a `-` in the version core (build metadata uses `+`).
    let resolved_is_prerelease = resolved_version.contains('-');
    Ok(classify(&versioned, &package_level, resolved_is_prerelease)
        .into_iter()
        .collect())
}

/// OSV's `MAL-*` namespace is the malicious-package database. A hit confirms
/// malware (not a flaw in a legitimate package); both the `MAL-` and the
/// `OSV-MAL-` id prefixes are used in practice.
fn is_malware_id(id: &str) -> bool {
    id.starts_with("MAL-") || id.starts_with("OSV-MAL-")
}

/// Extract the deduped malicious-package advisory ids from a set of OSV vulns,
/// preserving first-seen order.
fn malware_ids(vulns: &[OsvVuln]) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for v in vulns {
        if is_malware_id(&v.id) && !ids.iter().any(|x| x == &v.id) {
            ids.push(v.id.clone());
        }
    }
    ids
}

/// Look up malicious-package advisories for a package by NAME ONLY, for the case
/// where the npm registry no longer serves it (a 404 / removed package).
///
/// Unlike [`evaluate`], this applies no version or prerelease gating. The
/// prerelease gate in [`classify`] exists to protect the clean *current* version
/// of a still-published package that was compromised only in since-removed
/// versions. A package npm has fully removed has no current version to protect,
/// so any `MAL-*` advisory for the name is authoritative evidence it was taken
/// down for malware. Returns the advisory ids, or an empty vec when OSV has none
/// (a genuinely unknown / never-published name).
pub async fn malware_advisories_for_name(
    http: &reqwest::Client,
    name: &str,
) -> Result<Vec<String>> {
    let vulns = query(http, name, None).await?;
    Ok(malware_ids(&vulns))
}

/// Issue a single OSV `/v1/query`. `version = None` is a package-level query
/// (every advisory for the package); `Some(v)` asks OSV to match `v` against
/// advisory ranges. Best-effort: a non-2xx response is logged and treated as
/// "no advisories" rather than blocking the caller.
async fn query(http: &reqwest::Client, name: &str, version: Option<&str>) -> Result<Vec<OsvVuln>> {
    let body = OsvQuery {
        package: OsvPackage {
            name,
            ecosystem: "npm",
        },
        version,
    };
    let resp = http
        .post(OSV_QUERY_URL)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .json(&body)
        .send()
        .await
        .context("posting to osv.dev")?;
    if !resp.status().is_success() {
        tracing::warn!("osv.dev returned {} for {}", resp.status(), name);
        return Ok(Vec::new());
    }
    let parsed: OsvResponse = resp.json().await.context("parsing osv response")?;
    Ok(parsed.vulns)
}

/// Pure decision over OSV results.
///
/// OSV's `MAL-*` namespace is the malicious-package database: a hit confirms
/// malware, not a flaw in a legitimate package, and blocks regardless of CVSS.
/// A MAL advisory matched to the resolved version (the versioned query) is
/// authoritative. We additionally honor a package-level MAL hit ONLY when the
/// resolved version is a prerelease, because OSV's semver matching wrongly
/// excludes prereleases from open-ended ranges (the `-security` takedown-stub
/// case). We must NOT blanket-trust package-level MAL for a normal version: a
/// legitimate package compromised only in specific, since-removed versions has
/// a clean current version that must never be labelled malicious.
///
/// Absent malware, fall back to the worst CVE severity in the version-matched
/// set, so an advisory that does not affect the resolved version cannot inflate
/// the score.
fn classify(
    versioned: &[OsvVuln],
    package_level: &[OsvVuln],
    resolved_is_prerelease: bool,
) -> Option<Signal> {
    // The versioned query is authoritative; the package-level query is a
    // prerelease-only fallback (see the doc comment above).
    let mut mal_sources: Vec<&OsvVuln> =
        versioned.iter().filter(|v| is_malware_id(&v.id)).collect();
    if resolved_is_prerelease {
        mal_sources.extend(package_level.iter().filter(|v| is_malware_id(&v.id)));
    }
    let mut mal_ids: Vec<&str> = Vec::new();
    for v in mal_sources {
        if !mal_ids.contains(&v.id.as_str()) {
            mal_ids.push(v.id.as_str());
        }
    }
    if !mal_ids.is_empty() {
        let shown = mal_ids
            .iter()
            .take(3)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        let extra = if mal_ids.len() > 3 {
            format!(" (+{} more)", mal_ids.len() - 3)
        } else {
            String::new()
        };
        return Some(Signal {
            kind: SignalKind::KnownCve,
            // Single-signal block; see scoring::Thresholds::default (block = 70).
            points: 80,
            detail: format!(
                "{} confirmed malicious by OSV: {}{}",
                mal_ids.len(),
                shown,
                extra
            ),
        });
    }

    if versioned.is_empty() {
        return None;
    }
    let max_severity = versioned.iter().map(severity_rank).max().unwrap_or(0);
    let points = match max_severity {
        4 => 50, // critical
        3 => 20, // high
        2 => 10, // medium
        _ => 5,  // low / unknown
    };
    let ids: Vec<&str> = versioned.iter().map(|v| v.id.as_str()).take(3).collect();
    let extra = if versioned.len() > 3 {
        format!(" (+{} more)", versioned.len() - 3)
    } else {
        String::new()
    };
    Some(Signal {
        kind: SignalKind::KnownCve,
        points,
        detail: format!(
            "{} known advisories for this version: {}{}",
            versioned.len(),
            ids.join(", "),
            extra
        ),
    })
}

fn severity_rank(v: &OsvVuln) -> u8 {
    // OSV's `severity[].score` for a `CVSS_V3` entry is the full vector string
    // (e.g. `CVSS:3.1/AV:N/...`), NOT a leading number; a naive
    // `split('/').next().parse()` always fails and silently under-scores real
    // criticals. Compute the base score from the vector; also accept a bare
    // numeric score from sources that store one. Take the max across entries.
    let cvss = v
        .severity
        .iter()
        .filter(|s| s.severity_type.starts_with("CVSS"))
        .filter_map(|s| {
            s.score
                .parse::<f32>()
                .ok()
                .or_else(|| cvss_v3_base_score(&s.score))
        })
        .fold(None, |acc: Option<f32>, x| {
            Some(acc.map_or(x, |a| a.max(x)))
        });
    if let Some(score) = cvss {
        return if score >= 9.0 {
            4
        } else if score >= 7.0 {
            3
        } else if score >= 4.0 {
            2
        } else {
            1
        };
    }
    // Fallback: GHSA database_specific.severity string.
    if let Some(s) = v
        .database_specific
        .get("severity")
        .and_then(|x| x.as_str())
        .map(|s| s.to_ascii_lowercase())
    {
        return match s.as_str() {
            "critical" => 4,
            "high" => 3,
            "moderate" | "medium" => 2,
            _ => 1,
        };
    }
    1
}

/// Compute the CVSS v3.x base score from a vector string like
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (CVSS v3.1 spec, Appendix A).
/// Returns `None` for anything that is not a recognizable v3 base vector
/// (a v2/v4 vector, or one missing a required base metric). Used only to bucket
/// severity into 4 coarse levels, so the simplified one-decimal roundup is more
/// than accurate enough; the result is well within the 2-point bucket gaps.
fn cvss_v3_base_score(vector: &str) -> Option<f32> {
    if !vector.starts_with("CVSS:3") {
        return None;
    }
    let get = |key: &str| -> Option<&str> {
        vector
            .split('/')
            .skip(1)
            .filter_map(|p| p.split_once(':'))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    };

    let scope_changed = match get("S")? {
        "C" => true,
        "U" => false,
        _ => return None,
    };
    let av: f64 = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac: f64 = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr: f64 = match get("PR")? {
        "N" => 0.85,
        "L" => {
            if scope_changed {
                0.68
            } else {
                0.62
            }
        }
        "H" => {
            if scope_changed {
                0.50
            } else {
                0.27
            }
        }
        _ => return None,
    };
    let ui: f64 = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let impact_metric = |x: &str| -> Option<f64> {
        match x {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let c = impact_metric(get("C")?)?;
    let i = impact_metric(get("I")?)?;
    let a = impact_metric(get("A")?)?;

    let isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02).powi(15)
    } else {
        6.42 * isc_base
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    // Roundup to one decimal place.
    Some(((raw * 10.0).ceil() / 10.0) as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank_for_cvss(vector: &str) -> u8 {
        severity_rank(&OsvVuln {
            id: "CVE-test".into(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".into(),
                score: vector.into(),
            }],
            database_specific: serde_json::Value::Null,
        })
    }

    fn vuln(id: &str) -> OsvVuln {
        OsvVuln {
            id: id.into(),
            severity: vec![],
            database_specific: serde_json::Value::Null,
        }
    }

    fn cve(score: &str) -> OsvVuln {
        OsvVuln {
            id: "CVE-x".into(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".into(),
                score: score.into(),
            }],
            database_specific: serde_json::Value::Null,
        }
    }

    #[test]
    fn prerelease_malware_in_package_level_blocks_when_versioned_empty() {
        // The lodahs regression: the resolved version is a `-security`
        // prerelease, so OSV's versioned query returns nothing, but the
        // package-level query surfaces the MAL advisory. Because the resolved
        // version is a prerelease, we honor it and block.
        let sig = classify(&[], &[vuln("MAL-2025-25502")], true).expect("malware signal");
        assert_eq!(sig.kind, SignalKind::KnownCve);
        assert_eq!(sig.points, 80);
        assert!(sig.detail.contains("MAL-2025-25502"));
        assert!(sig.detail.contains("malicious"));
    }

    #[test]
    fn package_level_malware_does_not_block_a_clean_normal_version() {
        // The create-glee-app regression: a legitimate package was compromised
        // only in specific, since-removed versions. Its clean current (non
        // prerelease) version must NOT be labelled malicious just because a MAL
        // advisory exists for the name at package level.
        assert!(classify(&[], &[vuln("MAL-2025-190767")], false).is_none());
    }

    #[test]
    fn malware_in_versioned_set_blocks_regardless_of_prerelease() {
        // A MAL advisory matched to the resolved version is authoritative.
        assert_eq!(
            classify(&[vuln("OSV-MAL-1")], &[], false)
                .expect("malware signal")
                .points,
            80
        );
    }

    #[test]
    fn versioned_cve_ranks_by_severity_not_malware() {
        let sig = classify(&[cve("7.5")], &[], false).expect("cve signal");
        assert_eq!(sig.kind, SignalKind::KnownCve);
        assert_eq!(sig.points, 20); // high
        assert!(sig.detail.contains("known advisories"));
    }

    #[test]
    fn package_level_cve_does_not_inflate_score() {
        // A non-malware advisory present only at package level (OSV did not
        // match it to the resolved version) must not be scored as affecting it.
        assert!(classify(&[], &[cve("9.8")], true).is_none());
    }

    #[test]
    fn no_advisories_anywhere_is_none() {
        assert!(classify(&[], &[], false).is_none());
    }

    #[test]
    fn malware_ids_keeps_only_mal_advisories() {
        let vulns = vec![
            vuln("MAL-2025-1"),
            cve("9.8"),
            vuln("OSV-MAL-2"),
            vuln("GHSA-abcd"),
        ];
        assert_eq!(malware_ids(&vulns), vec!["MAL-2025-1", "OSV-MAL-2"]);
    }

    #[test]
    fn malware_ids_dedups_preserving_order() {
        let vulns = vec![vuln("MAL-2025-1"), vuln("MAL-2025-1"), vuln("MAL-2025-2")];
        assert_eq!(malware_ids(&vulns), vec!["MAL-2025-1", "MAL-2025-2"]);
    }

    #[test]
    fn malware_ids_empty_when_no_malware() {
        assert!(malware_ids(&[cve("7.5"), vuln("GHSA-x")]).is_empty());
    }

    #[test]
    fn computes_canonical_critical_vector() {
        // The canonical 9.8 CVSS:3.1 vector (network, no auth, full impact).
        let s = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((s - 9.8).abs() < 0.1, "got {}", s);
    }

    #[test]
    fn computes_scope_changed_vector() {
        // Scope-changed reflected-XSS-style vector scores 6.1.
        let s = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").unwrap();
        assert!((s - 6.1).abs() < 0.1, "got {}", s);
    }

    #[test]
    fn no_impact_vector_scores_zero() {
        let s = cvss_v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").unwrap();
        assert_eq!(s, 0.0);
    }

    #[test]
    fn vector_string_buckets_as_critical_not_low() {
        // Regression for the under-scoring bug: a vector-string severity must
        // bucket on its real score (critical = 4), not collapse to the
        // unknown-severity floor (1).
        assert_eq!(
            rank_for_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            4
        );
    }

    #[test]
    fn non_v3_vector_is_not_parsed() {
        assert!(cvss_v3_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P").is_none());
        assert!(cvss_v3_base_score("9.8").is_none());
    }

    #[test]
    fn bare_numeric_score_still_works() {
        // Sources that store a numeric score (no vector) keep working.
        assert_eq!(rank_for_cvss("9.8"), 4);
        assert_eq!(rank_for_cvss("5.0"), 2);
    }

    #[test]
    fn database_specific_fallback_when_no_cvss() {
        let v = OsvVuln {
            id: "GHSA-x".into(),
            severity: vec![],
            database_specific: serde_json::json!({ "severity": "HIGH" }),
        };
        assert_eq!(severity_rank(&v), 3);
    }
}
