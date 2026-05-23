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
    version: &'a str,
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
    let body = OsvQuery {
        package: OsvPackage {
            name: &pkg.name,
            ecosystem: "npm",
        },
        version: resolved_version,
    };
    let resp = http
        .post(OSV_QUERY_URL)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .json(&body)
        .send()
        .await
        .context("posting to osv.dev")?;
    if !resp.status().is_success() {
        // OSV is best-effort. Surface as a soft failure rather than blocking.
        tracing::warn!("osv.dev returned {} for {}", resp.status(), pkg.display());
        return Ok(Vec::new());
    }
    let parsed: OsvResponse = resp.json().await.context("parsing osv response")?;
    if parsed.vulns.is_empty() {
        return Ok(Vec::new());
    }
    // OSV's `MAL-*` namespace is the malicious-package database. Anything in
    // that namespace is confirmed-malicious by OSV, not a vulnerability in
    // a legitimate package, and warrants an immediate block regardless of
    // any CVSS string.
    let malicious = parsed
        .vulns
        .iter()
        .any(|v| v.id.starts_with("MAL-") || v.id.starts_with("OSV-MAL-"));

    let max_severity = parsed.vulns.iter().map(severity_rank).max().unwrap_or(0);
    let points = if malicious {
        // Single-signal block; see scoring::Thresholds::default (block = 70).
        80
    } else {
        match max_severity {
            4 => 50, // critical
            3 => 20, // high
            2 => 10, // medium
            _ => 5,  // low / unknown
        }
    };
    let ids: Vec<&str> = parsed.vulns.iter().map(|v| v.id.as_str()).take(3).collect();
    let extra = if parsed.vulns.len() > 3 {
        format!(" (+{} more)", parsed.vulns.len() - 3)
    } else {
        String::new()
    };
    let label = if malicious {
        "CONFIRMED MALICIOUS by OSV"
    } else {
        "known advisories"
    };
    Ok(vec![Signal {
        kind: SignalKind::KnownCve,
        points,
        detail: format!(
            "{} {} for this version: {}{}",
            parsed.vulns.len(),
            label,
            ids.join(", "),
            extra
        ),
    }])
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
