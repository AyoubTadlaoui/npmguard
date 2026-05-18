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
    // that namespace is confirmed-malicious by OSV — not a vulnerability in
    // a legitimate package — and warrants an immediate block regardless of
    // any CVSS string.
    let malicious = parsed
        .vulns
        .iter()
        .any(|v| v.id.starts_with("MAL-") || v.id.starts_with("OSV-MAL-"));

    let max_severity = parsed.vulns.iter().map(severity_rank).max().unwrap_or(0);
    let points = if malicious {
        // Single-signal block — see scoring::Thresholds::default (block = 70).
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
    // OSV returns CVSS scores as strings; we coarsely bucket them.
    let cvss = v.severity.iter().find_map(|s| {
        if s.severity_type.starts_with("CVSS") {
            s.score
                .split('/')
                .next()
                .and_then(|n| n.parse::<f32>().ok())
        } else {
            None
        }
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
