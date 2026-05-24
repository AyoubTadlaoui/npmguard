//! Malware evaluation across a resolved dependency closure.
//!
//! The root verdict scores one package; this layer scans the whole transitive
//! set for malware, the way a worm like sha1-hulud actually spreads: through a
//! deeply nested transitive dependency, invisible to a single-package check.
//!
//! Detection is deliberately narrow and high-confidence, not a re-run of the
//! full scoring engine over hundreds of packages:
//!   * OSV `MAL-*` / `OSV-MAL-*` advisories, gathered via the batch endpoint so a
//!     600-node closure costs one HTTP round trip, not 600.
//!   * npm `-security` takedown stubs, detected locally with no network.
//!
//! Both checks are best-effort: a non-2xx OSV response is logged and treated as
//! "no advisories" rather than aborting the scan. The classification step is a
//! pure function over already-fetched results so it can be unit-tested.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::resolver::ResolvedNode;

const OSV_QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const USER_AGENT: &str = concat!("npmguard/", env!("CARGO_PKG_VERSION"));

/// OSV `/v1/querybatch` caps a request at 1000 queries; chunk the closure to
/// stay under it.
const OSV_BATCH_LIMIT: usize = 1000;

/// npm publishes an `X.Y.Z-security` placeholder when it removes a package,
/// almost always after malware. A closure node on such a version resolves to a
/// dead stub.
const SECURITY_HOLDING_SUFFIX: &str = "-security";

/// A malicious node found in the closure, with the reason it was flagged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureFinding {
    pub node: ResolvedNode,
    /// Human-readable reason: the OSV `MAL-*` id(s) or the security-holding note.
    pub detail: String,
}

/// The outcome of scanning a dependency closure for malware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureReport {
    /// How many transitive nodes were scanned (the closure size).
    pub scanned: usize,
    /// Malicious nodes, in closure order.
    pub findings: Vec<ClosureFinding>,
}

impl ClosureReport {
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

#[derive(Serialize)]
struct OsvBatchQuery<'a> {
    queries: Vec<OsvBatchEntry<'a>>,
}

#[derive(Serialize)]
struct OsvBatchEntry<'a> {
    version: &'a str,
    package: OsvPackage<'a>,
}

#[derive(Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Deserialize, Debug, Default)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvBatchResult>,
}

#[derive(Deserialize, Debug, Default)]
struct OsvBatchResult {
    #[serde(default)]
    vulns: Vec<OsvBatchVuln>,
}

#[derive(Deserialize, Debug)]
struct OsvBatchVuln {
    id: String,
}

/// Is an OSV id in the malicious-package namespace.
fn is_malware_id(id: &str) -> bool {
    id.starts_with("MAL-") || id.starts_with("OSV-MAL-")
}

/// Scan a resolved closure for malware and build the report.
///
/// Runs the OSV batch query over every node, then folds in the local
/// security-holding check. `scanned` is the closure size regardless of how many
/// findings surface.
pub async fn evaluate_closure_nodes(
    http: &reqwest::Client,
    nodes: Vec<ResolvedNode>,
) -> Result<ClosureReport> {
    let scanned = nodes.len();
    if nodes.is_empty() {
        return Ok(ClosureReport {
            scanned,
            findings: Vec::new(),
        });
    }

    // Per-node OSV ids, index-aligned with `nodes`. Best-effort: a failed chunk
    // contributes empty results rather than aborting.
    let mut osv_ids: Vec<Vec<String>> = vec![Vec::new(); nodes.len()];
    for (chunk_idx, chunk) in nodes.chunks(OSV_BATCH_LIMIT).enumerate() {
        let base = chunk_idx * OSV_BATCH_LIMIT;
        match osv_querybatch(http, chunk).await {
            Ok(per_node) => {
                for (i, ids) in per_node.into_iter().enumerate() {
                    if let Some(slot) = osv_ids.get_mut(base + i) {
                        *slot = ids;
                    }
                }
            }
            Err(e) => tracing::warn!("closure: osv querybatch failed: {e}"),
        }
    }

    Ok(classify_closure(&nodes, &osv_ids))
}

/// Pure classification: given the closure nodes and the OSV ids found for each
/// (index-aligned), produce the findings. A node is malicious when it has an
/// OSV `MAL-*` id, or its version is an npm `-security` takedown stub.
fn classify_closure(nodes: &[ResolvedNode], osv_ids: &[Vec<String>]) -> ClosureReport {
    let mut findings = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let mut reasons: Vec<String> = Vec::new();

        let mal_ids: Vec<&str> = osv_ids
            .get(i)
            .map(|ids| {
                ids.iter()
                    .filter(|id| is_malware_id(id))
                    .map(String::as_str)
                    .collect()
            })
            .unwrap_or_default();
        if !mal_ids.is_empty() {
            reasons.push(format!(
                "confirmed malicious by OSV: {}",
                mal_ids.join(", ")
            ));
        }

        if node.version.ends_with(SECURITY_HOLDING_SUFFIX) {
            reasons.push(format!(
                "npm security-holding placeholder `{}`, the package was removed, typically after malware",
                node.version
            ));
        }

        if !reasons.is_empty() {
            findings.push(ClosureFinding {
                node: node.clone(),
                detail: reasons.join("; "),
            });
        }
    }

    ClosureReport {
        scanned: nodes.len(),
        findings,
    }
}

/// One OSV `/v1/querybatch` call over a chunk of nodes. Returns the ids per node,
/// index-aligned with the input chunk. A non-2xx response is logged and treated
/// as "no advisories" so the scan degrades gracefully.
async fn osv_querybatch(
    http: &reqwest::Client,
    chunk: &[ResolvedNode],
) -> Result<Vec<Vec<String>>> {
    let body = OsvBatchQuery {
        queries: chunk
            .iter()
            .map(|n| OsvBatchEntry {
                version: &n.version,
                package: OsvPackage {
                    name: &n.name,
                    ecosystem: "npm",
                },
            })
            .collect(),
    };
    let resp = http
        .post(OSV_QUERYBATCH_URL)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .json(&body)
        .send()
        .await
        .context("posting to osv.dev querybatch")?;
    if !resp.status().is_success() {
        tracing::warn!("osv.dev querybatch returned {}", resp.status());
        return Ok(vec![Vec::new(); chunk.len()]);
    }
    let parsed: OsvBatchResponse = resp.json().await.context("parsing osv batch response")?;
    // OSV returns results index-aligned with queries; pad to the chunk length in
    // case the server returns fewer entries.
    let mut out: Vec<Vec<String>> = parsed
        .results
        .into_iter()
        .map(|r| r.vulns.into_iter().map(|v| v.id).collect())
        .collect();
    out.resize(chunk.len(), Vec::new());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, version: &str) -> ResolvedNode {
        ResolvedNode {
            name: name.to_string(),
            version: version.to_string(),
            path: vec!["root".to_string(), name.to_string()],
        }
    }

    #[test]
    fn flags_mal_id_and_security_holding() {
        let nodes = vec![
            node("clean-pkg", "1.0.0"),
            node("evil-pkg", "2.3.4"),
            node("removed-pkg", "0.0.1-security"),
        ];
        // OSV ids index-aligned: only evil-pkg has a MAL id; a plain CVE on
        // clean-pkg must NOT flag (only MAL ids are malware here).
        let osv_ids = vec![
            vec!["CVE-2023-0001".to_string()],
            vec!["MAL-2025-12345".to_string()],
            vec![],
        ];
        let report = classify_closure(&nodes, &osv_ids);
        assert_eq!(report.scanned, 3);
        assert_eq!(report.findings.len(), 2);

        let evil = report
            .findings
            .iter()
            .find(|f| f.node.name == "evil-pkg")
            .expect("evil-pkg flagged");
        assert!(evil.detail.contains("MAL-2025-12345"));
        assert!(evil.detail.contains("malicious by OSV"));

        let removed = report
            .findings
            .iter()
            .find(|f| f.node.name == "removed-pkg")
            .expect("security-holding flagged");
        assert!(removed.detail.contains("security-holding"));
        assert!(removed.detail.contains("0.0.1-security"));

        // clean-pkg with only a CVE is not a closure malware finding.
        assert!(report.findings.iter().all(|f| f.node.name != "clean-pkg"));
    }

    #[test]
    fn osv_mal_prefix_also_flags() {
        let nodes = vec![node("evil", "1.0.0")];
        let osv_ids = vec![vec!["OSV-MAL-9999".to_string()]];
        let report = classify_closure(&nodes, &osv_ids);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].detail.contains("OSV-MAL-9999"));
    }

    #[test]
    fn node_flagged_by_both_reasons_merges_detail() {
        // A node that is both on a security stub and carries a MAL id reports
        // both reasons.
        let nodes = vec![node("doomed", "9.9.9-security")];
        let osv_ids = vec![vec!["MAL-2025-1".to_string()]];
        let report = classify_closure(&nodes, &osv_ids);
        assert_eq!(report.findings.len(), 1);
        let d = &report.findings[0].detail;
        assert!(d.contains("MAL-2025-1"));
        assert!(d.contains("security-holding"));
    }

    #[test]
    fn clean_closure_has_no_findings() {
        let nodes = vec![node("a", "1.0.0"), node("b", "2.0.0")];
        let osv_ids = vec![vec![], vec!["CVE-x".to_string()]];
        let report = classify_closure(&nodes, &osv_ids);
        assert_eq!(report.scanned, 2);
        assert!(!report.has_findings());
    }

    #[test]
    fn missing_osv_alignment_does_not_panic() {
        // Fewer osv_ids entries than nodes (server returned short): nodes
        // without an entry simply have no OSV reason.
        let nodes = vec![node("a", "1.0.0"), node("b", "0.0.1-security")];
        let osv_ids: Vec<Vec<String>> = vec![];
        let report = classify_closure(&nodes, &osv_ids);
        // b still flags on the local security-holding check.
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].node.name, "b");
    }
}
