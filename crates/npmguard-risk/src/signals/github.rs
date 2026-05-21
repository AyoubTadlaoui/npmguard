//! GitHub repo-health signal.
//!
//! Only runs if the registry exposed a github.com repository URL. We make a
//! single unauthenticated `GET /repos/{owner}/{repo}` call; rate-limited to
//! 60/hr per IP. The signal is silently skipped on 403/404.

use anyhow::Result;
use serde::Deserialize;

use crate::signals::registry::PackageMetadata;
use crate::types::{Signal, SignalKind};

const USER_AGENT: &str = concat!("npmguard/", env!("CARGO_PKG_VERSION"));

#[derive(Deserialize, Debug)]
struct GhRepo {
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    stargazers_count: u64,
    #[serde(default)]
    pushed_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn evaluate(http: &reqwest::Client, meta: &PackageMetadata) -> Result<Vec<Signal>> {
    let Some(url) = meta.repository_url.as_deref() else {
        return Ok(Vec::new());
    };
    let Some((owner, repo)) = parse_github(url) else {
        return Ok(Vec::new());
    };
    let api = format!("https://api.github.com/repos/{}/{}", owner, repo);
    let resp = http
        .get(&api)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("github fetch failed: {}", e);
            return Ok(Vec::new());
        }
    };
    if !resp.status().is_success() {
        tracing::debug!("github returned {} for {}", resp.status(), api);
        return Ok(Vec::new());
    }
    let r: GhRepo = match resp.json().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("github json parse: {}", e);
            return Ok(Vec::new());
        }
    };
    let mut sigs = Vec::new();
    if r.archived {
        sigs.push(Signal {
            kind: SignalKind::RepoHealth,
            points: 15,
            detail: format!("source repo {}/{} is archived", owner, repo),
        });
    }
    let now = chrono::Utc::now();
    let stale_6mo = r
        .pushed_at
        .map(|t| now.signed_duration_since(t) > chrono::Duration::days(180))
        .unwrap_or(false);
    if r.stargazers_count == 0 && stale_6mo {
        sigs.push(Signal {
            kind: SignalKind::RepoHealth,
            points: 10,
            detail: format!(
                "source repo {}/{} has 0 stars and no commits in 6 months",
                owner, repo
            ),
        });
    }
    Ok(sigs)
}

fn parse_github(url: &str) -> Option<(String, String)> {
    let url = url.trim().trim_end_matches('/');
    let rest = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
        .or_else(|| url.strip_prefix("github.com/"))?;
    let (owner, repo) = rest.split_once('/')?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_github_url() {
        assert_eq!(
            parse_github("https://github.com/lodash/lodash"),
            Some(("lodash".into(), "lodash".into()))
        );
        assert_eq!(
            parse_github("https://github.com/lodash/lodash/"),
            Some(("lodash".into(), "lodash".into()))
        );
        assert_eq!(parse_github("https://gitlab.com/foo/bar"), None);
    }
}
