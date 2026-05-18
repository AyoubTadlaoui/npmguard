//! Local verdict cache (SQLite, single file).
//!
//! Keyed on (name, version, signal_set_hash). A change to the active signal
//! set or scoring thresholds invalidates prior verdicts automatically because
//! the hash component is different.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use directories::ProjectDirs;
use rusqlite::{params, Connection, OptionalExtension};

use npmguard_risk::{PackageRef, RiskVerdict};

/// Cache TTLs.
#[derive(Debug, Clone, Copy)]
pub struct CachePolicy {
    /// TTL for packages younger than `stable_age`.
    pub fresh_ttl: Duration,
    /// TTL for packages older than `stable_age`.
    pub stable_ttl: Duration,
    /// Threshold above which a package's verdict is "stable".
    pub stable_age: Duration,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            fresh_ttl: Duration::hours(24),
            stable_ttl: Duration::days(7),
            stable_age: Duration::days(30),
        }
    }
}

pub struct VerdictCache {
    conn: Mutex<Connection>,
    policy: CachePolicy,
}

impl VerdictCache {
    pub fn default_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("dev", "npmguard", "npmguard")
            .context("could not determine cache directory")?;
        let dir = dirs.cache_dir().to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| format!("creating cache dir {:?}", dir))?;
        Ok(dir.join("verdicts.db"))
    }

    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating cache dir {:?}", parent))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("opening sqlite at {:?}", path))?;
        conn.execute_batch(SCHEMA)
            .context("initializing cache schema")?;
        Ok(Self {
            conn: Mutex::new(conn),
            policy: CachePolicy::default(),
        })
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
            policy: CachePolicy::default(),
        })
    }

    pub fn with_policy(mut self, policy: CachePolicy) -> Self {
        self.policy = policy;
        self
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("cache mutex poisoned"))
    }

    /// Look up a verdict for the resolved (name, version, signal_set_hash).
    /// Returns None on miss, stale entry, or schema-mismatch.
    pub fn get(
        &self,
        pkg: &PackageRef,
        signal_set_hash: &str,
        resolved_version: &str,
        published_at: Option<DateTime<Utc>>,
    ) -> Result<Option<RiskVerdict>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT verdict_json, fetched_at FROM verdicts \
             WHERE name = ?1 AND version = ?2 AND signal_set_hash = ?3",
                params![pkg.name, resolved_version, signal_set_hash],
                |row| {
                    let verdict_json: String = row.get(0)?;
                    let fetched_at: String = row.get(1)?;
                    Ok((verdict_json, fetched_at))
                },
            )
            .optional()?;
        drop(conn);

        let Some((verdict_json, fetched_at_str)) = row else {
            return Ok(None);
        };
        let fetched_at = DateTime::parse_from_rfc3339(&fetched_at_str)
            .context("parsing cached fetched_at")?
            .with_timezone(&Utc);

        // TTL: short if package itself is young, otherwise long.
        let ttl = match published_at {
            Some(pub_at) if Utc::now().signed_duration_since(pub_at) > self.policy.stable_age => {
                self.policy.stable_ttl
            }
            _ => self.policy.fresh_ttl,
        };
        if Utc::now().signed_duration_since(fetched_at) > ttl {
            return Ok(None);
        }

        let verdict: RiskVerdict =
            serde_json::from_str(&verdict_json).context("deserializing cached verdict")?;
        Ok(Some(verdict))
    }

    pub fn put(&self, verdict: &RiskVerdict) -> Result<()> {
        let json = serde_json::to_string(verdict)?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO verdicts \
             (name, version, signal_set_hash, verdict_json, fetched_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                verdict.package.name,
                verdict.resolved_version,
                verdict.signal_set_hash,
                json,
                verdict.fetched_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Drop every entry for a given package — call when a new registry version
    /// appears so the risk verdict is recomputed.
    pub fn invalidate(&self, name: &str) -> Result<usize> {
        let conn = self.lock()?;
        let n = conn.execute("DELETE FROM verdicts WHERE name = ?1", params![name])?;
        Ok(n)
    }

    pub fn purge_older_than(&self, cutoff: DateTime<Utc>) -> Result<usize> {
        let conn = self.lock()?;
        let n = conn.execute(
            "DELETE FROM verdicts WHERE fetched_at < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        Ok(n)
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS verdicts (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    signal_set_hash TEXT NOT NULL,
    verdict_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (name, version, signal_set_hash)
);
CREATE INDEX IF NOT EXISTS verdicts_name ON verdicts(name);
CREATE INDEX IF NOT EXISTS verdicts_fetched_at ON verdicts(fetched_at);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use npmguard_risk::{RiskLevel, Signal, SignalKind};

    fn sample_verdict(name: &str, version: &str, hash: &str) -> RiskVerdict {
        RiskVerdict {
            package: PackageRef::new(name, Some(version.to_string())),
            resolved_version: version.to_string(),
            score: 12,
            level: RiskLevel::Ok,
            signals: vec![Signal {
                kind: SignalKind::PackageAge,
                points: 10,
                detail: "young".into(),
            }],
            fetched_at: Utc::now(),
            signal_set_hash: hash.to_string(),
        }
    }

    #[test]
    fn round_trips_a_verdict() {
        let cache = VerdictCache::in_memory().unwrap();
        let v = sample_verdict("lodash", "4.17.21", "h1");
        cache.put(&v).unwrap();
        let pkg = PackageRef::new("lodash", Some("4.17.21".into()));
        let got = cache.get(&pkg, "h1", "4.17.21", None).unwrap().unwrap();
        assert_eq!(got.resolved_version, "4.17.21");
        assert_eq!(got.signals.len(), 1);
    }

    #[test]
    fn different_signal_hash_misses() {
        let cache = VerdictCache::in_memory().unwrap();
        let v = sample_verdict("lodash", "4.17.21", "h1");
        cache.put(&v).unwrap();
        let pkg = PackageRef::new("lodash", Some("4.17.21".into()));
        let got = cache.get(&pkg, "h2", "4.17.21", None).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn invalidate_drops_all_versions() {
        let cache = VerdictCache::in_memory().unwrap();
        cache
            .put(&sample_verdict("lodash", "4.17.20", "h1"))
            .unwrap();
        cache
            .put(&sample_verdict("lodash", "4.17.21", "h1"))
            .unwrap();
        cache.put(&sample_verdict("react", "18.0.0", "h1")).unwrap();
        let n = cache.invalidate("lodash").unwrap();
        assert_eq!(n, 2);
    }
}
