//! Local verdict cache (SQLite, single file).
//!
//! Keyed on (name, resolved_version, signal_set_hash). The TTL is computed
//! internally from the stored `published_at`: young packages get a short
//! TTL (24h), stable packages a longer one (7d). A change to the active
//! signal set or scoring thresholds invalidates prior verdicts automatically
//! because the hash component is different.

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

/// Bump on any schema change. On version mismatch the table is dropped and
/// recreated; verdicts are regenerable, so a clean slate beats migration
/// gymnastics for this cache.
const SCHEMA_VERSION: i32 = 2;

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
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            policy: CachePolicy::default(),
        })
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            policy: CachePolicy::default(),
        })
    }

    pub fn with_policy(mut self, policy: CachePolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy(&self) -> &CachePolicy {
        &self.policy
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("cache mutex poisoned"))
    }

    /// Look up a verdict for the resolved (name, version, signal_set_hash).
    /// Returns None on miss, on stale entry, or on a schema mismatch. The
    /// caller does not need to supply `published_at`; the cache reads it
    /// from the stored row when picking a TTL.
    pub fn get(
        &self,
        pkg: &PackageRef,
        resolved_version: &str,
        signal_set_hash: &str,
    ) -> Result<Option<RiskVerdict>> {
        let conn = self.lock()?;
        let row = conn
            .query_row(
                "SELECT verdict_json, fetched_at, published_at FROM verdicts \
                 WHERE name = ?1 AND version = ?2 AND signal_set_hash = ?3",
                params![pkg.name, resolved_version, signal_set_hash],
                |row| {
                    let verdict_json: String = row.get(0)?;
                    let fetched_at: String = row.get(1)?;
                    let published_at: Option<String> = row.get(2)?;
                    Ok((verdict_json, fetched_at, published_at))
                },
            )
            .optional()?;
        drop(conn);

        let Some((verdict_json, fetched_at_str, published_at_opt)) = row else {
            return Ok(None);
        };
        let fetched_at = DateTime::parse_from_rfc3339(&fetched_at_str)
            .context("parsing cached fetched_at")?
            .with_timezone(&Utc);
        let published_at = match published_at_opt {
            Some(s) => Some(
                DateTime::parse_from_rfc3339(&s)
                    .context("parsing cached published_at")?
                    .with_timezone(&Utc),
            ),
            None => None,
        };

        // TTL: short if the *package version* itself is young (could still be
        // in the post-publish ownership-takeover risk window), long if it's
        // been stable for a while.
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
             (name, version, signal_set_hash, verdict_json, fetched_at, published_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                verdict.package.name,
                verdict.resolved_version,
                verdict.signal_set_hash,
                json,
                verdict.fetched_at.to_rfc3339(),
                verdict.published_at.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Drop every entry for a given package; call when a new registry
    /// version appears so the risk verdict is recomputed.
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

fn init_schema(conn: &Connection) -> Result<()> {
    let current: i32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap_or(0);
    if current != SCHEMA_VERSION {
        // Old or unknown schema; discard. Verdicts are regenerable.
        conn.execute_batch("DROP TABLE IF EXISTS verdicts;")
            .context("dropping stale schema")?;
    }
    conn.execute_batch(SCHEMA_DDL)
        .context("initializing cache schema")?;
    conn.execute_batch(&format!("PRAGMA user_version = {};", SCHEMA_VERSION))
        .context("recording schema version")?;
    Ok(())
}

const SCHEMA_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS verdicts (
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    signal_set_hash TEXT NOT NULL,
    verdict_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    published_at TEXT,
    PRIMARY KEY (name, version, signal_set_hash)
);
CREATE INDEX IF NOT EXISTS verdicts_name ON verdicts(name);
CREATE INDEX IF NOT EXISTS verdicts_fetched_at ON verdicts(fetched_at);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use npmguard_risk::{RiskLevel, Signal, SignalKind};

    fn sample_verdict(
        name: &str,
        version: &str,
        hash: &str,
        published_at: Option<DateTime<Utc>>,
    ) -> RiskVerdict {
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
            published_at,
            signal_set_hash: hash.to_string(),
        }
    }

    #[test]
    fn round_trips_a_verdict() {
        let cache = VerdictCache::in_memory().unwrap();
        let v = sample_verdict("lodash", "4.17.21", "h1", None);
        cache.put(&v).unwrap();
        let pkg = PackageRef::new("lodash", Some("4.17.21".into()));
        let got = cache.get(&pkg, "4.17.21", "h1").unwrap().unwrap();
        assert_eq!(got.resolved_version, "4.17.21");
        assert_eq!(got.signals.len(), 1);
    }

    #[test]
    fn different_signal_hash_misses() {
        let cache = VerdictCache::in_memory().unwrap();
        let v = sample_verdict("lodash", "4.17.21", "h1", None);
        cache.put(&v).unwrap();
        let pkg = PackageRef::new("lodash", Some("4.17.21".into()));
        let got = cache.get(&pkg, "4.17.21", "h2").unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn invalidate_drops_all_versions() {
        let cache = VerdictCache::in_memory().unwrap();
        cache
            .put(&sample_verdict("lodash", "4.17.20", "h1", None))
            .unwrap();
        cache
            .put(&sample_verdict("lodash", "4.17.21", "h1", None))
            .unwrap();
        cache
            .put(&sample_verdict("react", "18.0.0", "h1", None))
            .unwrap();
        let n = cache.invalidate("lodash").unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn fresh_package_uses_short_ttl_and_expires_quickly() {
        let cache = VerdictCache::in_memory().unwrap().with_policy(CachePolicy {
            fresh_ttl: Duration::seconds(0),
            stable_ttl: Duration::days(7),
            stable_age: Duration::days(30),
        });
        // Published 1 day ago → fresh.
        let mut v = sample_verdict(
            "fresh-pkg",
            "0.0.1",
            "h1",
            Some(Utc::now() - Duration::days(1)),
        );
        // Pretend the verdict was fetched 1 hour ago, past fresh_ttl of 0s.
        v.fetched_at = Utc::now() - Duration::hours(1);
        cache.put(&v).unwrap();
        let pkg = PackageRef::new("fresh-pkg", Some("0.0.1".into()));
        assert!(cache.get(&pkg, "0.0.1", "h1").unwrap().is_none());
    }

    #[test]
    fn stable_package_uses_long_ttl_and_survives() {
        let cache = VerdictCache::in_memory().unwrap().with_policy(CachePolicy {
            fresh_ttl: Duration::seconds(0),
            stable_ttl: Duration::days(7),
            stable_age: Duration::days(30),
        });
        // Published 2 years ago → stable.
        let mut v = sample_verdict(
            "stable-pkg",
            "1.0.0",
            "h1",
            Some(Utc::now() - Duration::days(730)),
        );
        v.fetched_at = Utc::now() - Duration::hours(2);
        cache.put(&v).unwrap();
        let pkg = PackageRef::new("stable-pkg", Some("1.0.0".into()));
        assert!(cache.get(&pkg, "1.0.0", "h1").unwrap().is_some());
    }
}
