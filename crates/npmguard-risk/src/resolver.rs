//! Transitive dependency closure resolution.
//!
//! Given a root package version, walk its full runtime dependency graph from the
//! npm registry and produce the set of resolved `name@version` nodes (direct and
//! transitive, excluding the root itself). Most supply-chain attacks hide in a
//! transitive dependency, so scanning only the named package misses them; the
//! closure is what actually lands in `node_modules` on a fresh install.
//!
//! Resolution mirrors a fresh `npm install`: each declared range resolves to the
//! highest published version that satisfies it. `optionalDependencies`,
//! non-registry specs (git / `file:` / `workspace:` / `npm:` aliases), and
//! unparseable ranges are skipped rather than guessed at. The walk is bounded by
//! depth and node count, deduped by `name@version`, and cycle-safe.
//!
//! The graph walk is split from the network: [`bfs_closure`] is a pure function
//! over an injected "fetch deps" closure, so the dedup / bounds / cycle logic is
//! unit-testable without a runtime or live registry.

use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::Result;
use futures::stream::{self, StreamExt};
use nodejs_semver::{Range, Version};
use serde::{Deserialize, Serialize};

use crate::signals::registry::{NpmRegistryClient, Packument};

/// How wide the registry fan-out may run at once. The whole closure shares the
/// engine's single connection pool; 16 in flight keeps the registry happy
/// without serialising the walk.
const FETCH_CONCURRENCY: usize = 16;

/// A resolved node in the dependency closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedNode {
    pub name: String,
    pub version: String,
    /// Chain of package names from the root to this node, inclusive of the root
    /// name at index 0 and this node's name at the end.
    pub path: Vec<String>,
}

/// Bounds for a closure walk. Defaults: depth 6, 600 nodes. Deep enough to reach
/// the transitive deps where worms hide, capped so an adversarial or merely huge
/// tree cannot fan out without limit.
#[derive(Debug, Clone, Copy)]
pub struct ResolveOpts {
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl Default for ResolveOpts {
    fn default() -> Self {
        Self {
            max_depth: 6,
            max_nodes: 600,
        }
    }
}

/// One dependency declaration to resolve: the dependent's name plus the
/// `name -> range` it asked for. Used as the unit of the BFS frontier.
#[derive(Debug, Clone)]
struct DepEdge {
    name: String,
    range: String,
}

/// Resolve a single dependency range against a fetched packument, npm-style: the
/// highest published, non-prerelease version that satisfies the range. Returns
/// the concrete published version string (exactly as it appears in the
/// packument), or `None` when the spec cannot be resolved from the registry.
///
/// Handling of non-semver specs, matching a fresh `npm install`:
///   * `*`, empty, or a dist-tag like `latest` / `next` resolves via `dist-tags`.
///   * git URLs, `file:`, `link:`, `workspace:`, and `npm:` aliases cannot be
///     resolved from the registry and are skipped (`None`).
///   * an otherwise unparseable range is skipped (`None`), never a panic.
fn resolve_range(packument: &Packument, range: &str) -> Option<String> {
    let trimmed = range.trim();

    // Non-registry specs we cannot resolve from the packument. `npm:` is an
    // alias spec (`npm:other-pkg@^1`); resolving it correctly would mean
    // following the alias target, out of scope for the closure walk, so skip.
    const UNRESOLVABLE_PREFIXES: &[&str] = &[
        "git+",
        "git:",
        "github:",
        "file:",
        "link:",
        "workspace:",
        "npm:",
        "http:",
        "https:",
    ];
    if UNRESOLVABLE_PREFIXES.iter().any(|p| trimmed.starts_with(p)) || trimmed.contains("://") {
        return None;
    }

    // `*` / empty / latest-style: take the dist-tag. A bare tag name (no semver
    // operators, not parseable as a range) is looked up in dist-tags.
    if trimmed.is_empty() || trimmed == "*" || trimmed == "latest" {
        return packument.dist_tags.get("latest").cloned();
    }
    if let Some(tagged) = packument.dist_tags.get(trimmed) {
        return Some(tagged.clone());
    }

    let parsed_range = Range::parse(trimmed).ok()?;

    // Parse every published version string, keeping the map back to its exact
    // registry string so the reported version is verbatim, not a re-serialised
    // form.
    let mut by_version: HashMap<Version, &String> = HashMap::new();
    let mut versions: Vec<Version> = Vec::with_capacity(packument.versions.len());
    for ver_str in packument.versions.keys() {
        if let Ok(v) = Version::parse(ver_str) {
            by_version.entry(v.clone()).or_insert(ver_str);
            versions.push(v);
        }
    }

    // `max_satisfying` mirrors npm: highest satisfying version, prereleases
    // excluded unless the range itself targets one.
    let best = parsed_range.max_satisfying(&versions)?;
    by_version.get(best).map(|s| (*s).to_string())
}

/// Pure BFS over the dependency graph. `fetch` maps a package name to its parsed
/// packument (or `None` when the fetch failed and the node must be skipped). The
/// root is resolved up front by the caller and seeded as depth 0; only its
/// transitive set (depth >= 1) is returned.
///
/// Invariants enforced here, independent of the network:
///   * dedup by `name@version` so a diamond dependency is visited once and a
///     cycle terminates,
///   * `max_depth` caps how deep edges are followed (root = 0, direct deps = 1),
///   * `max_nodes` caps how many resolved nodes are returned; once reached, no
///     further edges are enqueued.
fn bfs_closure<F>(
    root_name: &str,
    root_version: &str,
    root_deps: &[DepEdge],
    opts: &ResolveOpts,
    mut fetch: F,
) -> Vec<ResolvedNode>
where
    F: FnMut(&str) -> Option<Packument>,
{
    let mut out: Vec<ResolvedNode> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(format!("{}@{}", root_name, root_version));

    // Frontier carries the dependent's resolved path plus the edge to resolve.
    let mut frontier: VecDeque<(Vec<String>, DepEdge, usize)> = VecDeque::new();
    let root_path = vec![root_name.to_string()];
    for edge in root_deps {
        frontier.push_back((root_path.clone(), edge.clone(), 1));
    }

    while let Some((parent_path, edge, depth)) = frontier.pop_front() {
        if out.len() >= opts.max_nodes {
            break;
        }
        // The edge's own packument is needed to resolve its range; for a fresh
        // install the dependent declared `edge.range` for `edge.name`.
        let Some(packument) = fetch(&edge.name) else {
            continue;
        };
        let Some(version) = resolve_range(&packument, &edge.range) else {
            continue;
        };

        let key = format!("{}@{}", edge.name, version);
        if !seen.insert(key) {
            continue;
        }

        let mut path = parent_path.clone();
        path.push(edge.name.clone());
        let node = ResolvedNode {
            name: edge.name.clone(),
            version: version.clone(),
            path: path.clone(),
        };
        out.push(node);
        if out.len() >= opts.max_nodes {
            break;
        }

        // Enqueue this node's children only while under the depth cap.
        if depth < opts.max_depth {
            if let Some(vd) = packument.versions.get(&version) {
                for (dep_name, dep_range) in &vd.dependencies {
                    frontier.push_back((
                        path.clone(),
                        DepEdge {
                            name: dep_name.clone(),
                            range: dep_range.clone(),
                        },
                        depth + 1,
                    ));
                }
            }
        }
    }

    out
}

/// Resolve the full transitive runtime dependency closure of `root_name@root_version`.
///
/// Returns the direct and transitive dependency nodes, excluding the root (the
/// caller already evaluates the root separately). Each node carries the chain of
/// package names from the root to it. Registry fetches run with bounded
/// concurrency; a fetch failure for one package is logged and skipped, never
/// aborting the whole closure.
pub async fn resolve_closure(
    client: &NpmRegistryClient,
    root_name: &str,
    root_version: &str,
    opts: &ResolveOpts,
) -> Result<Vec<ResolvedNode>> {
    // The async layer is a thin cache around the network: it prefetches every
    // packument reachable, level by level, then runs the pure BFS over the
    // populated cache. This keeps all dedup / bounds / cycle logic in one
    // testable place while still fanning out fetches concurrently.
    let mut cache: HashMap<String, Option<Packument>> = HashMap::new();

    // Seed: the root packument, so we can read its declared dependencies.
    let root_pack = match client.fetch_packument(root_name).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("closure: root packument fetch failed for {root_name}: {e}");
            return Ok(Vec::new());
        }
    };
    let root_deps: Vec<DepEdge> = root_pack
        .versions
        .get(root_version)
        .map(|vd| {
            vd.dependencies
                .iter()
                .map(|(name, range)| DepEdge {
                    name: name.clone(),
                    range: range.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    cache.insert(root_name.to_string(), Some(root_pack));

    // Breadth-first prefetch. At each level, fetch every not-yet-cached package
    // name referenced by the previous level's resolved versions. We over-fetch
    // slightly (a name skipped by bounds may still get fetched) but never more
    // than the set of distinct names, and concurrency is capped.
    let mut frontier: HashSet<String> = root_deps.iter().map(|e| e.name.clone()).collect();
    for _ in 0..opts.max_depth {
        let to_fetch: Vec<String> = frontier
            .iter()
            .filter(|n| !cache.contains_key(*n))
            .cloned()
            .collect();
        if to_fetch.is_empty() {
            break;
        }
        if cache.len() >= opts.max_nodes.saturating_add(1) {
            // Already cached enough packuments to cover the node budget.
            break;
        }

        let fetched: Vec<(String, Option<Packument>)> = stream::iter(to_fetch)
            .map(|name| async move {
                match client.fetch_packument(&name).await {
                    Ok(p) => (name, Some(p)),
                    Err(e) => {
                        tracing::warn!("closure: packument fetch failed for {name}: {e}");
                        (name, None)
                    }
                }
            })
            .buffer_unordered(FETCH_CONCURRENCY)
            .collect()
            .await;

        let mut next: HashSet<String> = HashSet::new();
        for (name, pack) in fetched {
            if let Some(p) = &pack {
                // Queue the names this packument's versions can reach. We do not
                // know yet which version resolves, so queue across all versions'
                // dependency names; the pure BFS picks the real one. Bounded by
                // the distinct-name set, which is finite.
                for vd in p.versions.values() {
                    for dep_name in vd.dependencies.keys() {
                        if !cache.contains_key(dep_name) {
                            next.insert(dep_name.clone());
                        }
                    }
                }
            }
            cache.insert(name, pack);
        }
        frontier = next;
    }

    let closure = bfs_closure(root_name, root_version, &root_deps, opts, |name| {
        cache.get(name).cloned().flatten()
    });
    Ok(closure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::registry::VersionDeps;
    use std::collections::BTreeMap;

    /// A `(name, dep_range)` pair, the test shorthand for one declared edge.
    type DepSpec<'a> = (&'a str, &'a str);
    /// A `(name, version, deps)` triple describing one package in a fake registry.
    type PackageSpec<'a> = (&'a str, &'a str, &'a [DepSpec<'a>]);

    fn pack(versions: &[(&str, &[(&str, &str)])], dist_latest: &str) -> Packument {
        let mut vmap: BTreeMap<String, VersionDeps> = BTreeMap::new();
        for (ver, deps) in versions {
            let dependencies = deps
                .iter()
                .map(|(n, r)| (n.to_string(), r.to_string()))
                .collect();
            vmap.insert(
                ver.to_string(),
                VersionDeps {
                    dependencies,
                    optional_dependencies: HashMap::new(),
                },
            );
        }
        let mut dist_tags = HashMap::new();
        if !dist_latest.is_empty() {
            dist_tags.insert("latest".to_string(), dist_latest.to_string());
        }
        Packument {
            versions: vmap,
            dist_tags,
        }
    }

    fn versions_only(vers: &[&str]) -> Packument {
        let pairs: Vec<(&str, &[(&str, &str)])> = vers.iter().map(|v| (*v, &[][..])).collect();
        pack(&pairs, vers.last().copied().unwrap_or(""))
    }

    // ---- range resolution -------------------------------------------------

    #[test]
    fn caret_picks_highest_in_major() {
        let p = versions_only(&["1.0.0", "1.2.0", "1.9.3", "2.0.0"]);
        assert_eq!(resolve_range(&p, "^1.2.0").as_deref(), Some("1.9.3"));
    }

    #[test]
    fn tilde_picks_highest_in_minor() {
        let p = versions_only(&["1.2.0", "1.2.7", "1.3.0"]);
        assert_eq!(resolve_range(&p, "~1.2.0").as_deref(), Some("1.2.7"));
    }

    #[test]
    fn exact_pins_exact() {
        let p = versions_only(&["1.0.0", "1.2.0", "1.2.1"]);
        assert_eq!(resolve_range(&p, "1.2.0").as_deref(), Some("1.2.0"));
    }

    #[test]
    fn star_resolves_to_dist_tag_latest() {
        let p = pack(
            &[("1.0.0", &[]), ("2.0.0", &[]), ("3.0.0-rc.1", &[])],
            "2.0.0",
        );
        assert_eq!(resolve_range(&p, "*").as_deref(), Some("2.0.0"));
        assert_eq!(resolve_range(&p, "").as_deref(), Some("2.0.0"));
        assert_eq!(resolve_range(&p, "latest").as_deref(), Some("2.0.0"));
    }

    #[test]
    fn named_dist_tag_resolves() {
        let mut p = versions_only(&["1.0.0", "2.0.0"]);
        p.dist_tags.insert("next".to_string(), "2.0.0".to_string());
        assert_eq!(resolve_range(&p, "next").as_deref(), Some("2.0.0"));
    }

    #[test]
    fn prerelease_excluded_unless_targeted() {
        // A caret over stable releases must not select a prerelease, matching
        // npm. The prerelease is only chosen when the range targets it.
        let p = versions_only(&["1.0.0", "1.1.0", "1.2.0-beta.1"]);
        assert_eq!(resolve_range(&p, "^1.0.0").as_deref(), Some("1.1.0"));
    }

    #[test]
    fn unparseable_spec_is_skipped() {
        let p = versions_only(&["1.0.0", "2.0.0"]);
        assert_eq!(resolve_range(&p, "git+https://example.com/x.git"), None);
        assert_eq!(resolve_range(&p, "file:../local"), None);
        assert_eq!(resolve_range(&p, "workspace:*"), None);
        assert_eq!(resolve_range(&p, "npm:other@^1.0.0"), None);
        assert_eq!(resolve_range(&p, "github:user/repo"), None);
        assert_eq!(resolve_range(&p, "https://example.com/x.tgz"), None);
        // A genuinely garbage range parses to nothing and is skipped, not a panic.
        assert_eq!(resolve_range(&p, "not a version at all"), None);
    }

    #[test]
    fn no_satisfying_version_is_none() {
        let p = versions_only(&["1.0.0", "1.2.0"]);
        assert_eq!(resolve_range(&p, "^9.0.0"), None);
    }

    // ---- BFS dedup / bounds ----------------------------------------------

    /// Build a fake registry: name to a single-version packument with the given
    /// dependency edges (all ranges `*`, resolving via dist-tags).
    fn fake_registry(spec: &[PackageSpec]) -> HashMap<String, Packument> {
        let mut map = HashMap::new();
        for (name, ver, deps) in spec {
            map.insert(name.to_string(), pack(&[(ver, deps)], ver));
        }
        map
    }

    fn edges(deps: &[(&str, &str)]) -> Vec<DepEdge> {
        deps.iter()
            .map(|(n, r)| DepEdge {
                name: n.to_string(),
                range: r.to_string(),
            })
            .collect()
    }

    #[test]
    fn bfs_resolves_transitive_chain() {
        // root -> a -> b -> c
        let reg = fake_registry(&[
            ("a", "1.0.0", &[("b", "1.0.0")]),
            ("b", "1.0.0", &[("c", "1.0.0")]),
            ("c", "1.0.0", &[]),
        ]);
        let opts = ResolveOpts::default();
        let out = bfs_closure("root", "0.0.0", &edges(&[("a", "1.0.0")]), &opts, |n| {
            reg.get(n).cloned()
        });
        let names: Vec<&str> = out.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
        // Path is recorded root..node inclusive.
        let c = out.iter().find(|n| n.name == "c").unwrap();
        assert_eq!(c.path, vec!["root", "a", "b", "c"]);
    }

    #[test]
    fn bfs_dedups_diamond_and_cycle() {
        // root -> a, root -> b; a -> shared, b -> shared; shared -> a (cycle).
        let reg = fake_registry(&[
            ("a", "1.0.0", &[("shared", "1.0.0")]),
            ("b", "1.0.0", &[("shared", "1.0.0")]),
            ("shared", "1.0.0", &[("a", "1.0.0")]),
        ]);
        let opts = ResolveOpts::default();
        let out = bfs_closure(
            "root",
            "0.0.0",
            &edges(&[("a", "1.0.0"), ("b", "1.0.0")]),
            &opts,
            |n| reg.get(n).cloned(),
        );
        // shared appears once despite two parents; the a->shared->a cycle
        // terminates (a already seen). a, b, shared = 3 distinct nodes.
        let mut names: Vec<&str> = out.iter().map(|n| n.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["a", "b", "shared"]);
    }

    #[test]
    fn bfs_respects_max_depth() {
        // root -> a -> b -> c, but max_depth = 2: a (depth 1), b (depth 2)
        // resolved; c (depth 3) never enqueued.
        let reg = fake_registry(&[
            ("a", "1.0.0", &[("b", "1.0.0")]),
            ("b", "1.0.0", &[("c", "1.0.0")]),
            ("c", "1.0.0", &[]),
        ]);
        let opts = ResolveOpts {
            max_depth: 2,
            max_nodes: 600,
        };
        let out = bfs_closure("root", "0.0.0", &edges(&[("a", "1.0.0")]), &opts, |n| {
            reg.get(n).cloned()
        });
        let mut names: Vec<&str> = out.iter().map(|n| n.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn bfs_respects_max_nodes() {
        // A fan of five direct deps, capped at three nodes.
        let reg = fake_registry(&[
            ("a", "1.0.0", &[]),
            ("b", "1.0.0", &[]),
            ("c", "1.0.0", &[]),
            ("d", "1.0.0", &[]),
            ("e", "1.0.0", &[]),
        ]);
        let opts = ResolveOpts {
            max_depth: 6,
            max_nodes: 3,
        };
        let out = bfs_closure(
            "root",
            "0.0.0",
            &edges(&[
                ("a", "1.0.0"),
                ("b", "1.0.0"),
                ("c", "1.0.0"),
                ("d", "1.0.0"),
                ("e", "1.0.0"),
            ]),
            &opts,
            |n| reg.get(n).cloned(),
        );
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn bfs_skips_failed_fetch() {
        // root -> a (fetch fails) and root -> b (ok). a is skipped, b resolved.
        let reg = fake_registry(&[("b", "1.0.0", &[])]);
        let opts = ResolveOpts::default();
        let out = bfs_closure(
            "root",
            "0.0.0",
            &edges(&[("a", "1.0.0"), ("b", "1.0.0")]),
            &opts,
            |n| reg.get(n).cloned(),
        );
        let names: Vec<&str> = out.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["b"]);
    }

    #[test]
    fn bfs_skips_unresolvable_edge_but_keeps_walking() {
        // root -> a via git url (skipped), root -> b (ok).
        let reg = fake_registry(&[("b", "1.0.0", &[])]);
        let opts = ResolveOpts::default();
        let out = bfs_closure(
            "root",
            "0.0.0",
            &edges(&[("a", "git+https://x/y.git"), ("b", "*")]),
            &opts,
            |n| reg.get(n).cloned(),
        );
        let names: Vec<&str> = out.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["b"]);
    }
}
