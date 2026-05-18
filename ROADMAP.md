# Roadmap

> This document is a **direction**, not a guarantee. Every dated promise here
> is subject to "what actually works when we build it." If a phase changes
> shape, this file gets updated; the README's roadmap table is the
> machine-readable summary.

---

## North star (v1.0)

> **npmguard cannot prove packages are safe.** It *can* stop known-malicious
> packages, delay suspicious fresh releases, verify provenance, sandbox
> install scripts, and combine signals from multiple scanners under one
> policy gate.

If we can defend that sentence at v1.0, npmguard has earned its place.

---

## What v0.1 (shipped) actually does

- Pre-install risk score with 8 signals (lifecycle scripts, age, maintainer
  churn, sole maintainer, deprecated, typosquat, OSV.dev incl. MAL-*
  malware namespace, GitHub repo health).
- CLI verdict (`ok` / `warn` / `block`).
- MCP server so Claude Code / Cursor / Windsurf hit the same gate.
- SQLite verdict cache, ~5× speedup on repeat queries (v0.1.1).
- Releases on macOS x86_64+arm64, Linux x86_64+arm64, Windows x86_64,
  SHA256-verified, distributed *outside* the npm ecosystem.

**What v0.1 doesn't do, and the README says so:** doesn't yet wrap the
real `npm install` subprocess, doesn't sandbox lifecycle scripts,
doesn't verify provenance, doesn't gate AI agents at *runtime* (only at
install time).

---

## v0.2 — real install + sandbox + release-anomaly engine

**Why this is the most important release after v0.1.** v0.1 is a risk
*reporter*; v0.2 is the first release where npmguard actually *interposes*
between you and dangerous code.

### Install path (replace today's "print verdict and stop")

1. Resolve metadata (existing).
2. Download tarball to temp.
3. Verify tarball SHA against the registry's `integrity` field.
4. Inspect `package.json` from the tarball.
5. Run `npm install --ignore-scripts` for the resolved tree.
6. For each package with lifecycle scripts, decide per policy:
   - default: **prompt** the user (or auto-deny in non-TTY)
   - `--allow-scripts=foo,bar`: allow listed packages
   - `--no-scripts`: skip every lifecycle script (most secure default
     for AI-agent workflows)
7. Run allowed scripts **inside the sandbox layer** (see below).

`--ignore-scripts` is npm's own escape hatch — we don't need to reinvent
it. We just need to gate *which* scripts are allowed to run after.

### Sandbox layer (per OS)

| OS | Primitive | Crate / API |
|---|---|---|
| Linux ≥ 5.13 | landlock LSM | [`landlock`](https://crates.io/crates/landlock) |
| Linux (optional) | seccomp filter | direct `libseccomp` bindings |
| Linux (optional) | network namespace | `unshare -n` wrapper |
| macOS | sandbox-exec + `.sb` profile | shell out to system tool |
| Windows | AppContainer + Job Object | [`rappct`](https://crates.io/crates/rappct) |

Denied by default: `~/.ssh`, `~/.npmrc`, `~/.aws`, `~/.config/gh`, env
vars matching `*TOKEN*` / `*KEY*` / `*SECRET*`, outbound TCP except
`registry.npmjs.org`, exec of `curl` / `wget` / `nc` / `bash -c`.

`--no-sandbox` escape hatch for legitimate native-compile packages
(`bcrypt`, `node-gyp`-style). Off by default; printed in red when used.

### Release-anomaly engine (the single highest-value signal addition)

Most maintainer-takeover incidents share a pattern: the new version is
*almost identical* to the previous one but adds one new lifecycle
script or a dep that wasn't there before. v0.2 ships a per-version
diff:

- Fetch `package.json` for the resolved version AND the previous version.
- Flag added `preinstall` / `install` / `postinstall` scripts (+40 pts).
- Flag new top-level deps not present in the previous N versions (+25).
- Flag dep count delta > 50% (+15).
- Flag entropy spikes in install-script contents (base64/hex blobs).

This catches "looks normal" releases far better than the
metadata-only engine in v0.1.

### Distribution

- Homebrew tap: `brew install AyoubTadlaoui/tap/npmguard`
- Scoop bucket: `scoop install npmguard`
- AUR: `yay -S npmguard-bin`
- `curl -fsSL .../install.sh | sh` with SHA verification
- GHCR Docker for CI

Reuses the GoLogX distribution playbook.

---

## v0.3 — provenance + scanner adapters

### Provenance / signature verification

- Query the npm registry's `attestations` endpoint per resolved version.
- Verify the Sigstore-backed [npm provenance attestation](https://docs.npmjs.com/generating-provenance-statements):
  - publisher identity
  - source repo URL
  - build workflow path
- Flag if a package historically had provenance and the new version doesn't.
- Flag if provenance repo URL or workflow path changed between versions.
- Verify the older `package signature` manifest for packages that opted into it.

### Scanner adapters — "the policy gate that combines signals"

The "we don't replace Snyk/Socket/Dependabot" line in the README only
makes sense if we can *combine* with them. Three adapters land in v0.3:

```
npmguard check --with npm-audit       # shell out to npm audit --json
npmguard check --with osv-lockfile    # query OSV for the whole lockfile
npmguard check --with socket          # Socket free-tier API (optional)
```

Plus SBOM generation:

```
npmguard sbom --format cyclonedx > sbom.json
npmguard sbom --format spdx       > sbom.spdx.json
```

Critical/high CVEs from any adapter feed the composite score and the
block decision.

---

## v0.4 — policy + CI mode + waivers

Once we have multiple signal sources, projects need a way to express
policy.

```toml
# npmguard.toml at project root
[thresholds]
warn = 30
block = 70

[signals]
disable = ["repo_health"]      # repo signal noisy in our monorepo

[policy]
require_provenance = true
ignore_scripts_default = true
max_severity_unwaived = "high"

[allow]
# Per-package waivers with required justification.
"node-gyp"  = { reason = "native compile required", expires = "2026-12-31" }
"bcrypt"    = { reason = "native compile required" }
```

CI mode:

```
npmguard check --ci --policy npmguard.toml          # one verdict per package, exit on first block
npmguard check --ci --lockfile package-lock.json    # all transitive deps
```

Waiver workflow: blocked packages can be approved with a signed
commit message (`git config user.signingkey` + git's own
signature-verification path). No web service, no SaaS.

---

## v0.5 — organization presets + MCP marketplace

- Shareable policy presets (`extends = "github://AyoubTadlaoui/npmguard-presets/strict.toml"`).
- Reproducible org-wide gates via the policy file.
- Submit MCP server to the **Claude Code MCP catalog** + **Cursor MCP
  catalog** + **Smithery** auto-indexing.
- Drop everything we know is unstable behind feature flags pre-v1.0.

### Official `modelcontextprotocol/registry` submission — deferred

The MCP Registry currently supports `npm` / `PyPI` / `NuGet` / `OCI` /
`MCPB` packages, not raw native binaries from GitHub Releases. npmguard
intentionally avoids npm distribution (the whole point), so the `npm`
registry-type is off the table for branding reasons.

We'll revisit with **OCI** or **MCPB** packaging in v0.2:

- **OCI on GHCR** — push `ghcr.io/ayoubtadlaoui/npmguard-mcp` as part of
  the v0.2 distribution work alongside Homebrew/Scoop. Adds Docker as a
  user prerequisite for the registry path but not for the binary path,
  which stays primary.
- **MCPB bundle** — the official spec supports `.mcpb` artifacts hosted
  on GitHub Releases. Preserves the "GitHub Releases, not npm" story
  better than Docker, but requires understanding the MCPB packaging
  format (zip + manifest). Investigate in parallel with OCI.

Whichever path wins, the v0.5 marketplace work depends on it landing in
v0.2 first.

---

## v1.0 — stable schema + AI-assistant integration

- Freeze the public Rust API of `npmguard-risk` (semver from here).
- Freeze the MCP tool schema (`install_package` input/output) — additive
  changes only after this point.
- Freeze the JSON output format of `npmguard check --json`.
- Pursue placement in Claude Code / Cursor / Windsurf default MCP docs.
- Publish the corpus + scoring weights as a separate citable artifact.

---

## Considered and kept out of scope

### `npmguard run npm test` / runtime sandbox

Atlas's expanded proposal included a runtime sandbox subcommand
(`npmguard run` / `npmguard exec --net=deny`) so that *imported*
malicious code is also contained, not just install-time code.

**Why it's not on the roadmap:** that's a different product.

- Different user mental model — install gate vs runtime wrapper.
- Different performance profile — every `node` invocation goes through
  it; sandbox overhead becomes the hot path in CI.
- Different code path — the install sandbox runs once per package; the
  runtime sandbox runs continuously and has to be transparent to
  Node's own permission model.
- Different threat model — runtime malicious code is a much broader
  category and includes intentional behavior of legitimate packages
  (`fs` access by build tools, network calls by ORMs).

If runtime sandboxing is the right move, it ships as a separate
project (`npmsandbox` or similar) with its own threat model and
release cadence. Bundling it inflates npmguard's v1.0 claim sentence
beyond what we can defend.

### "Reproduce the install in a VM"

Briefly considered — boot a microVM (Firecracker), run the install
inside, diff filesystem. Way too heavy for the dev-loop use case;
belongs in a different category (CI hardening service, not a local
gate).

### "Block based on AI risk scoring"

LLM-based scoring of package source code. Conflict of interest with
the MCP-gate use case (we'd be asking the AI assistant we're trying to
protect to evaluate the risk). Not happening pre-v1.0.

---

## Cadence

Target: one release every 4–6 weeks until v1.0. No fixed dates because
the sandbox cross-platform parity work has unknown unknowns
(particularly on Windows). Each release earns or loses scope based on
what we learned in the previous one.

ChangeLog at [CHANGELOG.md](CHANGELOG.md). Discussion of any specific
phase scope happens in [GitHub Discussions](https://github.com/AyoubTadlaoui/npmguard/discussions)
(planned).
