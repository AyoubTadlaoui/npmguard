# npmguard

[![CI](https://img.shields.io/github/actions/workflow/status/AyoubTadlaoui/npmguard/ci.yml?branch=main&style=flat-square&label=CI&color=99ffe4&labelColor=000000)](https://github.com/AyoubTadlaoui/npmguard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/AyoubTadlaoui/npmguard/release.yml?style=flat-square&label=release&color=3b82f6&labelColor=000000)](https://github.com/AyoubTadlaoui/npmguard/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/AyoubTadlaoui/npmguard?style=flat-square&color=3b82f6&labelColor=000000)](https://github.com/AyoubTadlaoui/npmguard/releases/latest)
[![Stars](https://img.shields.io/github/stars/AyoubTadlaoui/npmguard?style=flat-square&color=ff8080&labelColor=000000)](https://github.com/AyoubTadlaoui/npmguard/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-3b82f6.svg?style=flat-square&labelColor=000000)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/AyoubTadlaoui/npmguard?style=flat-square&color=a0a0a0&labelColor=000000)](https://github.com/AyoubTadlaoui/npmguard/commits/main)

> **A native safety gate for `npm install`, built for humans and AI coding agents.** It checks package risk before install and blocks known-malicious or typosquatted packages before lifecycle scripts can run.

Distributed **outside** the npm ecosystem so it can't be compromised by the thing it's protecting you from. Written in Rust. Single static binary.

![npmguard blocking a typosquat](docs/demo.gif)

<sub>Live verdict against the npm registry — `lodahs` is a real typosquat of `lodash` flagged in OSV's malware namespace. Theme: [atlas-ragnarok](https://github.com/AyoubTadlaoui/atlas-ragnarok). Sibling project: [GoLogX](https://github.com/AyoubTadlaoui/GoLogX) (pretty `log/slog` for Go) — same distribution playbook (Homebrew, Scoop, AUR, install.sh) lands here in v0.2.</sub>

```
$ npmguard check lodahs

npmguard  lodahs@0.0.1-security  →  score 115 / 200  (block, thresholds warn=30 block=70)
   10 pts  SoleMaintainer       single maintainer: adam_baldwin
   25 pts  Typosquat            name 'lodahs' is 1 edit away from popular package 'lodash'
   80 pts  KnownCve             1 CONFIRMED MALICIOUS by OSV for this version: MAL-2025-25502
```

---

## What this is

`npmguard` is a thin wrapper that runs **before** `npm install` does. It:

1. Pulls registry + advisory + repo signals for the package in parallel (sub-second on cache hit).
2. Computes a composite risk score and a verdict: `ok` / `warn` / `block`.
3. Refuses to install on `block`, prompts on `warn`, passes through on `ok`.
4. **Exposes the same check as an MCP tool** so Claude Code / Cursor / Windsurf must go through the gate when *they* install packages on your behalf.

The MCP gate is the load-bearing feature. A CLI alone protects you only when you remember to type `npmguard install` instead of `npm install`. An MCP server protects you whenever your AI assistant tries to install anything — and that is increasingly when `npm install` actually runs in 2026.

## Why this exists

Across 2025–2026 the npm ecosystem absorbed a series of worm-style supply chain attacks that ran inside `preinstall` / `install` / `postinstall` scripts the moment a downstream user typed `npm install`:

- **Shai-Hulud** (Sept 2025) — `@ctrl/tinycolor`, `ngx-bootstrap`, `ng2-file-upload`
- **SHA1-Hulud** (Nov 2025) — second wave via `preinstall`
- **Axios compromise** (Mar 2026) — RAT deployed within ~2 seconds of `npm install`
- **Mini Shai-Hulud** (May 2026) — 170+ packages across SAP, TanStack, Mistral, Guardrails

The pattern is consistent. Defender wins or loses **before the install completes**, not after.

Three existing classes of defense leave a gap:

| Tool | Distribution | Coverage gap |
|---|---|---|
| `npq`, `safe-npm` / `socket npm`, `npm-risk` | npm package | Ships on the thing it's protecting you from. If the wrapper itself gets compromised, you've made the problem worse. |
| `pnpm v10+`, Bun | npm registry / standalone | Disables lifecycle scripts by default — but only for users who've moved off `npm`. The npm majority is unprotected. |
| `lavamoat/allow-scripts`, `npm audit`, Snyk, Dependabot | npm package / SaaS | Allow-list management, CVE scanning. Not pre-install heuristics, not a runtime gate for AI agents. |

`npmguard` fills the specific gap of: **(1) pre-install risk scoring, (2) AI-agent gate via MCP, (3) shipped as a binary outside npm.**

## What `npmguard` does NOT claim

Honesty is the contract.

- It does **not** catch attacks that pass all heuristic checks. A clean-history maintainer-account-takeover that ships a package matching every "looks normal" signal will still install.
- It does **not** protect against zero-day vulnerabilities in legitimate packages. That's `npm audit` / Snyk territory.
- It does **not** stop attacks that run **outside** lifecycle scripts. If a package is malicious only when imported at runtime, this tool isn't there.
- It does **not** replace `npm audit`, Snyk, Socket, Dependabot, or code review. It's an additional layer.
- It is **not** a guarantee. Any tool claiming "secure" is lying. We say "reduces blast radius" and stop there.

## Status

**v0.1 — risk-only.** The CLI `check` and `install` commands compute and display verdicts. `install` does not yet shell out to `npm` — it tells you what would happen and exits. The sandbox layer ships in v0.2.

| Feature | v0.1 | v0.2 | v0.3 |
|---|---|---|---|
| Risk engine (8 signals) | ✅ | ✅ | ✅ |
| SQLite verdict cache | ✅ | ✅ | ✅ |
| CLI (`check`, `install` print verdict) | ✅ | ✅ | ✅ |
| MCP server (`install_package` tool) | ✅ | ✅ | ✅ |
| Real `npm install` execution | ⬜ | ✅ | ✅ |
| Cross-platform sandbox (landlock / sandbox-exec / Job Object) | ⬜ | ✅ | ✅ |
| Homebrew / Scoop / install.sh distribution | ⬜ | ✅ | ✅ |
| Corpus benchmark in README (p50 / p99) | ⬜ | ✅ | ✅ |

## Installation

Pre-built binaries for macOS (Intel + Apple Silicon), Linux (x86_64 + aarch64), and Windows (x86_64) are published on every tagged release: [Releases page](https://github.com/AyoubTadlaoui/npmguard/releases/latest).

```sh
# macOS / Linux: download, verify, install
curl -L -o npmguard.tar.gz \
  https://github.com/AyoubTadlaoui/npmguard/releases/latest/download/npmguard-v0.1.0-aarch64-apple-darwin.tar.gz
tar -xzf npmguard.tar.gz
sudo mv npmguard-v0.1.0-aarch64-apple-darwin/npmguard /usr/local/bin/
sudo mv npmguard-v0.1.0-aarch64-apple-darwin/npmguard-mcp /usr/local/bin/

npmguard --help
```

`SHA256SUMS.txt` is published alongside every release — verify before installing.

Homebrew tap + `curl ... | sh` installer + Scoop bucket land with v0.2.

### Build from source

```sh
git clone https://github.com/AyoubTadlaoui/npmguard
cd npmguard
cargo build --release
./target/release/npmguard --help
```

## Usage

```sh
# Check the latest version (no install, just verdict)
npmguard check axios

# Check a pinned version, JSON output
npmguard check --json @ctrl/tinycolor@4.1.1

# Install path (v0.1: prints verdict; v0.2: runs sandboxed `npm install`)
npmguard install lodash@4.17.21
```

### MCP — for Claude Code / Cursor / Windsurf

Add this to your MCP config (`~/.claude.json` for Claude Code):

```jsonc
{
  "mcpServers": {
    "npmguard": {
      "command": "/full/path/to/target/release/npmguard-mcp"
    }
  }
}
```

The server exposes one tool, `install_package(name, version?)`, which returns a structured verdict the model can act on:

```json
{
  "package": "lodahs",
  "resolved_version": "0.0.1-security",
  "level": "block",
  "score": 115,
  "signals": [
    { "kind": "SoleMaintainer", "points": 10, "detail": "single maintainer: adam_baldwin" },
    { "kind": "Typosquat", "points": 25, "detail": "name 'lodahs' is 1 edit away from popular package 'lodash'" },
    { "kind": "KnownCve", "points": 80, "detail": "1 CONFIRMED MALICIOUS by OSV for this version: MAL-2025-25502" }
  ],
  "recommendation": "Block — do NOT install this package without explicit user override. Present the signals and ask the user to confirm."
}
```

## Risk signals

| Signal | Points | Triggered when |
|---|---|---|
| `LifecycleScripts` | 30 | Package defines `preinstall`, `install`, or `postinstall` |
| `PackageAge` | 25 / 10 | Version published < 7 / 30 days ago |
| `MaintainerChurn` | 20 | Version published after a > 180-day publish gap (dormant package resurrection) |
| `SoleMaintainer` | 10 | Package has exactly one maintainer |
| `RepoHealth` | 15 / 10 | Linked GitHub repo is archived / has zero stars and no commits in 6 months |
| `Typosquat` | 25 | Name is one Levenshtein edit from a popular package |
| `KnownCve` | 80 / 50 / 20 / 10 / 5 | OSV.dev advisory present. **80** if it's a `MAL-*` (confirmed malicious package). Otherwise CVSS critical / high / medium / low. |
| `Deprecated` | 10 | npm registry marks this version deprecated |

Composite score is the sum (capped at 200). Default thresholds: `warn ≥ 30`, `block ≥ 70`. Tunable per project via config (planned for v0.2).

**Weights are starting values, not science.** They will be tuned against the corpus in [`corpus/`](corpus/) and the values published as part of each release. PRs welcome.

## Distribution

`npmguard` is intentionally not on npm. v0.2 will ship via:

- GitHub Releases (prebuilt binaries × 6 targets)
- Homebrew tap: `brew install AyoubTadlaoui/tap/npmguard`
- `curl -fsSL ... | sh` install script
- GHCR Docker image for CI

## Project layout

```
crates/
├── npmguard-risk/    # signal fetchers + composite scoring
├── npmguard-cache/   # SQLite verdict cache
├── npmguard-cli/     # `npmguard` binary (clap)
└── npmguard-mcp/     # `npmguard-mcp` binary (rmcp, stdio transport)
corpus/
├── known-bad.json    # documented compromised packages, with expected signals
└── known-good.json   # high-traffic packages that should not block
```

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

The threat model and prior-art landscape draw on:

- Microsoft Security Blog — Shai-Hulud 2.0
- Unit 42 — Shai-Hulud worm analysis
- Snyk — npm Security Best Practices (post Shai-Hulud)
- The Hacker News — Mini Shai-Hulud coverage
- StepSecurity — Securing Vibe Coding and AI Coding Agents
- pnpm — Mitigating supply chain attacks
- `lirantal/npq`, `Freedruk/npm-risk` — prior-art pre-install checkers
- `modelcontextprotocol/rust-sdk` (`rmcp`) — MCP transport
- `landlock` and `rappct` crates — sandbox primitives (for v0.2)
