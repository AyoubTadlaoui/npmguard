# Launch playbook

Phase-by-phase playbook for going public. Everything below is the operational
sequence to execute — copy-paste-ready titles, bodies, commands, and timing.

> **Honest framing rule.** Pitch this as *"a pre-install risk gate for npm
> packages, with an MCP tool for AI coding agents."* It is not "drop-in
> npm install protection" (that ships in v0.2 with the sandbox). Stick to
> what v0.1.3 actually does — pre-install risk scoring + a verdict gate
> that AI assistants can call before they run `npm install` on your behalf.

---

## Pre-flight inventory

What's already shipped:

| Asset | Location |
|---|---|
| Public repo | https://github.com/AyoubTadlaoui/npmguard |
| Latest release (v0.1.3) | https://github.com/AyoubTadlaoui/npmguard/releases/tag/v0.1.3 |
| Demo GIF (atlas-ragnarok) | `docs/demo.gif` (also `.webp`, `.mp4`) |
| Hero PNG | `docs/hero.png` |
| Repo topics (10 tags) | `supply-chain-security`, `npm`, `mcp`, etc. |
| Outstanding PRs | `rust-unofficial/awesome-rust#2503`, `punkpeye/awesome-mcp-servers#6579` |
| Smithery.ai | Auto-indexing from topic tags |

What's still to do (this playbook):

- 2 web-form submissions (today, 15 min) — Phases 1–2
- Pick launch slot — Phase 3
- Execute launch (~90 min posting + 4h engagement) — Phases 4–13
- 7-day follow-up — Phases 14–15
- v0.2 / day-30 long-term — Phase 16

---

# PHASE 0 — Sanity check (5 min, do today)

**Goal:** confirm everything still works before funneling traffic.

```bash
cd ~/npmguard

# 1. Repo is on main, no uncommitted changes
git status
git log --oneline -3

# 2. Release v0.1.3 has all 6 assets
gh release view v0.1.3 --json url,assets --jq '{url, count: (.assets | length), assets: [.assets[].name]}'

# 3. CI is green on main
gh run list --workflow=ci.yml --limit 1 --json status,conclusion,headSha

# 4. Awesome-list PRs still open
gh search prs --author=AyoubTadlaoui --state=open --repo=rust-unofficial/awesome-rust --repo=punkpeye/awesome-mcp-servers --json url,title,state

# 5. The live CLI still blocks the demo.
# No pipe — we want npmguard's actual exit code (2 on block), not tail's 0.
./target/release/npmguard check --no-cache lodahs
echo "exit: $?"
```

**Expected for step 5 (final lines):**
```
npmguard  lodahs@0.0.1-security  →  score 115 / 200  (block, thresholds warn=30 block=70)
   10 pts  SoleMaintainer       single maintainer: adam_baldwin
   25 pts  Typosquat            name 'lodahs' is 1 edit away from popular package 'lodash'
   80 pts  KnownCve             1 CONFIRMED MALICIOUS by OSV for this version: MAL-2025-25502
exit: 2
```

> Note: `npmguard check` prints the verdict block and exits 2. It does **not**
> print `blocked: refusing to install ...` — that's the `install` subcommand.
> If you want to verify both code paths, run `npmguard install --no-cache
> lodahs` too; expect an additional `blocked: refusing to install lodahs
> (score 115 ≥ block threshold 70)` line and the same exit `2`.
>
> If you do pipe (e.g. `| tail`), prefix with `set -o pipefail` or the pipe
> hides npmguard's exit code behind the last command's `0`.

**If any check fails:** STOP. Fix before continuing.

---

# PHASE 1 — Submit to mcp.so (5 min, browser)

**Goal:** get listed in the most-trafficked MCP catalog before launch traffic hits.

### 1.1 — Open the submission page
**https://mcp.so/submit** — sign in with AyoubTadlaoui GitHub if prompted.

### 1.2 — Fill the form

```
Name:           npmguard
Slug:           npmguard
Author/Owner:   Ayoub Tadlaoui
GitHub URL:     https://github.com/AyoubTadlaoui/npmguard
Homepage:       https://github.com/AyoubTadlaoui/npmguard
License:        MIT
Language:       Rust
Category:       Security
Transport:      stdio
Server command: npmguard-mcp
```

**Short description (140 char):**
```
Pre-install risk gate for npm packages. Stops AI coding agents from running malicious or typosquatted packages before lifecycle scripts run.
```

**Long description:**
```
A native pre-install risk gate for npm packages, with an MCP tool for AI coding agents. Pulls npm registry + OSV.dev (incl. MAL-* malware namespace) + GitHub repo signals in parallel, computes a composite risk score, and returns an ok/warn/block verdict before lifecycle scripts can execute.

Single static Rust binary, distributed via GitHub Releases (not via npm), so the gate itself cannot be compromised by the npm supply chain it's protecting against.

Exposes the same check as an MCP server so Claude Code / Cursor / Windsurf must go through the same gate when they install packages on the user's behalf. Catches the lodahs typosquat of lodash (in OSV's malware namespace) at score 115/200 against the live registry.
```

**MCP config snippet (if there's a JSON field):**
```json
{
  "mcpServers": {
    "npmguard": {
      "command": "/usr/local/bin/npmguard-mcp"
    }
  }
}
```

**Tool exposed:**
```
install_package(name, version?) → { level: ok|warn|block, score, signals, recommendation }
```

**Tags:** `npm, supply-chain-security, mcp, rust, security, ai-safety, claude-code, cursor, typosquatting, model-context-protocol`

### 1.3 — Submit. Save the resulting URL.

---

# PHASE 2 — Submit to glama.ai (5 min, browser)

### 2.1 — Open https://glama.ai/mcp/servers
### 2.2 — Click **Add Server** in the nav. Sign in with GitHub if prompted.
### 2.3 — Fill with the same data as Phase 1.2 (Glama auto-pulls README + license from GitHub URL).
### 2.4 — Submit. Save the resulting URL.

---

# PHASE 3 — Pick your launch slot

The single highest-leverage decision in this playbook.

### Best windows (US-centric, HN peaks here)

| Day | Window (ET) | Window (UTC) | Why |
|---|---|---|---|
| **Tuesday** | 8:00–9:30 | 13:00–14:30 | US morning + EU afternoon overlap, midweek attention |
| **Wednesday** | 8:00–9:30 | 13:00–14:30 | Same |
| Thursday | OK if must | | Slightly worse — people mentally on Friday |

### Avoid

- **Monday** — back-to-work email backlog
- **Friday** — people log off, no weekend follow-up
- **Sat/Sun** — HN traffic ~40% of weekday
- Holidays in US, UK, or DE (HN's three biggest visitor markets)
- The day before/of/after a major Apple/Google/OpenAI event

### Block the calendar

You need **4 hours continuous** after posting. No meetings, no calls.
Engagement during the first 4 hours is what keeps an HN post on the front page.

---

# PHASE 4 — T-30 min: Pre-flight check (5 min)

### 4.1 — Re-run the Phase 0 commands

Same five-step sanity check, on launch day, 30 min before posting.

### 4.2 — Visual check

Open https://github.com/AyoubTadlaoui/npmguard in a private/incognito browser tab (to see what a first-time visitor sees, not your logged-in view).

Verify:
- README renders with the atlas-ragnarok hero PNG visible at top
- Demo GIF loads (give 2 s to start animating)
- Badges all show green (CI, Release, Latest release, License)
- Install section URLs point to v0.1.3 (not v0.1.1 or v0.1.0)
- MCP server section's JSON snippet is valid (no `//` comments)

If anything's broken — **STOP**. Fix and rebuild before posting.

### 4.3 — Baseline star count

```bash
gh api repos/AyoubTadlaoui/npmguard --jq '.stargazers_count'
```

Note the number; useful retrospective metric.

---

# PHASE 5 — T-15 min: Open tabs (3 min)

In this order, separate tabs, don't close any until Phase 13:

1. https://news.ycombinator.com/submit
2. https://www.reddit.com/r/programming/submit?type=LINK
3. https://www.reddit.com/r/node/submit?type=LINK
4. https://www.reddit.com/r/rust/submit?type=LINK
5. https://www.reddit.com/r/ClaudeAI/submit
6. https://www.reddit.com/r/Cursor/submit
7. https://twitter.com/compose/tweet
8. https://github.com/AyoubTadlaoui/npmguard (incognito tab)
9. https://news.ycombinator.com/newest (to find your post once live)
10. Terminal in `~/npmguard` for engagement tracking

Have in clipboard manager (Raycast / Alfred):
- All post titles and bodies (from Phases 6–12)
- The `docs/demo.gif` file path for drag-drop into X

---

# PHASE 6 — T+0 min: Show HN (~3 min)

### 6.1 — On https://news.ycombinator.com/submit

### 6.2 — Title (paste exactly, 80 char max)
```
Show HN: Npmguard – a Rust pre-install risk gate for npm, with an MCP tool
```

### 6.3 — URL
```
https://github.com/AyoubTadlaoui/npmguard
```

### 6.4 — Text field: **leave empty**
HN best practice for Show HN with a URL: body goes in the first comment, not the submission itself.

### 6.5 — Submit. Note the post URL — like `https://news.ycombinator.com/item?id=XXXXXXXX`.

### 6.6 — Immediately post the body as the first comment

```
Hi HN — Ayoub here.

After the Shai-Hulud / Axios / Mini-Shai-Hulud waves last year, I got
tired of the fact that every existing pre-install checker for npm
(npq, safe-npm/socket npm, npm-risk) is itself distributed on npm. If
the wrapper is ever compromised, you've made the problem worse.

npmguard is a single Rust binary, distributed via GitHub Releases, that
runs *before* `npm install` does:

  - pulls registry + OSV + GitHub signals in parallel (~sub-second on
    cache hit)
  - computes a composite risk score with documented weights
  - returns ok / warn / block, with an exit code

The piece I'm most interested in feedback on: it also ships as an MCP
server, so Claude Code / Cursor / Windsurf must go through the same
gate when *they* run `npm install` on your behalf. That's increasingly
when `npm install` actually happens in 2026.

Honest about scope: v0.1 is a risk checker + MCP verdict gate. It does
not yet wrap the actual `npm install` subprocess or sandbox lifecycle
scripts — that's v0.2. Shipping a half-broken sandbox would erode
trust faster than not shipping one.

Live demo, source, OSV+MAL-* malware detection working against the
real registry (lodahs typosquat blocks at score 115/200):

https://github.com/AyoubTadlaoui/npmguard

Pre-built binaries (macOS/Linux/Windows) and SHA256SUMS on the latest
Release page. Happy to answer questions on the risk weights, the MCP
schema, or why I dropped the Socket dependency from v0.1.
```

---

# PHASE 7 — T+5 min: X thread (5 min)

### 7.1 — Tweet 1 (with GIF attached)

```
I built a Rust binary that stops AI coding agents from blindly running malicious `npm install` commands.

Distributed outside npm. Single binary. Real demo against the live registry below 👇
```

Drag-drop `~/npmguard/docs/demo.gif` into the media area. X converts to MP4 — fine.

### 7.2 — Tweet 2 (reply to tweet 1)

```
Every existing pre-install npm checker (npq, safe-npm, npm-risk) ships as an npm package. So the protection runs on the thing it's protecting you from.

If they're ever compromised, you've made the problem worse.
```

### 7.3 — Tweet 3 (reply)

```
The wedge: npmguard also ships as an MCP server.

Claude Code / Cursor / Windsurf must go through the same risk check when *they* run `npm install` on your behalf.

That's increasingly when `npm install` actually happens in 2026.
```

### 7.4 — Tweet 4 (reply)

```
v0.1 is a risk gate + MCP verdict tool. Not yet a real npm wrapper or a sandbox — that's v0.2.

Better to ship one honest layer than a half-broken sandbox that fails on edge cases and erodes trust.
```

### 7.5 — Tweet 5 (reply, only this one tags accounts)

```
Rust, MIT, 5 platforms on GitHub Releases.
SHA256-verified. Live now:

github.com/AyoubTadlaoui/npmguard

cc @AnthropicAI @cursor_ai
```

### 7.6 — Note the URL of tweet 1. You'll reference it in HN replies later.

---

# PHASE 8 — T+15 min: r/programming (2 min)

### 8.1 — Type: Link post (default)

### 8.2 — Title
```
I built a Rust pre-install risk gate for npm — with an MCP tool so AI agents go through the same check
```

### 8.3 — URL
```
https://github.com/AyoubTadlaoui/npmguard
```

### 8.4 — Submit. Then post the body as the first comment:

```
Background: every existing pre-install checker for npm (npq, safe-npm, npm-risk) ships as an npm package. That's a meta-supply-chain risk — the protection runs on the thing it's protecting you from. After the Shai-Hulud / Axios incidents I wanted a single binary, distributed outside npm, that:

1. Pulls registry + OSV.dev + GitHub signals in parallel
2. Scores composite risk (8 signals, documented weights, capped at 200)
3. Returns ok / warn / block before lifecycle scripts can run
4. Exposes the same check as an MCP tool, so Claude Code / Cursor / Windsurf are forced through the gate when they install packages

Live example — `lodahs` (real npm typosquat of `lodash`, in OSV's malware namespace) blocks at score 115/200 with SoleMaintainer + Typosquat (Damerau-Levenshtein for adjacent-char swaps) + MAL-*.

Repo: https://github.com/AyoubTadlaoui/npmguard
Releases (5 platforms, SHA256 verified): https://github.com/AyoubTadlaoui/npmguard/releases/latest

Honest about scope: v0.1 is a risk checker + MCP verdict gate. It doesn't yet wrap the actual `npm install` subprocess or sandbox lifecycle scripts (that's v0.2 with landlock/sandbox-exec/Job Object).

Curious for feedback on the scoring weights and on whether the MCP gate is the right deployment shape for the AI-agent use case.
```

---

# PHASE 9 — T+30 min: r/node (2 min)

### 9.1 — Title
```
Show: npmguard — a single-binary risk gate that runs before `npm install` (with an MCP server for Claude Code / Cursor / Windsurf)
```

### 9.2 — URL
```
https://github.com/AyoubTadlaoui/npmguard
```

### 9.3 — First comment body

```
Trying to fill the specific gap that npq/safe-npm/npm-risk leave: pre-install scoring + AI-agent gate, distributed outside npm so the gate itself can't be compromised by the supply chain it's protecting.

Sample verdict against the real registry — `lodahs` (typosquat of `lodash`, in OSV's malware DB):

    npmguard  lodahs@0.0.1-security  →  score 115 / 200  (block)
       10 pts  SoleMaintainer       single maintainer: adam_baldwin
       25 pts  Typosquat            name 'lodahs' is 1 edit away from popular package 'lodash'
       80 pts  KnownCve             1 CONFIRMED MALICIOUS by OSV for this version: MAL-2025-25502

MCP integration is the part I think most matters for 2026 — Claude Code / Cursor / Windsurf run `npm install` autonomously, and there was no MCP gate for that until now.

Repo: https://github.com/AyoubTadlaoui/npmguard
v0.1.3 binaries (macOS/Linux/Windows): https://github.com/AyoubTadlaoui/npmguard/releases/latest

v0.1 is risk-only; real npm subprocess wrap + sandbox is v0.2. Honest about that in the README.
```

---

# PHASE 10 — T+45 min: r/rust (2 min)

### 10.1 — Title
```
Show r/rust: npmguard — async risk-signal fan-out (reqwest + tokio + rmcp), single static binary, atlas-ragnarok theme
```

### 10.2 — URL
```
https://github.com/AyoubTadlaoui/npmguard
```

### 10.3 — First comment body

```
A small Rust workspace I just shipped. Four crates:

- npmguard-risk: 8 parallel signal fetchers + composite scoring
- npmguard-cache: SQLite verdict cache (rusqlite, bundled)
- npmguard-cli: clap v4 CLI
- npmguard-mcp: MCP server via the official `rmcp` crate

The risk engine fans out the registry packument fetch + OSV.dev query + GitHub repo lookup with `futures::future::join` after the synchronous-from-metadata signals run. The MCP server uses rmcp's `#[tool]` macro for the `install_package` tool, stdio transport.

Release pipeline is a cross-platform matrix (macos-14 cross-compiles both Mac arches, ubuntu-latest for both Linux arches with gcc-aarch64-linux-gnu, windows-latest for MSVC with PowerShell `Get-FileHash` because Git Bash on Windows doesn't ship `shasum`).

Source: https://github.com/AyoubTadlaoui/npmguard

Happy to discuss the dependency graph between crates (cache depends on risk, mcp depends on both, cli depends on everything — no cycles), or how rmcp's macros compare to writing the JSON-RPC handlers by hand.
```

---

# PHASE 11 — T+60 min: r/ClaudeAI (2 min)

### 11.1 — Title
```
Built an MCP server that stops Claude Code from running malicious `npm install`
```

### 11.2 — Type: text post (r/ClaudeAI prefers self-posts)

### 11.3 — Body

````
Quick context: when an AI coding assistant runs `npm install <whatever>`, it can land arbitrary code on your machine via lifecycle scripts. The Shai-Hulud / Axios / Mini-Shai-Hulud waves last year all ran this exact path.

npmguard is a single-binary MCP server (Rust, distributed outside npm) that exposes one tool: `install_package(name, version?)`. It returns a structured verdict — ok / warn / block — with the signals that triggered (lifecycle scripts, OSV.dev malware advisories, typosquat distance, maintainer churn, etc).

When Claude Code goes through this MCP, it gets the recommendation as a tool response. Even if the user said "just install whatever," the assistant has structured signal to stop and ask.

Config in your `~/.claude.json`:

```json
{
  "mcpServers": {
    "npmguard": {
      "command": "/usr/local/bin/npmguard-mcp"
    }
  }
}
```

Live: https://github.com/AyoubTadlaoui/npmguard

Tested against the real registry — `lodahs` (typosquat of lodash, in OSV's malware DB) correctly blocks at score 115/200.

Looking for feedback specifically from people running Claude Code agentic workflows: what tool calls *do* you wish were gated by default?
````

---

# PHASE 12 — T+90 min: r/Cursor (2 min)

### 12.1 — Title
```
MCP server that stops Cursor from running malicious `npm install`
```

### 12.2 — Type: text post

### 12.3 — Body
Same body as Phase 11.3, with these substitutions:
- "Claude Code" → "Cursor" (every occurrence)
- "~/.claude.json" → Cursor's MCP config path (see Cursor's MCP docs)

---

# PHASE 13 — Engagement window (next 4 hours, mandatory)

**The most important phase.** HN posts that get author replies in the first hour stay on the front page; silent threads fall off.

### 13.1 — Reply discipline

| Time since post | Reply within |
|---|---|
| First 60 minutes | 5 minutes per comment |
| 1h–4h | 15 minutes per comment |
| 4h–24h | 1 hour per comment |
| Day 2 | Same day |
| Day 3+ | Within 24h |

### 13.2 — Reply rules

**Do:**
- Quote the comment in one line so context is obvious
- Link to specific source files (`crates/npmguard-risk/src/signals/osv.rs#L62`)
- Acknowledge flaws openly ("Yes, the weights are heuristic")
- Push back politely when wrong ("Actually npq does X but not Y")

**Don't:**
- Reply with "Thanks!" or "Great point!" alone — substantive only
- Ask for upvotes anywhere — HN ban offense
- Edit README aggressively during the launch window — breaks links in your own threads
- Tell friends to upvote — HN catches this

### 13.3 — Common questions, ready answers

| Q | A |
|---|---|
| "Why not just on npm?" | Meta-supply-chain risk — same reason `safe-npm` shipping on npm was criticized. v0.1.3 ships only via GitHub Releases SHA256-verified. v0.2 adds Homebrew/Scoop. |
| "How is this different from npq?" | Three things: (1) distributed outside npm, (2) escalates OSV `MAL-*` malware-namespace advisories to single-signal block (so `lodahs` actually blocks instead of warning at low severity), (3) ships as an MCP server for AI coding agents. |
| "Doesn't pnpm v10+ already do this?" | For pnpm users, yes. For the npm majority (~60% of the ecosystem), no. And neither pnpm nor Bun ship an MCP tool. |
| "Where's the sandbox?" | v0.2. Roadmap is honest about that — see ROADMAP.md. Shipping a half-broken sandbox is worse than no sandbox. |
| "Your scoring weights look arbitrary" | They are starting values, tuned against a small corpus. PRs welcome. They'll be republished with every release. v0.2 adds tarball-diff signals which catch the "looks normal release" pattern metadata-only scoring misses. |
| "What's the false-positive rate?" | Unknown at scale. Tested against 8 known-good packages (lodash, react, react-dom, typescript, express, next, zod, dayjs) — zero false-positive blocks. Real-world tuning happens in the open. |
| "Why Rust?" | Single static binary, no runtime to install, cross-platform releases work, fast enough that sub-100ms overhead is realistic. Plus the rmcp crate gave me MCP for free. |
| "Why not TypeScript?" | A TypeScript pre-install checker that runs via `npx` is exactly the thing this is trying to replace. |

### 13.4 — Track traffic every hour

```bash
cd ~/npmguard
gh api repos/AyoubTadlaoui/npmguard --jq '.stargazers_count'
gh api repos/AyoubTadlaoui/npmguard/traffic/popular/referrers
gh api repos/AyoubTadlaoui/npmguard/traffic/clones --jq '.count'
gh issue list --repo AyoubTadlaoui/npmguard
gh pr list --repo AyoubTadlaoui/npmguard --state open
```

### 13.5 — If HN lands well (front page top 30)
- Stay on the thread until midnight Pacific. The "second wave" of comments comes from EU morning the next day.
- Post the HN link as a reply on your X thread tweet 1.
- Don't get distracted by traffic spikes — comments feed the ranking algorithm.

### 13.6 — If HN dies fast (no comments in first hour)
- **Don't repost.** HN penalizes reposts.
- Push harder on Reddit + Discord (Phase 15).
- Don't panic — plenty of now-major projects had silent Show HNs.

---

# PHASE 14 — Day +1 (next morning)

### 14.1 — Triage incoming (15 min)

```bash
gh issue list --repo AyoubTadlaoui/npmguard
gh pr list --repo AyoubTadlaoui/npmguard
```

For each:
- Spam / drive-by: close politely
- Real feature request: thank, add to backlog (don't promise)
- Real bug: triage label, reply with timeline
- PR: review, **don't merge anything you don't fully understand**

### 14.2 — Check the awesome-list PRs

```bash
gh pr view 2503 --repo rust-unofficial/awesome-rust
gh pr view 6579 --repo punkpeye/awesome-mcp-servers
```

If maintainers requested changes, address within 24h. Awesome-list maintainers often abandon PRs that don't respond fast.

### 14.3 — Write the long-form post (~1.5h)

Target: dev.to or your personal blog. Working title:

> *How I built a single-binary risk gate for `npm install` — and why every existing one is on npm*

Outline (1200–1500 words):

1. **Hook** — the Shai-Hulud minute. Defender wins or loses *before* the install completes.
2. **What existed** — npq, safe-npm/socket, npm-risk, pnpm v10, Bun. The gap they leave.
3. **Design constraints** — distributed outside npm, sub-100ms overhead, no Socket-API dependency, MCP from day one.
4. **The risk engine** — 8 signals, scoring weights, the OSV `MAL-*` escalation that turned `lodahs` from "ok" into "block".
5. **Why MCP is the load-bearing part** — alias-based CLI gates leak through IDEs/CI/agents; MCP is the only call site you actually own when the AI is typing.
6. **What's still missing** — v0.2 sandbox roadmap, honest about scope.
7. **Try it** — one paragraph, link, releases.

### 14.4 — Publish + cross-link

- Submit to dev.to under tags: `rust`, `security`, `npm`, `mcp`, `ai`
- Reply to your own HN thread with the link
- Add as a comment to your r/programming and r/node threads

---

# PHASE 15 — Day +2 to Day +7

### 15.1 — Discord drops (Day +2, once per server)

| Server | Channel | Message |
|---|---|---|
| Anthropic Discord | `#mcp-discussion` or `#claude-code` | "Built an MCP server for npm supply-chain — feedback welcome on the install_package tool schema: github.com/AyoubTadlaoui/npmguard" |
| MCP server dev Discord (link in MCP official docs) | `#showcase` | Same |
| Rust language community Discord | `#projects` or `#general` | "Posted a small Rust workspace using rmcp + tokio. Single-binary npm risk gate." + link |

**Rule:** one post per server, then engage with replies. Never spam multiple channels in the same server.

### 15.2 — Warm DM outreach (Day +3, ONLY if launch went well)

One-line DMs, no preamble.

**Anthropic devrel (X @AlexAlbert or whoever covers Claude Code):**
```
Hi — built an MCP server that wraps `npm install` risk scoring for Claude Code. Single binary, OSV-backed, blocks typosquats live. Would be glad to demo if it's relevant for the MCP examples or for any post-Shai-Hulud guidance you publish: github.com/AyoubTadlaoui/npmguard
```

**Cursor/Windsurf maintainers (their public X handles):** same template, swap product name.

**Security-newsletter writers** (StepSecurity, Snyk security blog, Socket blog):
```
FYI — shipped an open-source pre-install gate that mirrors the threat-model you've written about. Happy to chat if useful: github.com/AyoubTadlaoui/npmguard
```

### 15.3 — Verify Smithery (Day +7)

```bash
open https://smithery.ai/server/AyoubTadlaoui/npmguard
```

If not indexed, submit manually.

---

# PHASE 16 — Long term

### 16.1 — Day +30 (2026-06-17) — awesome-nodejs PR

```bash
gh api repos/AyoubTadlaoui/npmguard --jq '.stargazers_count'
```

If **≥ 100 stars**, submit the awesome-nodejs PR (same approach as the existing two PRs). If **< 100**, wait another month — Sindre's bot auto-closes anything failing the 30-day/100-star rule.

### 16.2 — v0.2 release (whenever you have ~2 weeks)

See `ROADMAP.md § v0.2`. Highest-leverage items:
- Real `npm install` subprocess wrapper with `--ignore-scripts` enforcement
- Per-OS sandbox (start with macOS sandbox-exec — easiest)
- Tarball-diff release-anomaly engine (Atlas's highest-value addition)
- Homebrew tap + Scoop bucket + install.sh distribution

### 16.3 — v0.2 → revisit MCP Registry

Once shipping Docker images to GHCR (part of v0.2 distribution work), submit to `modelcontextprotocol/registry` as OCI type. See `ROADMAP.md § v0.5` for deferral rationale.

---

# 🚨 Hard rules — never violate

1. **Don't ask for upvotes anywhere.** HN bans for this. Reddit auto-flags.
2. **Don't post identical text** on HN and Reddit at the same minute. Anti-spam tooling correlates.
3. **Don't reply with "thanks!"** — substantive replies only.
4. **Don't edit your README aggressively** during the launch window. Broken links / changed claims undermine credibility.
5. **Don't merge any PR you don't fully understand.** First-week PRs include drive-by trolling and AI-generated noise.
6. **Don't promise features.** "On the roadmap" is fine. "I'll have that in v0.2" is not unless you've already started.
7. **Don't engage with hostile comments past one reply.** Acknowledge once, move on. Long flame threads kill the post.

---

# 📊 Realistic expectations

| Outcome | Stars | What it takes |
|---|---|---|
| **Quiet launch** | 200–800, week 1 | HN doesn't front-page; Reddit modest |
| **Solid launch** | 1k–3k, month 1 | HN top 30 + one Reddit sub gets 100+ upvotes + one X amplifier |
| **Strong launch** | 3k–5k, month 1 | HN top 10 + multiple subs land + sustained engagement |
| **Breakout** | 5k+, 3 months | One of above + an awesome-list inclusion + a major npm incident lands during your visibility window |
| **Default tool** | 10k+, 6 months | An AI coding assistant references npmguard in its docs (downstream of v0.5 MCP marketplace work) |

Median outcome for a polished Show HN with this profile: somewhere between **Quiet** and **Solid**.

---

# ✅ Done-list

- [ ] **Phase 0:** Sanity check passed
- [ ] **Phase 1:** mcp.so submitted, URL saved
- [ ] **Phase 2:** glama.ai submitted, URL saved
- [ ] **Phase 3:** Launch slot chosen, calendar blocked
- [ ] **Phase 4:** T-30 pre-flight passed
- [ ] **Phase 5:** All tabs open
- [ ] **Phase 6:** Show HN posted, body in first comment, URL noted
- [ ] **Phase 7:** X thread posted (5 tweets, GIF on tweet 1, tags on tweet 5)
- [ ] **Phase 8:** r/programming posted
- [ ] **Phase 9:** r/node posted
- [ ] **Phase 10:** r/rust posted
- [ ] **Phase 11:** r/ClaudeAI posted
- [ ] **Phase 12:** r/Cursor posted
- [ ] **Phase 13:** 4-hour engagement window — reply discipline maintained
- [ ] **Phase 14:** Day +1 — incoming triaged, awesome-list PRs checked, long-form posted
- [ ] **Phase 15:** Day +2-7 — Discord drops + warm DMs + Smithery check
- [ ] **Phase 16:** Day +30 awesome-nodejs retry scheduled

---

# 📚 Reference

- Repo: https://github.com/AyoubTadlaoui/npmguard
- Releases: https://github.com/AyoubTadlaoui/npmguard/releases/latest
- Roadmap: [ROADMAP.md](ROADMAP.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
