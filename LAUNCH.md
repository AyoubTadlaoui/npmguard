# Launch playbook

Drafts and checklist for going public. Everything below is intentionally
ready-to-paste — adapt timing to your week.

> **Honest framing rule.** Pitch this as *"a pre-install risk gate for npm
> packages, with an MCP tool for AI coding agents."* It is not "drop-in
> npm install protection" (that ships in v0.2 with the sandbox). Stick to
> what v0.1.1 actually does — pre-install risk scoring + a verdict gate
> that AI assistants can call before they run `npm install` on your behalf.

---

## Sequencing — strong launch in 5 days

| Day | Move | Why |
|---|---|---|
| **D-1** | Publish `v0.1.1`, verify Release page renders, copy-test all links | First impressions kill if README links 404 |
| **D-1** | Open PRs to community registries (below) | Drives discovery before the spike |
| **D-0 (Tue or Wed)** | Show HN at **8:00–9:30 ET** | Peak HN front-page window |
| **D-0** | Reddit posts (in order, ~30 min apart) | Avoid cross-post detection flagging |
| **D-0** | X thread | Lower stakes, longer tail |
| **D-0 → D+2** | Be on threads — answer every question | First-day engagement = visibility loop |
| **D+1** | Dev.to / Hashnode long-form | SEO + secondary discovery |
| **D+3** | Follow-up on PRs to lists | Maintainer review usually 2-3 days |

---

## Show HN

**Title (80 chars max — keep it boring and concrete):**

```
Show HN: Npmguard – a Rust pre-install risk gate for npm, with an MCP tool
```

(HN audience reads "Show HN" as a signal of "I built this." Don't add taglines or emojis.)

**Body (paste verbatim):**

```text
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

**Posting hygiene:**
- Submit, don't ask for upvotes anywhere (HN bans this fast).
- Stay on the thread for the first 4 hours. Reply to every top-level
  comment, even hostile ones, calmly and substantively.
- Don't post identical text on Reddit at the same minute — HN watches.

---

## Reddit

Post in this order, ~30 min between subs. Each sub has a different
tolerance — copy/paste these as drafts, not all at once.

### r/programming (least promotional, most technical)

**Title:**
```
I built a Rust pre-install risk gate for npm — with an MCP tool so AI agents go through the same check
```

**Body:**
```text
Background: every existing pre-install checker for npm (npq, safe-npm,
npm-risk) ships as an npm package. That's a meta-supply-chain risk —
the protection runs on the thing it's protecting you from. After the
Shai-Hulud / Axios incidents I wanted a single binary, distributed
outside npm, that:

1. Pulls registry + OSV.dev + GitHub signals in parallel
2. Scores composite risk (8 signals, documented weights, capped at 200)
3. Returns ok / warn / block before lifecycle scripts can run
4. Exposes the same check as an MCP tool, so Claude Code / Cursor /
   Windsurf are forced through the gate when they install packages

Live example — `lodahs` (real npm typosquat of `lodash`, in OSV's
malware namespace) blocks at score 115/200 with SoleMaintainer +
Typosquat (Damerau-Levenshtein for adjacent-char swaps) + MAL-*.

Repo: https://github.com/AyoubTadlaoui/npmguard
Releases (5 platforms, SHA256 verified):
https://github.com/AyoubTadlaoui/npmguard/releases/latest

Honest about scope: v0.1 is a risk checker + MCP verdict gate. It
doesn't yet wrap the actual `npm install` subprocess or sandbox
lifecycle scripts (that's v0.2 with landlock/sandbox-exec/Job Object).

Curious for feedback on the scoring weights and on whether the MCP
gate is the right deployment shape for the AI-agent use case.
```

### r/node (more practical, less ceremony)

**Title:**
```
Show: npmguard — a single-binary risk gate that runs before `npm install` (with an MCP server for Claude Code/Cursor/Windsurf)
```

**Body:** same as r/programming but drop the "background" framing and
lead with the live verdict block.

### r/rust (implementation details welcome)

**Title:**
```
Show r/rust: npmguard — async risk-signal fan-out (reqwest + tokio + rmcp), single-binary, atlas-ragnarok theme
```

**Body:**
```text
A small Rust workspace I just shipped. Four crates:

- npmguard-risk: 8 parallel signal fetchers + composite scoring
- npmguard-cache: SQLite verdict cache (rusqlite, bundled)
- npmguard-cli: clap v4 CLI
- npmguard-mcp: MCP server via the official `rmcp` crate

The risk engine fans out the registry packument fetch + OSV.dev query
+ GitHub repo lookup with `futures::future::join` after the
synchronous-from-metadata signals run. The MCP server uses rmcp's
`#[tool]` macro for the `install_package` tool, stdio transport.

The whole release pipeline (cargo-dist-style cross-platform matrix,
sha256 in PowerShell on Windows because Git Bash doesn't ship
`shasum`) is checked in too.

Source: https://github.com/AyoubTadlaoui/npmguard
```

### r/ClaudeAI (lead with the AI-agent angle)

**Title:**
```
Built an MCP server that stops Claude Code from running malicious `npm install`
```

**Body:**
```text
Quick context: when an AI coding assistant runs `npm install <whatever>`,
it can land arbitrary code on your machine via lifecycle scripts. The
Shai-Hulud / Axios / Mini-Shai-Hulud waves last year all ran this
exact path.

npmguard is a single-binary MCP server (Rust, distributed outside npm)
that exposes one tool: `install_package(name, version?)`. It returns
a structured verdict — ok / warn / block — with the signals that
triggered (lifecycle scripts, OSV.dev malware advisories, typosquat
distance, maintainer churn, etc).

When Claude Code (or Cursor, or Windsurf) goes through this MCP, it
gets the recommendation as a tool response. Even if the user said
"just install whatever," the assistant has structured signal to stop
and ask.

Config in your Claude Code `~/.claude.json`:
```jsonc
{
  "mcpServers": {
    "npmguard": { "command": "/usr/local/bin/npmguard-mcp" }
  }
}
```

Live: https://github.com/AyoubTadlaoui/npmguard

Tested against the real registry — `lodahs` (typosquat of lodash, in
OSV's malware DB) correctly blocks at score 115/200.

Looking for feedback specifically from people running Claude Code
agentic workflows: what tool calls *do* you wish were gated by
default?
```

### r/Cursor (same pitch, swap names)

Same template as r/ClaudeAI, swap "Claude Code" → "Cursor" and link
the MCP setup section of Cursor's docs.

---

## X / Twitter thread

5 short tweets. Post the GIF on tweet 1, link on the last tweet, tag
relevant accounts on the last tweet only (looks less spammy).

**1/5 — hook + GIF:**
```
I built a Rust binary that stops AI coding agents from blindly running
malicious `npm install` commands.

Distributed outside npm. Single binary. Real demo against the live
registry below 👇
```
*(attach docs/demo.gif)*

**2/5 — the gap:**
```
Every existing pre-install npm checker (npq, safe-npm, npm-risk) ships
as an npm package. So the protection runs on the thing it's protecting
you from.

If they're ever compromised, you've made the problem worse.
```

**3/5 — the MCP angle:**
```
The wedge: npmguard also ships as an MCP server.

Claude Code / Cursor / Windsurf must go through the same risk check
when *they* run `npm install` on your behalf.

That's increasingly when `npm install` actually happens in 2026.
```

**4/5 — honest scope:**
```
v0.1 is a risk gate + MCP verdict tool. Not yet a real npm wrapper or
a sandbox — that's v0.2.

Better to ship one honest layer than a half-broken sandbox that fails
on edge cases and erodes trust.
```

**5/5 — link + tags:**
```
Rust, MIT, 5 platforms on GitHub Releases.
SHA256-verified. Live now:

github.com/AyoubTadlaoui/npmguard

cc @AnthropicAI @cursor_ai
```

---

## Dev.to / Hashnode long-form (D+1)

**Working title:** *"How I built a single-binary risk gate for `npm install` — and why every existing one is on npm"*

Outline (target 1200–1500 words):

1. **Hook** (the Shai-Hulud minute — defender wins or loses *before* the
   install completes)
2. **What existed** (npq, safe-npm/socket, npm-risk, pnpm v10, Bun) and
   the gap they leave
3. **Design constraints** — distributed outside npm, sub-100ms overhead,
   no Socket-API dependency, MCP from day one
4. **The risk engine** — 8 signals, scoring weights, the OSV `MAL-*`
   namespace escalation that turned `lodahs` from "ok" into "block"
5. **Why MCP is the load-bearing part** — alias-based CLI gates leak
   through IDEs/CI/agents; MCP is the only call site you actually own
   when the AI is the one typing
6. **What's still missing** — v0.2 sandbox roadmap, honest about scope
7. **Try it** — one paragraph, link, releases

---

## External list submissions

Open these as PRs from `AyoubTadlaoui` to each repo. Each is a single
line addition or a single new file. **I will draft the PRs only on
your explicit go-ahead, since they post under your GitHub identity
on someone else's repo.**

| Target list | What to add | URL |
|---|---|---|
| `modelcontextprotocol/servers` | Single line under "Community Servers": `[**npmguard**](https://github.com/AyoubTadlaoui/npmguard) — Pre-install risk gate for npm packages. Stops AI coding agents from running malicious `npm install`.` | https://github.com/modelcontextprotocol/servers |
| `punkpeye/awesome-mcp-servers` | Same line under appropriate category (Security / DevOps) | https://github.com/punkpeye/awesome-mcp-servers |
| `rust-unofficial/awesome-rust` | Under "Applications → Security" | https://github.com/rust-unofficial/awesome-rust |
| `sindresorhus/awesome-nodejs` | Under "Security" if accepted (sindresorhus's bar is high) | https://github.com/sindresorhus/awesome-nodejs |
| `analyticalmonk/awesome-neuroscience` | _(no, skip)_ | _(unrelated)_ |

**MCP catalogs (browser-submission, not PR):**

- https://mcp.so/ — submit via their web form
- https://glama.ai/mcp/servers — submit via their form
- https://smithery.ai/ — auto-indexes public GitHub MCP servers; should pick npmguard up after the topic tags propagate

---

## Discord drops (post once per server, in the right channel)

| Server | Channel | Tone |
|---|---|---|
| Anthropic Discord | `#mcp-discussion` or `#claude-code` | "Built an MCP server for npm supply-chain — feedback welcome on the install_package tool schema" |
| MCP server developer Discord (link from official docs) | `#showcase` | Same |
| Rust language community | `#general` | "Posted a small Rust workspace using rmcp + tokio. Single-binary npm risk gate." |

**Avoid:** general developer Discords where security tooling reads as off-topic. Niche-fit only.

---

## Outreach (warm DM templates)

Use these sparingly. One-line, no preamble, no "hope this finds you well."

**Anthropic devrel (e.g. @AlexAlbert or whoever covers Claude Code):**
```
Hi — built an MCP server that wraps `npm install` risk scoring for
Claude Code. Single binary, OSV-backed, blocks typosquats live. Would
be glad to demo if it's relevant for the MCP examples or for any
post-Shai-Hulud guidance you publish:
github.com/AyoubTadlaoui/npmguard
```

**Cursor/Windsurf maintainers:** same template, swap product name.

**Security-newsletter writers (StepSecurity, Snyk security blog, Socket
blog):** "FYI — shipped an open-source pre-install gate that mirrors
the threat-model you've written about. Happy to chat if useful."

---

## Engagement principles for the launch window

- **Reply within 30 minutes** for the first 4 hours after Show HN goes up.
- **Be honest about flaws.** "Yes, the weights are heuristic. Yes, v0.1
  doesn't sandbox. Here's the roadmap." Wins more upvotes than defensive
  replies.
- **Don't post identical comments across subs.** Adapt to each
  community's tone.
- **Track every link click + star with `gh api`** — useful retro data:
  ```
  gh api repos/AyoubTadlaoui/npmguard/traffic/clones
  gh api repos/AyoubTadlaoui/npmguard/traffic/views
  gh api repos/AyoubTadlaoui/npmguard/traffic/popular/referrers
  ```
  (Requires `read:repo` token, which the local `gh` is already authed for.)

---

## Realistic expectations

Based on what comparable security tooling launches typically do:

| Outcome | What it takes |
|---|---|
| **200–800 stars** in launch week | Quiet ship — Releases live, README clean, one Show HN post |
| **1k–5k stars** in launch month | Show HN front page (top 10) + r/programming + at least one big X amplifier + an awesome-list inclusion |
| **5k+** in 3 months | Becomes the obvious "safe npm install" tool for at least one AI assistant's docs; a major supply-chain incident lands during the visibility window |
| **10k+** in 6 months | One of the above + sustained content (blog posts, follow-up releases, MCP marketplace placement) |

10k year-one is achievable but not certain. The thing that most moves
adoption is **whether AI coding assistants start recommending it by
default** — which is downstream of the MCP catalog listings and direct
outreach above.
