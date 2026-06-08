# A deterministic name-distance check at the agent-install seam

A positioning and design document for one body of work: a deterministic, offline name-distance check at the seam where an AI coding agent runs `npm install` or a package runner, brought natively into each agent's own approval step.

I build the trust boundary for autonomous code. [npmguard](https://github.com/AyoubTadlaoui/npmguard) gates what an AI agent is allowed to install. [GoLogX](https://github.com/AyoubTadlaoui/GoLogX) keeps a tamper-evident record of what it did after that. The same install-time gate, the part that flags a package name one edit away from a popular one, belongs inside the agents themselves, next to the analyzers they already run.

## The seam

When a human runs `npm install left-pad`, a human read the name. When an agent does it, nothing read the name. The agent expands a tool call into a shell command, the command runs a lifecycle script, and the first moment a person is in the loop is after the code has already executed. That gap, between the agent deciding to install and the lifecycle script running, is the seam. It is exactly where supply-chain attacks land: a name one keystroke off a real package (`lodahs` for `lodash`), a fresh package that looks like a known one, a runner invocation (`npx`, `bunx`, `pnpm dlx`) that pulls and executes code with no lockfile entry to review later.

Most agents already have an approval step at this seam. They ask the human before running a shell command, and some run security analyzers on the proposed action. What is missing is a cheap, deterministic check on the one thing a human would have noticed instantly: the name is almost, but not exactly, a package you trust.

## The check

It is one function, and it is intentionally small.

1. Parse the agent's proposed command. Extract package specs from install subcommands (`npm install`/`i`/`add`, `yarn add`, `pnpm add`/`install`, `bun add`/`install`) and from on-the-fly runners (`npx`, `bunx`, `npm exec`/`x`, `pnpm dlx`, `yarn dlx`, `bun x`). For a runner, only the executed package is checked, never the arguments passed to it. A bare `npm install` with no package argument is a lockfile restore and is left alone.
2. For each extracted name, compute the Damerau-Levenshtein distance to a curated list of the most-typosquatted npm names. Damerau-Levenshtein, not plain Levenshtein, because an adjacent character swap (`recat` for `react`) is a single human typo and should count as one edit, not two.
3. Flag only a name that is exactly one edit away from a popular name, and only when the popular name is long enough that a one-edit collision is unlikely (in npmguard, length greater than four). One edit is the signal. Two or more edits is a different word, and flagging it produces noise that trains people to click through.
4. On a flag, surface it to the human in the agent's own approval UI: "this name is one edit from `<popular>`, are you sure". Do not hard-deny. The human decides.

That is the whole check. It is pure: no network, no I/O, no registry call, no API key, no telemetry. It is deterministic: the same command always yields the same verdict, which means it is unit-testable without a runtime and cannot fail open because a service was down. It is offline by construction, so it adds no latency and no new dependency to the agent's hot path.

This is not a research artifact. It is the typosquat signal that already ships in npmguard, where `evaluate("lodahs")` returns a single typosquat signal pointing at `lodash`, `evaluate("react")` returns nothing, and `evaluate("zustand")` returns nothing. The parser that feeds it already splits compound shell commands on `&&`, `;`, and `|`, so `cd /tmp && npm install evil` is caught and `echo a || b` is not mistaken for a package. The work to bring upstream is the porting and the placement, not the algorithm.

## Why it belongs next to the existing analyzers, not replacing them

Agents that already do security analysis tend to lean on one of two things: an LLM judging whether an action looks risky, or a database lookup against known-bad advisories. Both are good. Neither covers the name-distance case well, and that is the argument for adding the check rather than folding it into what exists.

An LLM-based analyzer is probabilistic. Ask it the same question twice and you can get two answers, and a one-character difference between `lodash` and `lodahs` is precisely the kind of detail a token-level model glosses. You do not want the decision about whether a name is a typosquat to depend on sampling temperature. A deterministic edit-distance check gives the same verdict every time, and it gives a reason a human can check in one second: here is the name you typed, here is the real name, they differ by one character.

A database lookup (OSV, advisory feeds) is authoritative but only for packages someone has already reported. A brand-new typosquat published an hour ago is not in any database yet. Edit distance does not need the package to have been reported; it only needs the target it is impersonating to be popular, which is knowable in advance. The two approaches catch different things. npmguard runs both: it queries OSV for confirmed-malicious advisories (version-aware, so a `MAL-*` advisory matched to the resolved version blocks, including npm `-security` takedown stubs like `lodahs`) and it runs the offline name-distance heuristic. The database is the floor. The name check is the part that works before the database has heard of the threat.

So the proposal to each agent is additive: keep your analyzer, keep your advisory lookup, and add one deterministic, offline pre-check on the name at the moment of install. It is the cheapest analyzer you can run, it never calls out, and it covers the gap the other two leave open.

## Design constraints (the same ones npmguard holds)

- **Never hard-deny.** The check asks; the human answers. An agent that blocks installs outright gets disabled. An agent that asks a sharp question at the right moment gets trusted. The point is to put a person back in the loop at the seam, not to replace their judgment.
- **Fail open for non-installs.** A command that is not an install or a runner must never be blocked by this code. If parsing is uncertain, do nothing. The check only ever speaks up on a confident one-edit hit.
- **No new dependency, no network.** The check is standard-library-grade. Adding it to an agent must not add a service, a key, or a call home. This is why it is offline edit distance and not an API.
- **Boring on purpose.** One edit, long-enough target, one question. No scoring model to tune, no threshold to argue about in review. A maintainer can read the whole thing in one sitting and own it after I am gone.

## Targets and honest current state

This is one body of work proposed across several agents, each in that agent's real approval seam, with the same check above. None of the items below are merged. They are open proposals, and I will not describe them as anything else.

| Agent | Where it goes | State |
| --- | --- | --- |
| [Goose](https://github.com/block/goose/pull/9642) | Supply-chain typosquat inspector, native check at the install/runner step | Open PR, in review |
| [OpenHands](https://github.com/OpenHands/software-agent-sdk/issues/3560) | `SupplyChainSecurityAnalyzer` alongside the existing security analyzer | Open issue. Maintainers triaged it as an enhancement and pinged their security lead |
| [Cline](https://github.com/cline/cline/issues/11340) | Supply-chain inspector at the command-approval step | Open issue |
| [Continue](https://github.com/continuedev/continue/issues/12573) | Supply-chain inspector at the command-approval step | Open issue |
| [Crush](https://github.com/charmbracelet/crush/issues/3090) | Supply-chain inspector at the command-approval step | Open issue |

The framing to each is the same: the install-time gate, pushed into the agent itself. npmguard is the reference implementation that already does this over MCP and as a CLI. The upstream work is the same deterministic check, implemented natively in each agent's own approval seam so the human gets the question without needing to run a separate tool.

## What is actually shipped vs. proposed

I am keeping these two apart on purpose, because conflating them is the one mistake I refuse to make.

**Shipped / merged (stated as fact):**

- npmguard, an npm install firewall for AI agents, parses install and runner commands, runs the offline name-distance check, and queries OSV for confirmed-malicious advisories. It refuses real OSV malware (for example `lodahs`, `MAL-2025-25502`). It ships as one Rust binary, deliberately off npm, so the gate cannot be poisoned by the registry it guards.
- npmguard is listed in the [awesome-software-supply-chain-security](https://github.com/bureado/awesome-software-supply-chain-security/pull/65) registry (PR #65, merged).

**Proposed upstream (open, in review, not merged):**

- The five agent integrations above. Every one is an open PR or open issue. Goose is an open PR in review. OpenHands is an open issue the maintainers triaged as an enhancement. Cline, Continue, and Crush are open issues. I am not a contributor to any of these projects yet, and none of this work is shipping in them.

## Scope of the claim

I am not claiming adoption, users, or traction. The repos are small. The claim is narrower and it is true: this is one coherent surface, the agent-execution seam, and I have built the reference check for it, carried it all the way to a working firewall, and proposed the same check natively into the agents where it most belongs. The check is deterministic, offline, additive to what already exists, and honest about its limits: a sufficiently obfuscated command can evade any command-string parser, and full enforcement needs a wrapper-and-sandbox layer, which is a separate piece of work.

Atlas Kaisar  
atlas.kaisar@icloud.com  
github.com/AyoubTadlaoui
