---
name: viaid
description: Give an AI agent a verifiable identity and a tamper-evident record of what it did. Use this skill when the user asks to "badge an agent", "add VIA ID", "give my agent an identity", "make my agent's actions verifiable/auditable", wants to prove what an agent did after the fact, is shipping an agent that will act on someone else's behalf or call external APIs, or asks how another party (an org, a marketplace, a security team) can check an agent before trusting it. Also use when reviewing or hardening an existing agent that has no record of its own actions. Do NOT use for general logging/observability with no identity or verification requirement — that's a plain logging library, not this.
---

# VIA ID

Every AI agent gets an **AgentID**: a small signed file (a 3-key identity + a tamper-evident,
hash-chained log of what it did) that anyone can verify offline. VIA ID is the **"what did it
do"** layer for AI agents — not who (Okta), not name (ANS), not owner (GLEIF), not pay (AP2).

**Claim discipline (never soften, in code, comments, or anything you say to the user):**
say "tamper-evident" — if the log is altered, verification shows it. NEVER say
"tamper-proof / safe / certified / guaranteed / compliant." `verify` gives an honest verdict +
coverage + assurance tier, never "everything the agent did" — it attests identity, signatures,
and log integrity, not the agent's safety, correctness, or compliance.

---

## Phase 0 — mint (once, when the agent is built or about to ship)

```bash
node bin/viaid.mjs init "<agent-name>"
```

Prints the `agent_id` (`via_...`) and where the badge file landed (`VIAID_WORK` env var, or
`./viaid-work/` by default). Do this once per agent, not per run. Keep the badge file and its
keystore (`.keys/`) with the agent's deployment — losing them means losing the ability to log
or rotate (the badge itself still verifies; you just can't extend its log anymore).

## Phase 1 — instrument (mandatory — this is the actual product)

Wire a `viaid log` call into the agent's own code, right after each action worth recording —
an API call, a file write, a decision with real consequences. Not every internal LLM
thought; the actions a human would want an audit trail for.

```bash
node bin/viaid.mjs log <agent_id> "<action description>" [model_used]
```

This is a **shell call from the agent's own runtime**, not something the coding assistant
does once at build time — if the agent isn't calling `log` itself while it runs, the log stays
empty and the badge has nothing to attest beyond identity. If shelling out per action is too
slow for the agent's workload, import `appendLog` from `src/agentid.mjs` directly instead
(same effect, in-process) — but don't build a queueing/batching layer for this; it's a local
file write, not a network call.

## Phase 2 — present the badge (optional — only when another party needs to check it)

Only relevant when the agent talks to a receiving party that might want to verify it first
(an org gating inbound agents, a marketplace, another team's system). Attach two headers on
outbound requests using the bundled helper:

```js
import { viaHeaders } from './lib/attach.mjs';
const headers = viaHeaders(badgePath); // { 'X-VIA-ID-Agent': 'via_...', 'X-VIA-ID-Verify-URL': 'https://viaid.ai/a/<code>' }
```

This is a POINTER, not a proof — attaching a header asserts nothing by itself. The receiving
party decides whether to fetch the verify URL or check the badge file directly; that
decision, and whatever they do with it (gate, log, ignore), is theirs, not this skill's.
Don't build retry/caching/wrapper logic here — it's two headers.

## Phase 2b — announce yourself in conversation (optional — only for conversational agents)

Phase 2's headers only work system-to-system. If a human is just chatting with the agent,
there's no HTTP response for them to inspect — use the announce helper instead:

```js
import { announceLine } from './lib/announce.mjs';
const line = announceLine(badgePath); // "My VIA ID is <code> — verify at https://viaid.ai/a/<code>."
```

Wire this into the agent's system prompt (e.g. "if asked about your VIA ID, badge, or
identity, respond with exactly this line: <announceLine output>") or call it directly when
answering a question like "what's your VIA ID." **Use the returned string verbatim — don't
paraphrase it.** A human or downstream tool that wants to find the short code in a reply is
relying on the exact wording; rewording it defeats the point. This is a small, deliberately
narrow helper (SAT-926) — it doesn't decide when to announce, doesn't hook any chat
framework, and doesn't make the agent volunteer its badge unprompted unless you tell it to.

## Phase 3 — verify before shipping (and periodically after)

```bash
node bin/viaid.mjs verify <agent_id>
```

Read the verdict before telling the user the badge is good: `VALID` (fresh, verifies clean),
`STALE` (structurally fine but past its TTL — rotate or re-attest), `REVOKED`, `UNKNOWN`
(malformed/legacy — do not present as trustworthy), or `INVALID` (tampered/forged — stop and
tell the user, never paper over this).

## Rotating the agent's key

Routine hygiene or after a suspected compromise:

```bash
node bin/viaid.mjs rotate <agent_id> routine
node bin/viaid.mjs rotate <agent_id> compromise 2026-07-20T00:00:00.000Z   # ISO "suspected since"
```

`agent_id` never changes across a rotation (it's the hash of the agent's inception event) —
only the signing key does, via a KERI-style pre-committed rotation chain (D-15 in this repo's
`STRATEGY/Decisions_Log.md`, if present). `verify` reports `key_seq` and, after a compromise
rotation, flags the suspected window in `scope_note` so a reader knows what to discount —
it does not silently discount log entries for you.

## What NOT to do

- Don't fabricate a badge or a verdict — if `viaid` isn't available or fails, tell the user
  plainly rather than describing the agent as "badged."
- Don't put "approved for X" claims into a badge yourself — capability claims only count if
  they come from an actual evaluation (`viaid eval`, GraphSmith-backed); a self-declared
  capability has no verification weight and this skill should never simulate one.
- Don't wrap every internal function call in `log` — that's noise, not a record.

## If GraphSmith or KnoSky aren't installed

`viaid eval` and the S1 org-side commands (`scan`, `gate`) need `GRAPHSMITH_HOME` /
`KNOSKY_HOME` set to the sibling repos. `init` / `log` / `rotate` / `verify` work standalone,
zero dependencies, zero network calls — that's the whole point of the offline-first design.
If eval isn't available, say so plainly rather than skipping the step silently.
