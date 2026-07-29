# VIA ID

Give an AI agent a verifiable identity and a tamper-evident record of what it did.

An **AgentID** is a small signed file: a 3-key identity (an Owner/Creator key, an Agent key,
and a neutral VIA ID "Witness" co-signature) plus a hash-chained log the agent appends to as
it acts. Anyone can verify a badge offline — no VIA ID server required to check it, only to
mint or co-sign a new one.

VIA ID answers **"what did this agent do, and can I trust the record?"** — not who the agent
is (that's Okta/identity providers), not its name (Agent Name Service), not who owns it
(GLEIF-style registries), not how it pays (AP2). One narrow job, done honestly.

**Claim discipline:** VIA ID says "tamper-evident" — if the log is altered, verification shows
it — and never "tamper-proof," "tamper-safe," "certified," or "compliant." A `verify` result
reports what it actually checked (signatures, log-chain integrity, key-rotation history) and
its assurance tier, not a blanket claim about the agent's safety or behavior.

## Install

**Fastest — published to npm, no clone needed:**

```bash
npx viaid-skill
```

**Via the Agent Skills registry:**

```bash
npx skills add SathiaAI/viaid
```

**From a clone of this repo:**

```bash
node scripts/install.js
```

All three auto-detect Claude Code, Codex CLI, Gemini CLI, Cursor, and Windsurf on your machine
and copy the skill into each one's skills directory. Takes under a second.

## Use

```bash
node bin/viaid.mjs init "my-agent"      # mint a badge once, when the agent ships
node bin/viaid.mjs log <id> "did-thing" # the agent's own runtime calls this after each action
node bin/viaid.mjs verify <id>          # check a badge — VALID / STALE / REVOKED / UNKNOWN
node bin/viaid.mjs rotate <id> [reason] # rotate the agent key on schedule or after compromise
```

See `SKILL.md` for the full instructions an AI coding agent follows when this skill is
installed — phased guidance (mint once, log every action, optionally present the badge to a
receiving party via headers, verify before shipping), plus an explicit "what NOT to do"
section.

## What's in here

- `SKILL.md` — the skill definition an AI coding agent reads.
- `bin/viaid.mjs` — the CLI (`init` / `log` / `verify` / `revoke` / `rotate`).
- `src/agentid.mjs` — the badge core: mint, sign, verify, key rotation, offline freshness
  states (FRESH/STALE/REVOKED/UNKNOWN). Zero external dependencies — just `node:crypto`.
- `src/verify-page.mjs` — renders a badge's verdict as a readable page/summary.
- `src/adapters/` — optional integrations (GraphSmith, KnoSky) — no-ops if those tools aren't
  present; this skill never requires them.
- `lib/attach.mjs` — `viaHeaders(badgePath)` for an agent to present its badge to a receiving
  party over HTTP. Deliberately thin: a header is a pointer, not a proof — the receiving party
  still has to call `verify()` itself.
- `scripts/install.js` — the installer.

## Status

Early. Built and dogfooded (mint → log → verify → rotate end-to-end, adversarial harness
passing including forged-rotation/replay/wrong-key-sequence attacks), not yet widely used.
Feedback and issues welcome.

## License

MIT — see `LICENSE`.
