// VIA ID — outbound-request header helper (the "at request time" half of the mechanism).
//
// A badge-carrying agent has exactly two things to do, and they're different:
//  1. LOG (mandatory, per action) — call the CLI's `viaid log <id> <action> [model]` from
//     the agent's own code after each significant action. This is the whole point of the
//     product ("what did it do") and is not optional — see SKILL.md Phase 2.
//  2. PRESENT the badge to a receiving party (optional, only when it matters — the S1
//     "visitor" scenario: an org receiving this agent wants to check it before trusting it).
//     Attach the two headers below on outbound HTTP calls so the receiving side can look the
//     agent up (fetch the verify URL, or check the local badge file if they already have it)
//     and decide whether to trust/gate it.
//
// This file does ONLY #2, and deliberately does nothing else: it does not re-verify the
// badge, does not wrap fetch/axios/whatever HTTP client the agent happens to use, and does
// not cache. A header is a POINTER, never a substitute for the receiving party's own verify()
// call — attaching a header proves nothing by itself; that's the whole design point of a
// verifiable badge over a self-asserted claim.

import { readFileSync } from 'node:fs';
import { shortCodeFrom } from '../src/agentid.mjs';

const DEFAULT_VERIFY_BASE = 'https://viaid.ai/a/';

// badgePath: path to the minted badge JSON (from `viaid init`). Returns a plain object —
// attach it however the agent's own HTTP client wants (fetch options, axios config, curl -H, ...).
export function viaHeaders(badgePath, { verifyBase = DEFAULT_VERIFY_BASE } = {}) {
  const badge = JSON.parse(readFileSync(badgePath, 'utf8'));
  const code = shortCodeFrom(badge.agent_id);
  return {
    'X-VIA-ID-Agent': badge.agent_id,
    'X-VIA-ID-Verify-URL': verifyBase + code,
  };
}
