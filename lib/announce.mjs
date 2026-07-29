// VIA ID — conversational self-announcement helper (SAT-926).
//
// attach.mjs's viaHeaders() answers "how does a system-to-system caller find this agent's
// badge" (two HTTP response headers). This answers the conversational equivalent: a human
// just chatting with the agent has no headers to read. There's no chat transport this skill
// can hook automatically, so this is deliberately the smallest possible piece: one function
// that returns one fixed, regex-detectable sentence. The integrator decides WHEN to use it
// (on request, once per session, in the system prompt, whatever fits their agent) — this
// file doesn't wrap a chat loop or guess at intent.
//
// The wording matters: if an integrator paraphrases it instead of using it verbatim, a human
// or tool trying to regex the short code back out of the reply may fail. Treat the returned
// string as a fixed contract, not a template to reword.

import { readFileSync } from 'node:fs';
import { shortCodeFrom } from '../src/agentid.mjs';

const DEFAULT_VERIFY_BASE = 'https://viaid.ai/a/';

// badgePath: path to the minted badge JSON (from `viaid init`). Returns the exact sentence to
// paste into a system prompt, or to return verbatim when a human asks "what's your VIA ID" /
// "do you have a badge" / similar.
export function announceLine(badgePath, { verifyBase = DEFAULT_VERIFY_BASE } = {}) {
  const badge = JSON.parse(readFileSync(badgePath, 'utf8'));
  const code = shortCodeFrom(badge.agent_id);
  return `My VIA ID is ${code} — verify at ${verifyBase}${code}.`;
}
