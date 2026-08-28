// SAT-1009 — Jazzer.js coverage-guided fuzz target for the badge verify/parse core.
//
// Exercises exactly the same two calls the CLI makes for every inbound badge (`viaid verify
// <id>` / `viaid scan <id>`, bin/viaid.mjs -> aid.loadBadge() then aid.verifyBadge()):
//   1. JSON.parse(rawBytes)   — what loadBadge() does (src/agentid.mjs)
//   2. verifyBadge(parsed)    — the verify/parse core itself
//
// Two properties are checked on every input, matching this ticket's goal: malformed/adversarial
// badge input must not crash the process or bypass verification — it must fail cleanly.
//
//   (a) NO CRASH. verifyBadge() must never throw for any value JSON.parse can produce. Invalid
//       JSON *syntax* is expected to throw from JSON.parse itself -- that's an already-handled
//       rejection at the parse boundary (loadBadge's own contract), not a target bug, so it's
//       caught here and treated as uninteresting, not a finding.
//
//   (b) NO BYPASS. verifyBadge() must never return a "trusted" verdict -- VALID, REVOKED, STALE,
//       or UNKNOWN -- unless the badge carries three genuine Ed25519 signatures over its own
//       signed core (coreForSigning). Per the verdict computation in src/agentid.mjs, all four of
//       those are only reachable once `structurally_valid` (agent_id match + all 3 signatures +
//       log hash-chain) has passed; only 'INVALID' is reachable without it. Forging a signature is
//       computationally infeasible for a byte-mutating fuzzer, so for adversarial input, any
//       verdict other than INVALID means a signature/chain check was skipped or short-circuited --
//       a real verification bypass, not just the 'VALID' case.
//
//       Exactly one corpus seed is exempt: fuzz/corpus/verify-badge/revoked.json is a genuinely
//       signed badge (real Ed25519 keypairs, generated only for this fixture) with
//       revocation_state: REVOKED, added so this corpus actually exercises the REVOKED branch --
//       see PR #15 review discussion. Inputs whose *signed core* (everything except
//       `.signatures` -- see coreForSigning in src/agentid.mjs, replicated below) exactly matches
//       that seed's are recognized and held to their own, narrower property: since `.signatures`
//       is excluded from the core, the fuzzer can still mutate those three string values alone,
//       and doing so legitimately produces either REVOKED (mutation was noise a lenient base64
//       decoder absorbed, signatures still verify) or INVALID (mutation broke a signature for
//       real) -- both correct, expected outcomes for this fixed core, never a bypass. See the
//       fuzz() body below for the full trace of why only those two verdicts are reachable here.
//
//       This is a *core*-content match, not a raw-byte or whole-document match, and that
//       distinction is load-bearing, not cosmetic: an early version of this check compared raw
//       input bytes and a live fuzz run immediately produced a false positive, because
//       Node's base64 decoder silently discards non-alphabet characters, so e.g. inserting a lone
//       `: ` inside a signature string still decodes to the exact same signature bytes and still
//       verifies. The signed core, by contrast, cannot be mutated without breaking every one of
//       the three signatures (that is the entire point of signing it), so a core match reliably
//       means "this is the one genuinely-signed seed, however its signature strings happen to be
//       spelled" and a core mismatch reliably means "this has no genuine signature behind it at
//       all." Every other seed in corpus/verify-badge/ carries deliberately-garbage
//       `signatures`/`voucher_attestation` values (see gen script note in the corpus README) and,
//       along with every mutation that changes the core, is subject to the INVALID-only rule.
//
// Throwing from fuzz() is how Jazzer.js records a finding, so both properties are just: don't
// swallow verifyBadge()'s own exceptions, and explicitly throw if either check above is violated.
//
// Run: npm run fuzz:verify-badge (time-boxed — see the -max_total_time in that script; a fixed
// duration on purpose, so this can run to completion in CI without hanging indefinitely).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { verifyBadge, canonical } from '../src/agentid.mjs';

// Real badges are small signed JSON documents (a handful of Ed25519 keys/hashes and, typically,
// a short log). Capping the input size keeps the fuzzer inside the realistic badge-file size
// envelope instead of spending its time budget mutating multi-megabyte blobs that no caller of
// loadBadge()/verifyBadge() would ever be handed as a *.badge.json file.
const MAX_INPUT_BYTES = 16384;

// Mirrors the unexported coreForSigning() in src/agentid.mjs exactly: the three signatures cover
// the badge core, which is everything except `.signatures`. Kept local rather than exported from
// the library purely for this one fuzz-target comparison -- not a verification-logic change.
function coreForSigning(badge) {
  const { signatures, ...core } = badge;
  return canonical(core);
}

// The one legitimately-signed seed's core -- see property (b) above. Computed once, by exact
// path, so this stays tied to that specific fixture rather than to anything guessed from shape.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GENUINE_REVOKED_SEED_PATH = path.join(__dirname, 'corpus/verify-badge/revoked.json');
const GENUINE_REVOKED_CORE = coreForSigning(JSON.parse(readFileSync(GENUINE_REVOKED_SEED_PATH, 'utf8')));

export function fuzz(data) {
  if (data.length > MAX_INPUT_BYTES) return;

  let text;
  try {
    text = data.toString('utf8');
  } catch {
    return; // not valid UTF-8 -- can't be a JSON badge file, uninteresting
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return; // invalid JSON syntax -- loadBadge()/JSON.parse already rejects this, not a target bug
  }

  const verdict = verifyBadge(parsed); // must never throw -- see file header, property (a)

  const isGenuineCore = typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) &&
    coreForSigning(parsed) === GENUINE_REVOKED_CORE;

  if (isGenuineCore) {
    // The one exception to property (b): this input's signed core exactly matches the known
    // genuinely-signed REVOKED fixture. `.signatures` is excluded from the core by definition
    // (coreForSigning), so the fuzzer is still free to mutate those three string values alone --
    // and doing so determines, deterministically, which of exactly two outcomes results (traced
    // through the verdict computation in src/agentid.mjs for this fixed core): agent_id/keys/log
    // all check out unconditionally (they're core-fixed and already correct), so
    // structurally_valid reduces to sigOk alone; and revocation_state: REVOKED in the core forces
    // offline_state to REVOKED unconditionally whenever structurally_valid holds. So verdict is
    // REVOKED when the three signatures still verify (mutation was noise a lenient base64 decoder
    // absorbed, or no mutation at all) and INVALID when any of them was broken for real (mutation
    // changed the actual decoded signature bytes) -- both are correct, expected verifyBadge()
    // behavior, not a bypass. Anything else here (VALID/STALE/UNKNOWN) is not reachable through
    // that logic for this core no matter what `.signatures` says, so it would mean a real bug.
    if (verdict.verdict !== 'REVOKED' && verdict.verdict !== 'INVALID') {
      throw new Error(
        'REGRESSION: an input with the known genuinely-signed core (corpus/verify-badge/' +
        'revoked.json) returned an unreachable verdict for that core -- got: ' +
        JSON.stringify(verdict)
      );
    }
    return;
  }

  if (verdict.verdict !== 'INVALID') {
    // property (b): a fuzzer holding no private key material forged a passing verdict.
    throw new Error(
      'VERIFICATION BYPASS: verifyBadge() returned ' + verdict.verdict + ' (expected INVALID) ' +
      'for fuzzer-generated input with no genuine Ed25519 signature -- input: ' +
      JSON.stringify(parsed).slice(0, 500)
    );
  }
}
