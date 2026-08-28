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
//   (b) NO BYPASS. verifyBadge() must never return verdict 'VALID' unless the badge carries
//       three genuine Ed25519 signatures over its own signed core (coreForSigning). Forging one
//       is computationally infeasible for a byte-mutating fuzzer, so any 'VALID' verdict coming
//       out of this harness means a signature/chain check was skipped or short-circuited -- a
//       real verification bypass. (Every seed in corpus/verify-badge/ that is otherwise fully
//       well-formed carries deliberately-garbage `signatures`/`voucher_attestation` values for
//       exactly this reason -- see gen script note in the corpus README.)
//
// Throwing from fuzz() is how Jazzer.js records a finding, so both properties are just: don't
// swallow verifyBadge()'s own exceptions, and explicitly throw if a VALID verdict is observed.
//
// Run: npm run fuzz:verify-badge (time-boxed — see the -max_total_time in that script; a fixed
// duration on purpose, so this can run to completion in CI without hanging indefinitely).
import { verifyBadge } from '../src/agentid.mjs';

// Real badges are small signed JSON documents (a handful of Ed25519 keys/hashes and, typically,
// a short log). Capping the input size keeps the fuzzer inside the realistic badge-file size
// envelope instead of spending its time budget mutating multi-megabyte blobs that no caller of
// loadBadge()/verifyBadge() would ever be handed as a *.badge.json file.
const MAX_INPUT_BYTES = 16384;

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

  if (verdict.verdict === 'VALID') {
    // property (b): a fuzzer holding no private key material forged a passing verdict.
    throw new Error(
      'VERIFICATION BYPASS: verifyBadge() returned VALID for fuzzer-generated input with no ' +
      'genuine Ed25519 signature -- input: ' + JSON.stringify(parsed).slice(0, 500)
    );
  }
}
