// VIA ID — AgentID / badge core (thin prototype).
// The badge = a 3-key signed file (Owner + Agent + VIA ID voucher, Ed25519)
// + a tamper-evident, hash-chained Log. KERI-style: agent_id = hash of the
// inception event, so it is immutable across key rotation (D-15).
//
// CLAIM DISCIPLINE (security-relevant, never soften):
//  - "tamper-evident" (if it's changed, it shows) — NEVER "tamper-proof".
//  - verify returns an honest verdict + coverage + assurance tier — it proves
//    what passed through the recorder, never "everything the agent did".
//  - kill = revoke + gate-refuse (handled in the KnoSky adapter), never remote-terminate.
//
// Prototype-only shortcut: private keys are written to a local .keys/ store so
// the CLI can re-sign. In production the Owner/Agent hold their own keys and the
// VIA ID voucher key lives in a KMS/HSM — the badge file itself never holds a private key.
//
// D-15 (key rotation, this file) — schema notes:
//  - `inception` is HASHED into `agent_id` and must never change after mint. So the two
//    fields that legitimately change on rotation — `key_seq` and `next_key_commitment` —
//    live in TWO places: a frozen genesis snapshot inside `inception` (seq 0's values,
//    kept for history/verification) and a live, top-level `badge.key_seq` /
//    `badge.next_key_commitment` that `rotateKey()` advances. `badge.keys.agent_pub` IS
//    the frozen list's "current_key" — reused rather than duplicated.
//  - `badge_ttl` (seconds) and `inception.issued_at` are additions not named verbatim in
//    D-15's frozen-field list but required to make `badge_ttl` computable at all (STALE is
//    a function of "how long since issuance", which needs an issuance timestamp). Frozen at
//    mint time for v1 — re-issuing a longer TTL is an Act-2 concern, not built here.
//  - `voucher_attestation` is a PER-ROTATION-EVENT signature (voucher key over that one
//    rotation's detail), not just reliance on the whole-badge `signatures.voucher_sig`. This
//    lets a single rotation event be checked/disclosed independently of the rest of the badge
//    and is what the "forged rotation without voucher co-sign" adversarial probe targets.
//  - `COMPROMISE_ROTATION` records `suspected_since` but does not itself auto-discount prior
//    log entries — v1 surfaces the compromise window in `verify()`'s `scope_note` so a human/
//    downstream tool can decide what to discount, rather than guessing a discounting policy.

import { generateKeyPairSync, sign as edSign, verify as edVerify, createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';

const SCHEMA = 'viaid.badge/0.1';
const DEFAULT_BADGE_TTL_SECONDS = 90 * 24 * 3600; // 90 days

// ---- canonical JSON (stable key order) so hashes/signatures are reproducible ----
export function canonical(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonical).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
}
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

// ---- Ed25519 helpers ----
function genKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  };
}
function signB64(privB64, msg) {
  const key = createPrivateKey({ key: Buffer.from(privB64, 'base64'), format: 'der', type: 'pkcs8' });
  return edSign(null, Buffer.from(msg), key).toString('base64');
}
function verifyB64(pubB64, msg, sigB64) {
  try {
    const key = createPublicKey({ key: Buffer.from(pubB64, 'base64'), format: 'der', type: 'spki' });
    return edVerify(null, Buffer.from(msg), key, Buffer.from(sigB64, 'base64'));
  } catch { return false; }
}

// ---- keystore (PROTOTYPE ONLY) ----
// SAT-957 (CRITICAL, fixed here to match VIAID-LOCKED/prototype and skill copies, 2026-08-02):
// this file previously wrote the keystore with no restrictive file mode (0644/world-readable).
// Fixed: request 0600 at create time AND force it with an explicit chmodSync afterward, since
// writeFileSync's `mode` option only governs permissions at file CREATION and is silently
// ignored for a pre-existing file written before this fix. Honest disclosure (ported from the
// other two copies' comment): meaningful protection on Linux/macOS (POSIX bits), but does NOT
// by itself achieve equivalent protection on Windows, where NTFS ACLs govern real access control.
function keystorePath(root, agentId) { return join(root, '.keys', agentId + '.json'); }
function saveKeys(root, agentId, keys) {
  const p = keystorePath(root, agentId);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(keys, null, 2), { mode: 0o600 });
  chmodSync(p, 0o600);
}
function loadKeys(root, agentId) {
  return JSON.parse(readFileSync(keystorePath(root, agentId), 'utf8'));
}

// The three signatures cover the badge core (everything except `.signatures`).
function coreForSigning(badge) {
  const { signatures, ...core } = badge;
  return canonical(core);
}
function resign(badge, keys) {
  const msg = coreForSigning(badge);
  badge.signatures = {
    owner_sig: signB64(keys.owner.priv, msg),
    agent_sig: signB64(keys.agent.priv, msg),
    voucher_sig: signB64(keys.voucher.priv, msg),
  };
  return badge;
}

// ---- mint a badge (viaid init) ----
export function mintBadge({ name, owner = 'local-dev', workRoot, badge_ttl = DEFAULT_BADGE_TTL_SECONDS }) {
  const owner_k = genKeypair(), agent_k = genKeypair(), voucher_k = genKeypair();
  const next_k = genKeypair(); // pre-rotation: commit to the NEXT agent key now (D-15)
  const inception = {
    schema: SCHEMA,
    name,
    owner_id: owner,
    owner_pub: owner_k.pub,
    agent_pub: agent_k.pub,
    voucher_pub: voucher_k.pub,
    next_key_commitment: sha256(next_k.pub), // rotate later without changing agent_id
    key_seq: 0,
    issued_at: new Date().toISOString(),     // needed so badge_ttl can be evaluated (D-15)
    badge_ttl,                               // seconds; frozen at mint for v1
  };
  // KERI-style: the id IS the hash of the inception event → immutable across rotation.
  const agent_id = 'via_' + sha256(canonical(inception)).slice(0, 32);

  let badge = {
    schema: SCHEMA,
    agent_id,
    inception,
    keys: { owner_pub: owner_k.pub, agent_pub: agent_k.pub, voucher_pub: voucher_k.pub }, // agent_pub = "current_key"
    key_seq: 0,                             // live pointer, advances on rotation (inception.key_seq stays the genesis snapshot)
    next_key_commitment: inception.next_key_commitment, // live pointer, replaced on rotation
    last_rotation_reason: null,
    last_rotation_at: null,
    assurance_tier: 'SELF',                 // SELF | WITNESSED | HARDWARE (prototype = SELF)
    revocation_state: 'FRESH',              // stored assertion: FRESH | REVOKED (STALE/UNKNOWN are computed at verify time, see below)
    evidence: null,                         // filled by the GraphSmith eval adapter
    log: [],                                // tamper-evident, hash-chained
    created_note: 'A badge is evidence, not a safety or compliance guarantee.',
  };
  const keys = {
    owner: owner_k, agent: agent_k, voucher: voucher_k,
    next_agent: next_k,
  };
  badge = resign(badge, keys);
  saveKeys(workRoot, agent_id, keys);
  return badge;
}

// ---- WITNESSED tier: mint (viaid init --witnessed) — SAT-958 fix, ported from
// viaid-locked/prototype/src/agentid.mjs (canonical, SAT-933/934, merged 2026-08-01). Gives
// holders of this published package an actual path to close the SAT-958 SELF-tier gap
// disclosed in verifyBadge()'s scope_note below — not previously available here.
//
// POST-REVIEW FIX (adversarial review, 2026-08-08): a non-numeric override (e.g. "10s") used to
// silently collapse the timeout to ~0ms -- `Number("10s") === NaN`, and `setTimeout(fn, NaN)`
// fires on (almost) the next tick, not after the documented 10s default. Validated here instead
// of trusting the env var directly. Exported as a pure function so the parsing rule has a direct
// regression test, independent of module-load env var timing.
//
// POST-REVIEW FIX (2nd round): an *oversized* override (e.g. a typo'd extra zero) had the exact
// same silent-collapse failure mode from the OTHER direction -- Node's setTimeout silently clamps
// any delay above 2^31-1ms (~24.8 days) down to ~1ms rather than erroring, so a value like
// "9999999999" passed the original validation (finite, positive) and still collapsed to an
// effectively-zero timeout. Capped at a generous-but-sane 5 minutes for an HTTP request timeout --
// well under Node's hard clamp, and long enough that no legitimate caller needs more.
const MAX_WITNESS_HTTP_TIMEOUT_MS = 5 * 60 * 1000;
export function parseWitnessTimeoutMs(raw, fallbackMs = 10000) {
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 && parsed <= MAX_WITNESS_HTTP_TIMEOUT_MS ? parsed : fallbackMs;
}
const WITNESS_HTTP_TIMEOUT_MS = parseWitnessTimeoutMs(process.env.VIAID_WITNESS_TIMEOUT_MS);

// Single swap point, per the commitment made when this shipped (2026-08-01): the only
// production default hardcoded in this file. Once a custom domain (e.g. witness.viaid.ai) is
// live, change ONLY this line (or set VIAID_WITNESS_URL) — nothing else here needs to change.
const WITNESS_SERVICE_URL = process.env.VIAID_WITNESS_URL || 'https://witness.viaid.ai';

// POST-REVIEW FIX (2nd round): no scheme was ever checked on the witness service URL -- an
// http:// override (env var typo, stale example copy-pasted from docs) would silently send real
// owner_sig/voucher_sig signatures and the full inception object (name, owner_id, public keys)
// over plaintext, MITM-able. http:// stays allowed only for localhost/127.0.0.1/::1 (the
// standard "point this at a local dev server" convention, and what this repo's own tests use);
// everything else must be https:.
const WITNESS_URL_LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1']);
function assertSafeWitnessUrl(url) {
  let parsed;
  try { parsed = new URL(url); } catch {
    throw new Error(`invalid witness service URL "${url}"`);
  }
  const isSafe = parsed.protocol === 'https:'
    || (parsed.protocol === 'http:' && WITNESS_URL_LOCAL_HOSTNAMES.has(parsed.hostname));
  if (!isSafe) {
    throw new Error(`refusing non-HTTPS witness service URL "${url}" — only https:, or http: to localhost/127.0.0.1 for local development, are allowed here (this call would otherwise send signed registration data or revocation queries over plaintext)`);
  }
  return url;
}

// Mirrors viaid-witness's lib/witness.mjs `registrationAttestationMessage(agent_id, owner_pub,
// voucher_pub)` BYTE FOR BYTE — same canonical() algorithm (this file's canonical() is the same
// stable-key-order implementation the witness service copies from viaid-web/lib/agentid-core.mjs),
// same field set. The server recomputes and checks this exact message; any drift here makes
// every owner_sig/voucher_sig fail server-side verification.
function registrationAttestationMessage(agentId, ownerPub, voucherPub) {
  return canonical({ purpose: 'witness_registration', agent_id: agentId, owner_pub: ownerPub, voucher_pub: voucherPub });
}

export async function mintWitnessedBadge(opts) {
  const witnessServiceUrl = (opts && opts.witnessServiceUrl) || WITNESS_SERVICE_URL;
  assertSafeWitnessUrl(witnessServiceUrl); // fail before doing any work, not after minting

  // Step 1: mint exactly as SELF-tier, via the existing unchanged path — same inception, same
  // agent_id derivation, same keystore write. No new failure surface introduced here.
  const badge = mintBadge(opts);
  const keys = loadKeys(opts.workRoot, badge.agent_id);

  // Step 2: sign the registration attestation with the REAL owner/voucher private keys — never
  // agent (matches REVOKE_ROLE_PUB_FIELD's established "agent never self-attests a mutation").
  const msg = registrationAttestationMessage(badge.agent_id, badge.inception.owner_pub, badge.inception.voucher_pub);
  const owner_sig = signB64(keys.owner.priv, msg);
  const voucher_sig = signB64(keys.voucher.priv, msg);

  // Step 3: register with the witness service. Fail-closed — see header comment.
  //
  // PRIVACY NOTE (post-review disclosure fix): `inception` — including `name` and `owner_id` —
  // is sent to the witness service IN FULL, deliberately. The server independently recomputes
  // agent_id = hash(canonical(inception)) (viaid-witness's lib/witness.mjs registerAgent()) to
  // bind the registration to a caller-unforgeable id; withholding any inception field would make
  // the server's recomputed agent_id diverge from this badge's real one. There is no way to
  // minimize this payload without changing that hash-binding protocol on the server side too
  // (out of scope here). Only reached when the caller explicitly opts into WITNESSED tier (viaid
  // init --witnessed) — never on the default SELF-tier mint path. Logged so this is visible at
  // the point of action, not just in a comment.
  console.warn(`[viaid:witness] mint: registering with ${witnessServiceUrl} — this sends the full inception object (including name, owner_id) to a third party.`);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), WITNESS_HTTP_TIMEOUT_MS);
  let res, body = null;
  try {
    try {
      res = await fetch(`${witnessServiceUrl}/api/witness-register`, {
        method: 'POST',
        signal: ctrl.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ inception: badge.inception, owner_sig, voucher_sig }),
      });
    } catch (e) {
      throw new Error(`WITNESSED mint failed: witness-register request to ${witnessServiceUrl} errored — ${e.message}`);
    }
    // POST-REVIEW FIX: the body read now happens INSIDE the same timer-protected scope. Previously
    // clearTimeout() ran right after fetch() resolved (headers only), so a response that stalled
    // mid-body could hang this call forever. A stalled body now hits the same abort signal and
    // fails closed, matching this function's own "fail-closed" contract; a non-JSON body on an
    // otherwise-OK response stays lenient (body just stays null), same as before.
    try {
      body = await res.json();
    } catch {
      if (ctrl.signal.aborted) {
        throw new Error(`WITNESSED mint failed: witness-register request to ${witnessServiceUrl} timed out reading the response body after ${WITNESS_HTTP_TIMEOUT_MS}ms`);
      }
    }
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    throw new Error(`WITNESSED mint failed: witness-register returned HTTP ${res.status}${body && body.error ? ` — ${body.error}` : ''}`);
  }

  // Step 4: only NOW claim WITNESSED — re-sign the whole badge core so the tier change itself is
  // covered by the same whole-badge signature every other field already is.
  badge.assurance_tier = 'WITNESSED';
  return resign(badge, keys);
}

// ---- append a hash-chained log entry (viaid log) ----
export function appendLog(badge, workRoot, { action, model_used = null, detail = null }) {
  const prev_hash = badge.log.length ? badge.log[badge.log.length - 1].entry_hash : 'GENESIS';
  const body = { seq: badge.log.length, action, model_used, detail, prev_hash };
  const entry = { ...body, entry_hash: sha256(prev_hash + '\n' + canonical(body)) };
  badge.log.push(entry);
  return resign(badge, loadKeys(workRoot, badge.agent_id));
}

// ---- rotate the agent key (viaid rotate) — KERI-style pre-rotation, D-15 ----
// reason: free-text ('routine', 'scheduled', ...). Pass compromisedSince (ISO string) to
// emit a COMPROMISE_ROTATION event instead of a plain ROTATION event.
export function rotateKey(badge, workRoot, { reason = 'routine', compromisedSince = null } = {}) {
  const keys = loadKeys(workRoot, badge.agent_id);
  const revealedNext = keys.next_agent;
  if (!revealedNext) throw new Error('no pre-committed next key in the keystore — cannot rotate');

  const priorCommitment = badge.next_key_commitment;
  if (sha256(revealedNext.pub) !== priorCommitment) {
    // Keystore/badge got out of sync — refuse rather than mint an unverifiable rotation.
    throw new Error('pre-committed next key does not match next_key_commitment — rotation aborted');
  }

  const newNext = genKeypair(); // pre-commit to the FOLLOWING rotation now
  const isCompromise = !!compromisedSince;
  const detail = {
    prev_key_seq: badge.key_seq,
    new_key_seq: badge.key_seq + 1,
    revealed_next_pub: revealedNext.pub,        // fulfills the prior commitment
    prior_commitment: priorCommitment,
    new_next_key_commitment: sha256(newNext.pub),
    reason,
    ...(isCompromise ? { suspected_since: compromisedSince } : {}),
  };
  // Per-event voucher attestation — independent of the whole-badge resign below, so a single
  // rotation event can be checked/disclosed on its own (D-15's "voucher-witnessed" requirement).
  const voucher_attestation = signB64(keys.voucher.priv, canonical(detail));

  const prev_hash = badge.log.length ? badge.log[badge.log.length - 1].entry_hash : 'GENESIS';
  const body = {
    seq: badge.log.length,
    action: isCompromise ? 'COMPROMISE_ROTATION' : 'ROTATION',
    model_used: null,
    detail,
    voucher_attestation,
    prev_hash,
  };
  const entry = { ...body, entry_hash: sha256(prev_hash + '\n' + canonical(body)) };
  badge.log.push(entry);

  // Advance the live pointers. inception.key_seq/next_key_commitment are left untouched —
  // they're the frozen genesis snapshot inception hashes into agent_id.
  badge.keys.agent_pub = revealedNext.pub;
  badge.key_seq = detail.new_key_seq;
  badge.next_key_commitment = detail.new_next_key_commitment;
  badge.last_rotation_reason = reason;
  badge.last_rotation_at = new Date().toISOString();

  // Rotate the keystore: the old "next" key becomes the current signing key; mint a fresh "next".
  keys.agent = revealedNext;
  keys.next_agent = newNext;
  saveKeys(workRoot, badge.agent_id, keys);

  return resign(badge, keys);
}

// ---- attach GraphSmith evidence (viaid eval) ----
export function attachEvidence(badge, workRoot, evidence) {
  badge.evidence = evidence; // { engine, status, confirmed_profiles, downgraded_profiles, note, evaluated_at_source }
  // Evidence raises the assurance the verdict can claim, but only what the evidence supports.
  return resign(badge, loadKeys(workRoot, badge.agent_id));
}

// ---- revoke (viaid revoke) — badge-side state; the gate-refuse lives in the KnoSky adapter ----
export function revokeBadge(badge, workRoot, reason = 'revoked') {
  badge.revocation_state = 'REVOKED';
  badge.revoked_reason = reason;
  return resign(badge, loadKeys(workRoot, badge.agent_id));
}

// ---- verify (viaid verify / scan) → honest verdict ----
// POST-REVIEW FIX (3rd round, caught by live CLI smoke-test rather than by review): the 2nd
// internal-use-only parameter below defaults to false for every existing external caller
// (verifyBadge(badge) is unchanged) — it exists solely so verifyBadgeWitnessed() below can ask
// this function for the base verdict WITHOUT the "did not perform the online witness lookup"
// sentence, which verifyBadgeWitnessed() is about to immediately supersede with the real
// outcome. See the call site in verifyBadgeWitnessed() for why leaving it in produced
// self-contradictory text like "...did not perform the online witness lookup... The witness
// service independently confirms no revocation is on record...".
export function verifyBadge(badge, opts) {
  // POST-REVIEW FIX (4th round): two crash bugs, same class as ones already fixed elsewhere in
  // this file but never mirrored onto this function specifically:
  //  (a) this function threw on a null/undefined `badge` instead of returning a verdict — in
  //      fact verifyBadgeWitnessed()'s OWN null-guard above exists specifically because calling
  //      this function with a bad badge used to throw (see its comment); the workaround there
  //      never fixed the root cause here, so any OTHER caller (the CLI, or a library consumer)
  //      calling verifyBadge() directly on a null/malformed badge still crashed.
  //  (b) `{ ... } = {}` default-parameter destructuring only applies to `undefined`, not an
  //      explicit `null` second argument — same bug already fixed on verifyBadgeWitnessed().
  const { _witnessedDisclosureHandledByCaller = false } = opts || {};
  if (!badge || typeof badge !== 'object') {
    return {
      verdict: 'INVALID', agent_id: undefined, assurance_tier: undefined,
      coverage: 'no evaluation attached (identity + log only)',
      scope_note: 'badge is missing or not an object — cannot verify.',
      confirmed_profiles: [], downgraded_profiles: [],
      key_seq: 0, last_rotation_reason: null, last_rotation_at: null,
      freshness_state: 'UNKNOWN', steps: [],
    };
  }
  const steps = [];
  const push = (step, ok, detail) => steps.push({ step, status: ok ? 'PASS' : 'FAIL', detail });
  const inc = badge.inception || {};
  // POST-REVIEW FIX (4th round): `badge.log || []` is a TRUTHY test, not a type test — a
  // malformed badge with `.log` set to a non-array truthy value (e.g. `{}`) sailed through
  // unchanged and crashed the very next `.filter()`/`for...of` call ("is not a function" / "is
  // not iterable"). Normalized ONCE here (Array.isArray, not `||`) and reused below instead of
  // three separate `badge.log || []` guards, one of which (the rotation-entries filter) still had
  // this exact bug. Each entry is also guarded for object-shape before being read/destructured,
  // since a log ARRAY containing a non-object entry (e.g. `[null]`) crashed the same way one line
  // later even after the array-vs-not check.
  const log = Array.isArray(badge.log) ? badge.log : [];

  // 1. id integrity: recompute agent_id from the inception event.
  const recomputed = 'via_' + sha256(canonical(inc)).slice(0, 32);
  push('agent_id == hash(inception)', recomputed === badge.agent_id, `${recomputed}`);

  // 2a. owner + voucher keys never rotate in v1 — must stay exactly as pinned by inception.
  const ownerVoucherBound =
    badge.keys?.owner_pub === inc.owner_pub &&
    badge.keys?.voucher_pub === inc.voucher_pub;
  push('owner/voucher keys bound to inception', ownerVoucherBound, ownerVoucherBound ? '' : 'keys.{owner,voucher}_pub != inception.*_pub');

  // 2b. the agent key CAN rotate — walk the ROTATION/COMPROMISE_ROTATION log events and confirm
  // an unbroken chain from the inception commitment to the badge's current live pointers. This
  // defeats: forged rotation w/o voucher co-sign, replayed rotation, wrong key_seq.
  let seq = inc.key_seq ?? 0;
  let commitment = inc.next_key_commitment;
  let currentKey = inc.agent_pub;
  let rotationChainOk = true;
  let compromisedSince = null;
  const rotationEntries = log.filter((e) => e && (e.action === 'ROTATION' || e.action === 'COMPROMISE_ROTATION'));
  for (const e of rotationEntries) {
    const d = e.detail || {};
    const attestationOk = verifyB64(inc.voucher_pub, canonical(d), e.voucher_attestation || '');
    const ok =
      d.prev_key_seq === seq &&
      d.new_key_seq === seq + 1 &&
      d.prior_commitment === commitment &&
      sha256(d.revealed_next_pub || '') === commitment &&
      attestationOk;
    if (!ok) { rotationChainOk = false; break; }
    if (e.action === 'COMPROMISE_ROTATION') compromisedSince = d.suspected_since || null;
    seq = d.new_key_seq; commitment = d.new_next_key_commitment; currentKey = d.revealed_next_pub;
  }
  if (rotationChainOk) {
    const topKeySeq = badge.key_seq ?? inc.key_seq ?? 0;
    const topCommitment = badge.next_key_commitment ?? inc.next_key_commitment;
    rotationChainOk = currentKey === badge.keys?.agent_pub && seq === topKeySeq && commitment === topCommitment;
  }
  push('key rotation chain intact', rotationChainOk, `${rotationEntries.length} rotation event(s), key_seq=${seq}`);

  const keysBound = ownerVoucherBound && rotationChainOk;

  // 3. the three signatures — verified against the current (post-rotation) keys.
  const msg = coreForSigning(badge);
  let sigOk = true;
  try {
    const s = badge.signatures || {};
    const o = verifyB64(inc.owner_pub, msg, s.owner_sig || '');
    const a = verifyB64(badge.keys?.agent_pub, msg, s.agent_sig || '');
    const v = verifyB64(inc.voucher_pub, msg, s.voucher_sig || '');
    sigOk = keysBound && o && a && v;
    push('owner signature', o, '');
    push('agent signature', a, '');
    push('voucher signature', v, '');
  } catch (e) { sigOk = false; push('signatures', false, e.message); }

  // 4. hash-chain of the log (tamper-evident) — covers rotation entries too (generic over body).
  // POST-REVIEW FIX (2nd round): `badge.log` was iterated directly with no fallback (missing
  // `.log` entirely, e.g. `{}` or `[]`, crashed with "undefined is not iterable"). POST-REVIEW FIX
  // (4th round): the `|| []` fallback used above only caught a MISSING log, not a present-but-
  // wrong-shape one — `log` (computed above) is now type-checked once, and each entry is checked
  // for object-shape before being destructured, since a `[null]` log crashed here too.
  let chainOk = true, prev = 'GENESIS';
  for (const e of log) {
    if (!e || typeof e !== 'object') { chainOk = false; break; }
    const { entry_hash, ...body } = e;
    const expect = sha256(prev + '\n' + canonical(body));
    if (expect !== entry_hash || body.prev_hash !== prev) { chainOk = false; break; }
    prev = entry_hash;
  }
  push('log hash-chain intact', chainOk, `${log.length} entries`);

  // 5. offline freshness/revocation state. `revocation_state` is a STORED assertion (only ever
  // FRESH or REVOKED — an issuer explicitly revokes). STALE/UNKNOWN are COMPUTED at verify time:
  // STALE = structurally fine but badge_ttl has elapsed since issuance (can't be re-confirmed
  // offline); UNKNOWN = badge predates badge_ttl/issued_at (legacy/malformed) so freshness can't
  // be evaluated at all. (D-15 offline states: FRESH / STALE / REVOKED / UNKNOWN.)
  const issuedAtMs = inc.issued_at ? Date.parse(inc.issued_at) : NaN;
  const ttlMs = typeof inc.badge_ttl === 'number' ? inc.badge_ttl * 1000 : NaN;
  let offline_state;
  if (badge.revocation_state === 'REVOKED') offline_state = 'REVOKED';
  else if (!Number.isFinite(issuedAtMs) || !Number.isFinite(ttlMs)) offline_state = 'UNKNOWN';
  else if (Date.now() - issuedAtMs > ttlMs) offline_state = 'STALE';
  else offline_state = 'FRESH';
  push('freshness / revocation state', offline_state === 'FRESH', offline_state);

  const structurally_valid = recomputed === badge.agent_id && sigOk && chainOk;
  const verdict = !structurally_valid ? 'INVALID'
    : offline_state === 'REVOKED' ? 'REVOKED'
    : offline_state === 'STALE' ? 'STALE'
    : offline_state === 'UNKNOWN' ? 'UNKNOWN'
    : 'VALID';

  // coverage + assurance tier — honest scope, never "everything the agent did".
  const ev = badge.evidence;
  const coverage = ev
    ? `GraphSmith eval: ${ev.status}; confirmed profiles [${(ev.confirmed_profiles || []).join(', ') || 'none'}]`
    : 'no evaluation attached (identity + log only)';
  const assurance_tier = badge.assurance_tier; // SELF here
  let scope_note = ev?.note
    || 'This verdict attests identity, signatures, and log integrity — not the safety, correctness, or compliance of the agent.';
  // SAT-930/SAT-958: honesty fix — a SELF-tier VALID/non-REVOKED verdict must not read as a
  // stronger guarantee than it is. Only the ONLINE witness check (Wave 0) can close this;
  // until a badge is WITNESSED/HARDWARE tier, say so plainly. Ported from viaid-locked's
  // prototype/src/agentid.mjs (canonical).
  if (assurance_tier === 'SELF') {
    scope_note += " SELF-tier revocation is not externally witnessed — a holder of this badge's raw JSON could locally suppress a revocation event, and this verifier cannot detect that.";
  } else if (assurance_tier === 'WITNESSED' && !_witnessedDisclosureHandledByCaller) {
    // POST-REVIEW FIX: this synchronous verifyBadge() never performs the online witness check
    // (only verifyBadgeWitnessed() does) -- previously a WITNESSED-tier badge verified through
    // THIS function alone got zero disclosure of that, so every pre-existing caller (e.g. the
    // CLI's `viaid verify`, which calls verifyBadge() directly) silently got a verdict no
    // stronger than SELF-tier while the badge itself claimed a higher tier.
    scope_note += ' This badge claims WITNESSED tier, but this synchronous check did not perform the online witness lookup — call verifyBadgeWitnessed() to independently confirm revocation status; absent that call, this verdict relies on local-log-only semantics, same as a SELF-tier badge.';
  }
  if (compromisedSince) {
    scope_note += ` Note: a COMPROMISE_ROTATION event flags key material suspected compromised since ${compromisedSince} — log entries in that window should be discounted by the reader, not treated as trusted.`;
  }

  return {
    verdict, agent_id: badge.agent_id, assurance_tier, coverage, scope_note,
    confirmed_profiles: ev?.confirmed_profiles || [],
    downgraded_profiles: ev?.downgraded_profiles || [], // shown grey, never green
    key_seq: badge.key_seq ?? inc.key_seq ?? 0,
    last_rotation_reason: badge.last_rotation_reason ?? null,
    last_rotation_at: badge.last_rotation_at ?? null,
    // computed FRESH/STALE/REVOKED/UNKNOWN (D-15) — the UI should read THIS, not the stored
    // badge.revocation_state field directly, since STALE/UNKNOWN only ever exist as a function
    // of "now", never as a value written into the badge itself.
    freshness_state: offline_state,
    steps,
  };
}

// ---- WITNESSED tier: verify (viaid verify, when badge.assurance_tier === 'WITNESSED') —
// SAT-958 fix. Independently confirms revocation status with witness.viaid.ai, which a
// locally-doctored (truncated) log copy cannot spoof — this is what actually closes the
// SELF-tier gap disclosed in verifyBadge()'s scope_note above. Ported from viaid-locked/
// prototype/src/agentid.mjs (canonical).
export async function verifyBadgeWitnessed(badge, opts) {
  // POST-REVIEW FIX (2nd round): default-parameter destructuring (`{ ... } = {}`) only kicks in
  // for `undefined`, NOT `null` — `verifyBadgeWitnessed(badge, null)` crashed on
  // "Cannot destructure property 'checkWitness' of 'null'" before even reaching the badge guard
  // below. Normalized here instead, so both an omitted and an explicit-null options argument work.
  const { checkWitness = true, witnessServiceUrl } = opts || {};
  // POST-REVIEW FIX: the `tier` guard below used to run AFTER `verifyBadge(badge)`, so a
  // null/non-object badge threw inside verifyBadge() before the guard was ever reached, making
  // the guard dead code. Checked first now, and returns a verdict shape consistent with every
  // other return path in this function (never throws for a bad `badge` argument).
  if (!badge || typeof badge !== 'object') {
    return {
      verdict: 'INVALID', agent_id: undefined, assurance_tier: undefined,
      coverage: 'no evaluation attached (identity + log only)',
      scope_note: 'badge is missing or not an object — cannot verify.',
      confirmed_profiles: [], downgraded_profiles: [],
      key_seq: 0, last_rotation_reason: null, last_rotation_at: null,
      freshness_state: 'UNKNOWN', steps: [],
      witness_state: 'NOT_APPLICABLE',
    };
  }
  // _witnessedDisclosureHandledByCaller: true — every return path below (SKIPPED/UNREACHABLE/
  // CHECKED_REVOKED/CHECKED_CLEAN) appends its own precise, accurate account of what the online
  // check actually did; the generic "did not perform the online witness lookup" sentence
  // verifyBadge() would otherwise add is stale the instant that check runs, and self-
  // contradictory once it succeeds (see the POST-REVIEW FIX comment on verifyBadge() above).
  const verdict = verifyBadge(badge, { _witnessedDisclosureHandledByCaller: true });
  const tier = badge.assurance_tier;

  if (tier !== 'WITNESSED') {
    return { ...verdict, witness_state: 'NOT_APPLICABLE' };
  }
  if (!checkWitness) {
    return {
      ...verdict, witness_state: 'SKIPPED',
      scope_note: `${verdict.scope_note} The online witness check was explicitly skipped for this verify call — this verdict relies on local-log-only semantics, same as a SELF-tier badge.`,
    };
  }

  // POST-REVIEW FIX: a witness-check FAILURE used to return the exact same top-level `verdict`
  // as a genuine online confirmation would (only the easy-to-miss `witness_state` field
  // differed) — so an attacker who could merely block network access to the witness service
  // could force every WITNESSED verify call into the fallback path while it still read as fully
  // verified to any caller that only checks `.verdict`. INVALID/REVOKED are already the worst
  // realistic states and are never masked further; VALID/STALE downgrade to UNKNOWN because the
  // one check that matters most for this tier could not be completed.
  const fallbackVerdict = (verdict.verdict === 'INVALID' || verdict.verdict === 'REVOKED') ? verdict.verdict : 'UNKNOWN';

  const url = witnessServiceUrl || WITNESS_SERVICE_URL;
  // POST-REVIEW FIX (2nd round): no scheme was checked here either — same plaintext-exposure risk
  // as mintWitnessedBadge(), but verify()'s established contract is "never throw, always return a
  // verdict" (see the badge-shape guard above), so an unsafe URL is treated as just another
  // UNREACHABLE-equivalent fallback rather than a thrown exception, and the network call is never
  // attempted at all.
  try {
    assertSafeWitnessUrl(url);
  } catch (e) {
    console.warn(`[viaid:witness] verify fallback: ${e.message}`);
    return {
      ...verdict, verdict: fallbackVerdict, witness_state: 'UNREACHABLE',
      scope_note: `${verdict.scope_note} The online witness check was skipped — ${e.message} — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.`,
    };
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), WITNESS_HTTP_TIMEOUT_MS);
  let res, body;
  try {
    try {
      res = await fetch(`${url}/api/witness-status?agent_id=${encodeURIComponent(verdict.agent_id || badge.agent_id || '')}`, { signal: ctrl.signal });
    } catch (e) {
      console.warn(`[viaid:witness] verify fallback: witness service unreachable at ${url} (${e.message}) — agent_id=${badge.agent_id || 'unknown'}`);
      return {
        ...verdict, verdict: fallbackVerdict, witness_state: 'UNREACHABLE',
        scope_note: `${verdict.scope_note} The online witness check was attempted but the witness service was unreachable — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.`,
      };
    }
    if (!res.ok) {
      console.warn(`[viaid:witness] verify fallback: witness service returned HTTP ${res.status} at ${url} — agent_id=${badge.agent_id || 'unknown'}`);
      return {
        ...verdict, verdict: fallbackVerdict, witness_state: 'UNREACHABLE',
        scope_note: `${verdict.scope_note} The online witness check was attempted but the witness service returned HTTP ${res.status} — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.`,
      };
    }
    // POST-REVIEW FIX: the body read now happens INSIDE the same timer-protected try block.
    // Previously clearTimeout() ran (in a `finally` around only the fetch() call) before this
    // read, so a response that stalled mid-body — headers arrive, body never completes — could
    // hang this call forever, bypassing the configured timeout entirely.
    try {
      body = await res.json();
    } catch (e) {
      const reason = ctrl.signal.aborted
        ? `timed out reading the response body after ${WITNESS_HTTP_TIMEOUT_MS}ms`
        : `response was not valid JSON (${e.message})`;
      console.warn(`[viaid:witness] verify fallback: witness service at ${url} ${reason} — agent_id=${badge.agent_id || 'unknown'}`);
      return {
        ...verdict, verdict: fallbackVerdict, witness_state: 'UNREACHABLE',
        scope_note: `${verdict.scope_note} The online witness check was attempted but the witness service's response ${reason} — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.`,
      };
    }
  } finally {
    clearTimeout(timer);
  }

  // POST-REVIEW FIX (2nd round): `body.witnessed === true` correctly escalates and (implicitly)
  // anything else fell through to CHECKED_CLEAN — including a malformed/unexpected response like
  // `{witnessed: "true"}` (string) or `{witnessed: 1}` (number), which strict-`=== true` correctly
  // does NOT match, but which then silently read as a confirmed-clean verdict rather than an
  // ambiguous one. The real service (viaid-witness's getStatus()) only ever returns a genuine JS
  // boolean, so this only bites on a buggy/compromised/misconfigured witness endpoint — but this
  // tier's whole purpose is not trusting a single source blindly, so an unexpected shape is now
  // treated the same as an unreachable service (fail toward UNKNOWN, not toward "looks fine").
  if (body && body.witnessed === true) {
    // OR-only escalation: never downgrade an already-INVALID verdict into looking like a
    // legitimately-signed-then-revoked badge — see the function header comment for why.
    const forcedVerdict = verdict.verdict === 'INVALID' ? verdict.verdict : 'REVOKED';
    return {
      ...verdict, verdict: forcedVerdict, witness_state: 'CHECKED_REVOKED',
      scope_note: `${verdict.scope_note} The witness service independently confirms a revocation (${body.action || 'unknown action'}) is on record for this agent_id — this holds even if the locally-presented badge's own log has been truncated to hide it, closing the SELF-tier log-truncation gap described above.`,
    };
  }
  if (body && body.witnessed === false) {
    return {
      ...verdict, witness_state: 'CHECKED_CLEAN',
      scope_note: `${verdict.scope_note} The witness service independently confirms no revocation is on record for this agent_id — unlike SELF-tier, this is not solely reliant on the locally-presented badge's own (potentially truncated) log.`,
    };
  }
  console.warn(`[viaid:witness] verify fallback: witness service at ${url} returned an unexpected response shape (witnessed=${JSON.stringify(body && body.witnessed)}, expected a boolean) — agent_id=${badge.agent_id || 'unknown'}`);
  return {
    ...verdict, verdict: fallbackVerdict, witness_state: 'UNREACHABLE',
    scope_note: `${verdict.scope_note} The online witness check returned an unexpected response shape (not a boolean \`witnessed\` field) — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.`,
  };
}

export function loadBadge(p) { return JSON.parse(readFileSync(p, 'utf8')); }
export function saveBadge(p, badge) { writeFileSync(p, JSON.stringify(badge, null, 2)); return p; }
export { existsSync };

// Crockford Base32 (no I/L/O/U — avoids exactly the human-typing confusion this exists to
// fix). Pure/stateless — kept identical to viaid-web/lib/agentid-core.mjs's copy (D-23) so
// a short code computed locally by the CLI/skill matches the one the hosted verify page shows.
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export function shortCodeFrom(agentId, len = 7) {
  const h = sha256('shortcode:' + agentId);
  let out = '';
  for (let i = 0; i < len; i++) {
    const byte = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    out += CROCKFORD[byte % 32];
  }
  return out;
}
