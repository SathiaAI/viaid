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
// Fail-closed shape for a badge verifyBadgeInner() couldn't even get through (crashed on
// malformed/hostile input, or wasn't even a plain object) — same keys as a normal verdict, so
// callers (CLI, verify-page renderer) never have to special-case a crash vs. a genuine INVALID.
// SAT-1009: fuzzing this entry point showed it threw uncaught on adversarial-but-JSON-decodable
// input (`null`, a badge with a non-array `.log`, `evidence.confirmed_profiles` present but not
// an array, ...) instead of failing cleanly. Mirrors the equivalent guard already reviewed and
// shipped in skill/src/agentid.mjs's verifyBadge()/verifyBadgeInner() split (its own SAT-958
// adversarial-review pass) — that fix was never ported to this copy; this closes that gap here.
function invalidVerdict(reason) {
  return {
    verdict: 'INVALID', agent_id: null, assurance_tier: null,
    coverage: 'no evaluation attached (identity + log only)',
    scope_note: 'This verdict attests identity, signatures, and log integrity — not the safety, correctness, or compliance of the agent.',
    confirmed_profiles: [], downgraded_profiles: [],
    key_seq: 0, last_rotation_reason: null, last_rotation_at: null,
    freshness_state: 'INVALID',
    steps: [{ step: 'verify', status: 'FAIL', detail: reason }],
  };
}

export function verifyBadge(badge) {
  if (!badge || typeof badge !== 'object') return invalidVerdict('badge JSON must be an object');
  try {
    return verifyBadgeInner(badge);
  } catch (e) {
    return invalidVerdict('verify crashed on malformed/hostile input: ' + (e && e.message ? e.message : String(e)));
  }
}

function verifyBadgeInner(badge) {
  const steps = [];
  const push = (step, ok, detail) => steps.push({ step, status: ok ? 'PASS' : 'FAIL', detail });
  const inc = badge.inception || {};

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
  const rotationEntries = (badge.log || []).filter((e) => e.action === 'ROTATION' || e.action === 'COMPROMISE_ROTATION');
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
  let chainOk = true, prev = 'GENESIS';
  for (const e of badge.log) {
    const { entry_hash, ...body } = e;
    const expect = sha256(prev + '\n' + canonical(body));
    if (expect !== entry_hash || body.prev_hash !== prev) { chainOk = false; break; }
    prev = entry_hash;
  }
  push('log hash-chain intact', chainOk, `${badge.log.length} entries`);

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
