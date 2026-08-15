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
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, unlinkSync } from 'node:fs';
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
// Exported (round 6): re-signing a badge after a deliberate field-level mutation is a real,
// legitimate operation this module already performs internally (every rotate/revoke/log/evidence
// call resigns) — tests need the same ability to construct realistic fixtures (e.g. a pre-existing
// badge that predates a newly-added signed field) without duplicating the canonical/signing logic
// inline. This does not expand what's actually possible: a caller must already hold the private
// keys (i.e. already have filesystem access to workRoot/.keys/, the real security boundary this
// file's own header comments describe), so exporting the function that re-signs with keys someone
// already has grants no new capability.
export function loadKeys(root, agentId) {
  return JSON.parse(readFileSync(keystorePath(root, agentId), 'utf8'));
}
// POST-REVIEW FIX (4th round): best-effort cleanup for mintWitnessedBadge()'s rollback path
// below — never let a cleanup failure mask the original, more important error that triggered it.
//
// POST-REVIEW FIX (5th round, reliability-3): a cleanup failure other than ENOENT used to be
// logged via console.warn and then fully discarded — the caller had no programmatic way to know
// private key material might still be sitting on disk. Now returns the cleanup error (or null on
// success/nothing-to-clean-up) so the caller can attach it to the error it's already throwing,
// without changing what that original error's own message/code is.
function removeOrphanedKeys(root, agentId) {
  try {
    unlinkSync(keystorePath(root, agentId));
    return null;
  } catch (e) {
    if (e.code === 'ENOENT') return null; // nothing was ever there to clean up — not a failure
    console.warn(`[viaid:witness] mint failed AND could not clean up the orphaned keystore file for ${agentId} — ${e.message}`);
    return e;
  }
}

// The three signatures cover the badge core (everything except `.signatures`).
function coreForSigning(badge) {
  const { signatures, ...core } = badge;
  return canonical(core);
}
export function resign(badge, keys) {
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

  // POST-REVIEW FIX (5th round, correctness-2 / data_privacy-F1 / SEC-004 — found independently
  // by three reviewers in the round-5 adversarial review): mintBadge() and loadKeys() now run
  // INSIDE the try block below, not before it. Previously they ran before the try, so if
  // loadKeys() threw right after mintBadge() succeeded (e.g. a transient fs error, or a
  // concurrent process racing the keystore write mintBadge()'s internal saveKeys() call had just
  // performed), the catch below was unreachable for that specific failure and the just-written
  // private-key material was never rolled back by removeOrphanedKeys(). `badge` is declared here
  // with `let` so the catch can still reach it for cleanup if it was assigned before the
  // failure, and correctly skip cleanup (there is nothing to orphan) if mintBadge() itself never
  // returned at all.
  let badge;
  try {
    // Step 1: mint exactly as SELF-tier, via the existing unchanged path — same inception, same
    // agent_id derivation, same keystore write. No new failure surface introduced here.
    badge = mintBadge(opts);
    const keys = loadKeys(opts.workRoot, badge.agent_id);

    // POST-REVIEW FIX (4th round): everything from here on can fail (network error, non-2xx,
    // unconfirmed body, timeout) AFTER step 1 has already written real owner/agent/voucher/
    // next-agent PRIVATE KEY material to workRoot/.keys/<agent_id>.json. Previously, any failure
    // below left that keystore file orphaned on disk forever — referenced by no badge (the CLI
    // only ever calls saveBadge() once this function returns successfully), with no command to
    // find or clean it up. Every retry during a witness-service outage silently left another one
    // behind. Wrapped (now including step 1 above too, see 5th-round comment) so any failure
    // below rolls that keystore file back before propagating the real error.
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
          // POST-REVIEW FIX (5th round, SEC-002): fetch() follows redirects by default with no
          // scheme re-validation on the target — a redirect from this HTTPS endpoint to an
          // http:// target would silently defeat assertSafeWitnessUrl()'s plaintext protection
          // above. 'manual' turns a redirect into an opaqueredirect response (status 0, !ok)
          // instead of following it, which the existing `!res.ok` fail-closed check below then
          // correctly rejects — no attacker-controlled destination is ever contacted.
          redirect: 'manual',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ inception: badge.inception, owner_sig, voucher_sig }),
        });
      } catch (e) {
        // POST-REVIEW FIX (decision 2, wave 6): this catch fires for the class of failures that
        // are almost always a network problem on the CALLER's end (DNS failure, connection
        // refused, TLS handshake failure, or the abort firing before headers ever arrive) rather
        // than anything wrong with the badge or the witness service's own logic. Said so plainly
        // -- the generic Error.message is the ONLY thing that reaches the user here (see
        // bin/viaid.mjs's top-level `catch (e) { console.error('✖', e.message); }`), so a person
        // with no way to inspect `e.message`'s cause needs this spelled out, not implied.
        throw new Error(`WITNESSED mint failed: witness-register request to ${witnessServiceUrl} errored — ${e.message}. This usually means a poor or interrupted network connection rather than a problem with your badge — please check your connection and run this command again.`);
      }
      // POST-REVIEW FIX: the body read now happens INSIDE the same timer-protected scope. Previously
      // clearTimeout() ran right after fetch() resolved (headers only), so a response that stalled
      // mid-body could hang this call forever. A stalled body now hits the same abort signal and
      // fails closed, matching this function's own "fail-closed" contract.
      try {
        body = await res.json();
      } catch {
        if (ctrl.signal.aborted) {
          // POST-REVIEW FIX (decision 2, wave 6): a stalled response body is also almost always a
          // connectivity problem, not a badge or witness-service-logic problem -- same rationale
          // as the fetch()-level catch above.
          throw new Error(`WITNESSED mint failed: witness-register request to ${witnessServiceUrl} timed out reading the response body after ${WITNESS_HTTP_TIMEOUT_MS}ms. This usually means a poor or interrupted network connection rather than a problem with your badge — please check your connection and run this command again.`);
        }
        // else: body stays null — no longer silently accepted, see the confirmation check below.
      }
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      throw new Error(`WITNESSED mint failed: witness-register returned HTTP ${res.status}${body && body.error ? ` — ${body.error}` : ''}`);
    }
    // POST-REVIEW FIX (4th round): an HTTP 2xx status alone used to be treated as proof of a
    // successful registration, even with an empty/unparseable body (`body` stays `null` above),
    // `{}` (valid JSON, confirms nothing), or an explicit in-body error signal despite the 2xx
    // transport status. A badge minted after any of these would locally claim WITNESSED tier while
    // the witness service may never have actually stored a record for it, silently breaking the
    // one guarantee this tier exists to provide. `already_registered` is the field this repo's own
    // witness-register contract always returns on genuine success (see this file's and
    // test/cli.witnessed.test.mjs's mocks) — its absence, or an explicit error signal, is now
    // treated as a failed registration rather than silently accepted.
    if (!body || typeof body.already_registered !== 'boolean' || body.error || body.status === 'error') {
      throw new Error(`WITNESSED mint failed: witness-register returned HTTP ${res.status} but did not confirm registration${body && body.error ? ` — ${body.error}` : body ? ` (got ${JSON.stringify(body)})` : ' (empty or unparseable body)'}`);
    }
    // POST-REVIEW FIX (decision 3, wave 6 -- SEC-003, confirmed safe against viaid-witness's real
    // contract before implementing, not assumed): mirrors the existing witness-status agent_id
    // check added in wave 4 (see the matching comment in verifyBadgeWitnessed() below) -- a
    // generic success response with no agent_id, or (in a misconfigured/multi-tenant deployment)
    // someone else's agent_id, was previously still accepted as proof THIS badge was registered.
    // Confirmed against viaid-witness's actual source (2026-08-09, not inferred): registerAgent()
    // (lib/witness.mjs) returns either db.insertRegistration()'s or db.getRegistration()'s row
    // spread with `already_registered`, and BOTH db functions' SQL explicitly
    // RETURNING/SELECT agent_id (lib/db.mjs) -- structurally guaranteed by the query, not just an
    // application-level convention that could silently drift. viaid-witness's own e2e test asserts
    // this directly (test/witness_register.e2e.test.mjs: `bResult.agent_id === b.agent_id` on the
    // exact success path this client code calls). witness-register.js (the HTTP handler) returns
    // registerAgent()'s result unmodified (`res.status(...).json(result)`, no field stripping), so
    // this holds all the way through the HTTP boundary too.
    if (body.agent_id !== badge.agent_id) {
      throw new Error(`WITNESSED mint failed: witness-register returned HTTP ${res.status} confirming registration for agent_id=${JSON.stringify(body.agent_id)}, but this badge's agent_id is ${JSON.stringify(badge.agent_id)} — refusing to trust a response for the wrong agent`);
    }

    // Step 4: only NOW claim WITNESSED — re-sign the whole badge core so the tier change itself is
    // covered by the same whole-badge signature every other field already is.
    //
    // POST-REVIEW FIX (bot finding, CodeRabbit correctness-8): which witness this badge was
    // actually registered against was previously never recorded anywhere on the badge itself —
    // only ever known to whoever happened to be holding the `witnessServiceUrl` opt at mint time.
    // Two real consequences, not just a transparency gap: (1) a recipient had no way to tell a
    // badge registered against a real, official witness apart from one registered against a
    // throwaway/test instance; (2) verifyBadgeWitnessed() below defaults to the global
    // WITNESS_SERVICE_URL when no explicit override is passed, so verifying a badge minted
    // against a NON-default witness (e.g. a staging instance) would silently check the WRONG
    // service and read back UNREACHABLE/never-heard-of-this-agent — a real correctness bug, not
    // just missing metadata. Signed (part of the core `resign()` covers), not hashed into
    // agent_id — recording it doesn't change identity derivation, only after-the-fact disclosure.
    badge.assurance_tier = 'WITNESSED';
    badge.witness_service_url = witnessServiceUrl;
    return resign(badge, keys);
  } catch (e) {
    // POST-REVIEW FIX (5th round): `badge` may now be unassigned if mintBadge() itself threw
    // before ever producing an agent_id (e.g. invalid opts) — nothing was written to the
    // keystore in that case, so there is nothing to clean up and calling removeOrphanedKeys()
    // with an undefined agent_id would just be a wasted (harmless, ENOENT) unlink attempt.
    if (badge && badge.agent_id) {
      // POST-REVIEW FIX (5th round, reliability-3): if cleanup ALSO fails, annotate the original
      // error rather than silently swallowing the cleanup failure — `e` stays the same object
      // (same message, same code, same identity for any existing `instanceof`/regex/code check),
      // just with two extra properties a caller can opt into inspecting.
      const cleanupError = removeOrphanedKeys(opts.workRoot, badge.agent_id);
      if (cleanupError) {
        e.keystoreCleanupFailed = true;
        e.keystoreCleanupError = cleanupError;
      }
    }
    throw e;
  }
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

// POST-REVIEW FIX (4th round): the same truthy-vs-type-test bug already fixed once for
// `badge.log` (below) existed a SECOND time on `badge.evidence.confirmed_profiles`/
// `downgraded_profiles` — `ev.confirmed_profiles || []` let a truthy non-array (e.g. `{}`) sail
// straight through into a `.join()` call that only exists on arrays, crashing verifyBadge() for
// ANY caller regardless of whether the rest of the badge was otherwise perfectly valid. All
// array-shaped badge sub-fields now share this one normalizer instead of ad hoc `|| []` guards
// repeated at each call site, so a field added later can't reintroduce the same bug by
// copy-pasting the wrong pattern (see the general "never throws" regression test in
// test/agentid.witnessed.test.mjs, added for the same reason).
function asArray(value) { return Array.isArray(value) ? value : []; }

// POST-REVIEW FIX (decision 1, wave 6 -- Paul's explicit direction on round 4/5's confirmed
// security-1/SEC-001 finding, formerly recorded as an intentionally-unfixed product-semantics
// question in round 5's validation/confirmed-unfixed-security-1.json): shared "never mask a
// worse verdict" rule. WITNESSED tier exists specifically to catch a revoked badge a SELF-tier
// check can't see; a caller who only branches on `.verdict` (exactly what that field is for)
// must NOT see the same value for "the online check was never attempted/was skipped" as for "the
// online check genuinely ran and came back clean". INVALID/REVOKED are already the worst
// realistic states a badge can present and are never softened by an incomplete check; VALID/
// STALE downgrade to UNKNOWN because the one check that matters most for this tier could not be
// completed. Used by verifyBadge()'s direct-WITNESSED-call branch (never asked) and by
// verifyBadgeWitnessed()'s SKIPPED branch (explicitly asked not to check) -- mirrors the
// identical rule verifyBadgeWitnessed() has always applied to its own UNREACHABLE fallback paths
// (network error, non-OK status, timeout, malformed/wrong-agent response).
function downgradeUnconfirmedVerdict(verdict) {
  return (verdict === 'INVALID' || verdict === 'REVOKED') ? verdict : 'UNKNOWN';
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
  // not iterable"). Normalized ONCE here via the shared asArray() helper (see its definition) and
  // reused below instead of three separate `badge.log || []` guards, one of which (the
  // rotation-entries filter) still had this exact bug. Each entry is also guarded for object-shape
  // before being read/destructured, since a log ARRAY containing a non-object entry (e.g.
  // `[null]`) crashed the same way one line later even after the array-vs-not check.
  const log = asArray(badge.log);

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
  let verdict = !structurally_valid ? 'INVALID'
    : offline_state === 'REVOKED' ? 'REVOKED'
    : offline_state === 'STALE' ? 'STALE'
    : offline_state === 'UNKNOWN' ? 'UNKNOWN'
    : 'VALID';

  // coverage + assurance tier — honest scope, never "everything the agent did".
  const ev = badge.evidence;
  const coverage = ev
    ? `GraphSmith eval: ${ev.status}; confirmed profiles [${asArray(ev.confirmed_profiles).join(', ') || 'none'}]`
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
    //
    // POST-REVIEW FIX (decision 1, wave 6 -- round 4/5's confirmed security-1/SEC-001 finding):
    // disclosure in scope_note alone was not enough -- a caller that only branches on the
    // machine-checkable `.verdict` field (exactly what that field is for) saw an unconfirmed
    // WITNESSED badge read identically to one that was genuinely checked and came back clean.
    // The verdict itself is now downgraded via the same "never mask a worse verdict, otherwise
    // fall back to UNKNOWN" rule verifyBadgeWitnessed() already applies to its own failed/skipped
    // online-check paths (see downgradeUnconfirmedVerdict()) -- so "never asked" now reads the
    // same as "asked and failed", instead of silently reading the same as "asked and succeeded".
    const preDowngradeVerdict = verdict;
    verdict = downgradeUnconfirmedVerdict(verdict);
    scope_note += verdict !== preDowngradeVerdict
      ? ` This badge claims WITNESSED tier, but this synchronous check did not perform the online witness lookup, so the verdict was downgraded from ${preDowngradeVerdict} to ${verdict} — call verifyBadgeWitnessed() to independently confirm revocation status; absent that call, this verdict relies on local-log-only semantics, same as a SELF-tier badge.`
      : ' This badge claims WITNESSED tier, but this synchronous check did not perform the online witness lookup — call verifyBadgeWitnessed() to independently confirm revocation status; this verdict relies on local-log-only semantics, same as a SELF-tier badge.';
  }
  if (compromisedSince) {
    scope_note += ` Note: a COMPROMISE_ROTATION event flags key material suspected compromised since ${compromisedSince} — log entries in that window should be discounted by the reader, not treated as trusted.`;
  }

  return {
    verdict, agent_id: badge.agent_id, assurance_tier, coverage, scope_note,
    confirmed_profiles: asArray(ev?.confirmed_profiles),
    downgraded_profiles: asArray(ev?.downgraded_profiles), // shown grey, never green
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

  // POST-REVIEW FIX (decision 1, wave 6): computed once, up front, via the shared
  // downgradeUnconfirmedVerdict() helper (see its definition for the "never mask a worse
  // verdict" rule), and now applied to EVERY fallback path below, including SKIPPED just below --
  // previously only the UNREACHABLE paths downgraded the verdict; SKIPPED silently returned the
  // undowngraded base verdict (round 4/5's confirmed security-1/SEC-001 finding, decided by Paul
  // 2026-08-09: downgrade to UNKNOWN, matching the check-failed case).
  const fallbackVerdict = downgradeUnconfirmedVerdict(verdict.verdict);

  // POST-REVIEW FIX (round 6, correctness-2 — independently confirmed by all 5 reviewers this
  // round, zero refutations): the online witness lookup used to run unconditionally for ANY
  // WITNESSED-tier-labeled badge, even one whose local signature/structure verification had
  // already failed (verdict.verdict === 'INVALID') — e.g. a bare, unsigned JSON object an
  // attacker crafts with `assurance_tier: 'WITNESSED'` and an arbitrary `witness_service_url`.
  // That let a malformed input that was never validly signed force an outbound HTTPS request
  // before this function had any reason to believe the badge was real — SSRF-adjacent
  // (attacker-chosen host) and a data leak (the request carries this badge's `agent_id` and the
  // verifier's own IP/timing to whatever host the unverified badge names). Concretely
  // reproduced by this file's own pre-existing malformed-badge test just below, which called
  // this function with `{ assurance_tier: 'WITNESSED', inception: {} }` and NO mocked fetch —
  // every `npm test` run was silently making a real network call to the production default
  // WITNESS_SERVICE_URL for that fixture; its assertion never caught this because verdict stays
  // 'INVALID' whether or not the call fires. A badge that's already known structurally invalid
  // gains nothing from an online check — INVALID cannot get worse, and
  // downgradeUnconfirmedVerdict() already preserves it unchanged — so it's checked first, and
  // the network path below is only reachable once the badge has at least passed local
  // signature/structure verification. This is a DIFFERENT fix from security-1/correctness-1
  // (which is about which witness a *validly-signed* badge gets checked against, once it's
  // reached the network call at all) — that remains open, pending the repo owner's decision on
  // a trust-policy approach; see this round's report.
  if (verdict.verdict === 'INVALID') {
    return {
      ...verdict, witness_state: 'SKIPPED',
      scope_note: `${verdict.scope_note} The online witness check was not attempted because this badge already failed local signature/structure verification — an invalid badge cannot be made valid by an online check, and this avoids an unnecessary outbound request to a witness URL supplied by unverified badge data.`,
    };
  }

  if (!checkWitness) {
    return {
      ...verdict, verdict: fallbackVerdict, witness_state: 'SKIPPED',
      scope_note: `${verdict.scope_note} The online witness check was explicitly skipped for this verify call — this verdict relies on local-log-only semantics, same as a SELF-tier badge.`,
    };
  }

  // POST-REVIEW FIX (bot finding, CodeRabbit correctness-8): fall back to the URL THIS BADGE was
  // actually registered against (now recorded at mint time, see mintWitnessedBadge()'s Step 4)
  // before falling back further to the global default. Previously an explicit opts override was
  // the only way to avoid silently checking the wrong service for a badge minted against a
  // non-default witness (e.g. staging) — omitting the override didn't mean "use this badge's
  // witness", it meant "use the global default", even when those differed. `badge.witness_service_url`
  // is undefined for badges minted before this fix, so the final `|| WITNESS_SERVICE_URL` fallback
  // preserves their existing (global-default) behavior unchanged.
  const url = witnessServiceUrl || badge.witness_service_url || WITNESS_SERVICE_URL;
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
      // POST-REVIEW FIX (5th round, SEC-002): see the matching comment on the witness-register
      // fetch() in mintWitnessedBadge() above — 'manual' prevents a redirect from silently
      // downgrading this request to plaintext; the `!res.ok` check just below fails closed on
      // the resulting opaqueredirect response the same way it already does for any other
      // non-2xx response.
      res = await fetch(`${url}/api/witness-status?agent_id=${encodeURIComponent(verdict.agent_id || badge.agent_id || '')}`, { signal: ctrl.signal, redirect: 'manual' });
    } catch (e) {
      console.warn(`[viaid:witness] verify fallback: witness service unreachable at ${url} (${e.message}) — agent_id=${badge.agent_id || 'unknown'}`);
      // POST-REVIEW FIX (decision 2, wave 6): same rationale as mintWitnessedBadge()'s matching
      // fetch()-catch above -- a rejected fetch() here is almost always a connectivity problem on
      // the caller's end, so say that plainly instead of leaving the reader to guess from "the
      // witness service was unreachable" whether that means their network, the service being
      // down, or something about their badge.
      return {
        ...verdict, verdict: fallbackVerdict, witness_state: 'UNREACHABLE',
        scope_note: `${verdict.scope_note} The online witness check was attempted but the witness service was unreachable — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier. This usually means a poor or interrupted network connection rather than a problem with this badge — please check your connection and try the verification again.`,
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
      const timedOut = ctrl.signal.aborted;
      const reason = timedOut
        ? `timed out reading the response body after ${WITNESS_HTTP_TIMEOUT_MS}ms`
        : `response was not valid JSON (${e.message})`;
      console.warn(`[viaid:witness] verify fallback: witness service at ${url} ${reason} — agent_id=${badge.agent_id || 'unknown'}`);
      // POST-REVIEW FIX (decision 2, wave 6): ONLY the timeout branch is a genuine connectivity
      // problem -- a response that arrived but wasn't valid JSON is a witness-service-side issue,
      // not something "check your connection and retry" would fix, so that branch's message is
      // deliberately left unchanged. Scoped this precisely per Paul's explicit direction: the
      // retry language belongs only at genuine-connectivity-failure sites, not generically on
      // every failure path.
      return {
        ...verdict, verdict: fallbackVerdict, witness_state: 'UNREACHABLE',
        scope_note: `${verdict.scope_note} The online witness check was attempted but the witness service's response ${reason} — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.${timedOut ? ' This usually means a poor or interrupted network connection rather than a problem with this badge — please check your connection and try the verification again.' : ''}`,
      };
    }
  } finally {
    clearTimeout(timer);
  }

  // POST-REVIEW FIX (4th round, security-3/correctness-4): the response was never checked to
  // actually be ABOUT the agent_id just queried — a caching bug, a load-balancer routing mix-up,
  // or a buggy witness deployment ignoring the query param would previously be trusted blindly.
  // The real contract (and this file's own test mocks, e.g. the CHECKED_REVOKED/CHECKED_CLEAN
  // tests) always echoes `agent_id` back in the response; a missing or mismatched one is now
  // treated the same as any other untrustworthy response — the "unexpected shape" fallback below.
  const queriedAgentId = verdict.agent_id || badge.agent_id || '';
  if (!body || body.agent_id !== queriedAgentId) {
    console.warn(`[viaid:witness] verify fallback: witness service at ${url} answered for agent_id=${JSON.stringify(body && body.agent_id)}, expected ${JSON.stringify(queriedAgentId)} — refusing to trust a response for the wrong agent`);
    return {
      ...verdict, verdict: fallbackVerdict, witness_state: 'UNREACHABLE',
      scope_note: `${verdict.scope_note} The online witness check returned a response that did not confirm it was answering about this agent_id — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.`,
    };
  }
  // POST-REVIEW FIX (2nd round): `body.witnessed === true` correctly escalates and (implicitly)
  // anything else fell through to CHECKED_CLEAN — including a malformed/unexpected response like
  // `{witnessed: "true"}` (string) or `{witnessed: 1}` (number), which strict-`=== true` correctly
  // does NOT match, but which then silently read as a confirmed-clean verdict rather than an
  // ambiguous one. The real service (viaid-witness's getStatus()) only ever returns a genuine JS
  // boolean, so this only bites on a buggy/compromised/misconfigured witness endpoint — but this
  // tier's whole purpose is not trusting a single source blindly, so an unexpected shape is now
  // treated the same as an unreachable service (fail toward UNKNOWN, not toward "looks fine").
  if (body.witnessed === true) {
    // OR-only escalation: never downgrade an already-INVALID verdict into looking like a
    // legitimately-signed-then-revoked badge — see the function header comment for why.
    const forcedVerdict = verdict.verdict === 'INVALID' ? verdict.verdict : 'REVOKED';
    return {
      ...verdict, verdict: forcedVerdict, witness_state: 'CHECKED_REVOKED',
      scope_note: `${verdict.scope_note} The witness service independently confirms a revocation (${body.action || 'unknown action'}) is on record for this agent_id — this holds even if the locally-presented badge's own log has been truncated to hide it, closing the SELF-tier log-truncation gap described above.`,
    };
  }
  if (body.witnessed === false) {
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
