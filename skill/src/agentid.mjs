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
//
// D-24/D-25 (revoke signing model + code/model integrity commitment, 2026-07-30) — schema notes:
//  - `revokeBadge()` used to call the SAME whole-badge `resign()` every other mutation uses —
//    requiring owner+agent+voucher privs together. That's backwards for revoke specifically:
//    revoke is precisely the action you need to complete WITHOUT the cooperation of the party
//    you may be revoking against (D-01/D1). Fixed by modeling revocation as three independent,
//    per-role signed log events (`OWNER_REVOKE` / `AGENT_KEY_REVOKED` / `VOUCHER_REVOKE`),
//    mirroring the exact pattern rotation already uses (`voucher_attestation`) — see
//    `ownerRevoke`/`voucherRevoke`/`agentKeyRevoked` below. `revoked_reason`/`revocation_state`
//    are now a best-effort CACHE only (may go stale) — `verifyBadge()` derives ground truth by
//    scanning the log for a validly-attested revoke event, same shape as its rotation-chain walk.
//  - Because these revoke events are deliberately NOT whole-badge-resigned (that's the whole
//    point — no single role should need the other two roles' keys to revoke), the whole-badge
//    `signatures` block would otherwise appear invalid once a revoke event is appended (its
//    `msg` covers `.log`/`.revocation_state`, which just changed). `coreAsSignedBeforeRevoke()`
//    handles this precisely: for any badge with a TRAILING run of revoke-type log entries, the
//    whole-badge signature is checked against the badge as it existed immediately before that
//    run (log truncated, revocation_state/revoked_reason reset), which is exactly what was last
//    legitimately `resign()`'d. For every badge with zero revoke events (100% of badges before
//    this change), this is byte-for-byte identical to the old check — no back-compat break.
//  - `inception.code_commitment` (`code_hash`, `tool_manifest_hash`) and `inception.model_set`
//    are new, frozen-at-mint fields (hashed into `agent_id` the same way the three pubkeys
//    already are). `model_set` is a declared ALLOWED ROSTER, not one fixed running state — an
//    agent legitimately calling multiple models per request pins the *set* they must come
//    from, not one deterministic value (Paul, 2026-07-30: "has to cater to agents that can have
//    multiple models running simultaneously"). v1 detection (re-hash + `model_used` cross-check
//    against this roster) is GraphSmith's job (VIA-094, Wave 1) — this file only adds the
//    primitive: the frozen commitment + the hashing helpers, not the detection wiring.
//
// ADVERSARIAL REVIEW PASS (2026-07-30, post-Wave-0): 3 independent, blind, zero-shared-context
// reviewers (distinct adversarial lenses: deep crypto forgery, fast/naive broad sweep, logic/
// lifecycle) found and proved — with executable exploits — that the FIRST version of the D-24
// revoke design above had real, serious holes. All are now fixed; the specific fixes (each with
// its own inline comment at the fix site) are:
//   1. Domain separation (`attestationMessage()`): every per-event attestation (rotation's
//      `voucher_attestation`, revoke's `revoke_attestation`) now signs {agent_id, seq, action,
//      detail} instead of bare `canonical(detail)`. Without this, a genuine ROTATION event's
//      voucher_attestation could be copied verbatim into a fabricated VOUCHER_REVOKE entry and
//      it would verify — a full revoke forgery requiring ZERO private key material.
//   2. `coreAsSignedBeforeRevoke()` now verifies each trailing entry's attestation before
//      tolerating it, not just its `action` string — an unsigned/garbage entry labeled e.g.
//      'OWNER_REVOKE' no longer gets silently excluded from the whole-badge signature check.
//   3. `appendLog`/`rotateKey`/`attachEvidence` now refuse to run on an already-revoked badge
//      (via `isRevoked()`), making "a revoke entry is always the tail of the log, never
//      followed by other activity" an ENFORCED invariant rather than a hopeful assumption.
//   4. `verifyBadge()` is now a fail-closed wrapper: malformed/hostile input (null, non-object,
//      a non-array `.log`, circular references, etc.) returns a clean INVALID verdict instead
//      of throwing an uncaught exception — found independently by all 3 reviewers.
//   5. `hashCodeTree`'s symlink-follow fix (below) gained cycle/depth protection — the fix
//      itself, without this, could hang indefinitely on a self-referential symlink loop.
//   6. `canonicalModelSet()` now dedupes, Unicode-normalizes (NFC), and sorts by plain code-
//      unit comparison instead of `localeCompare` (locale-dependent, not a true total order) —
//      the same logical model roster could otherwise hash into a different `agent_id`.
//   7. `canonical()` now handles `undefined` the way `JSON.stringify` does, so a signed message
//      containing one always round-trips through a save/load cycle as valid JSON.
//   8. `_revokeEvent`'s `extraDetail` no longer overrides protocol-computed audit fields
//      (`reason`/`signed_by`/`triggered_by`).
//   9. `node_modules` is no longer excluded from `code_commitment`'s hash (SKIP_DIRS) — it's
//      real, executable code, and excluding it was a straightforward bypass.
// ONE finding was NOT fixed here, because it isn't fixable from inside this file: an attacker
// holding nothing but a revoked badge's own public JSON can strip the trailing revoke log
// entries and reset `revocation_state`, producing a byte-identical "never revoked" badge that
// still passes every check here. This is inherent to any purely OFFLINE, single-file verifier
// with no external witness committing to "the log is at least N entries long" — not a bug
// specific to this design. See the "log hash-chain intact" step's comment below for the honest
// scope of what that check does and doesn't prove. Closing this gap requires an ONLINE
// tip-freshness/transparency-log check (the WITNESSED/HARDWARE assurance_tier already named in
// this schema, not yet built) — flagged to Paul as an open architectural question, not silently
// patched over.
//
// URGENT SECURITY HARDENING (2026-08-01, live-code adversarial hunt — SAT-957/958/959/961/962):
//   - SAT-957 (CRITICAL, fixed here): `saveKeys()` wrote the local keystore with no restrictive
//     file mode — private keys (including the KERI pre-rotation key) landed world-readable
//     (0644) in a 0755 directory. Fixed: keystore directory created/chmod'd 0700, key files
//     written 0600 via writeFileSync's `mode` option, PLUS an explicit chmodSync belt-and-braces
//     (writeFileSync's `mode` only governs a NEWLY created file — it is silently ignored if the
//     file already existed with looser permissions, e.g. from a pre-fix run). `loadKeys()` now
//     also opportunistically tightens permissions it finds too loose on read, so badges minted
//     before this fix self-heal the next time their keystore is touched, without requiring a
//     separate migration step.
//   - SAT-958 (CRITICAL, NOT fixable in this file — see the paragraph above and the
//     "log hash-chain intact" step below; this is the same architectural gap, independently
//     reproduced live against the shipped repo). What WAS missing and IS fixed here: this
//     repo's `scope_note` never carried the SAT-930 disclosure that shipped to viaid-web/
//     viaid-locked ("SELF-tier revocation is not externally witnessed...") — ported below so a
//     caller of THIS library sees the same honest disclosure, not just a code comment a human
//     reading the source might find.
//   - SAT-959 (HIGH, fixed here): neither `keystorePath()` here nor `badgePath()` in
//     bin/viaid.mjs validated the `id`/`agent_id` argument before building a filesystem path —
//     `keystorePath(root, '../../etc/cron.d/evil')` escaped `.keys/` entirely. A loaded badge's
//     own `agent_id` field (attacker-controlled in a crafted badge.json — nothing before this
//     fix checked it against `hash(inception)` prior to using it for a keystore path) fed
//     straight into `loadKeys`/`saveKeys` from `appendLog`/`rotateKey`/`attachEvidence`/
//     `_revokeEvent`. Fixed: `assertValidAgentId()` enforces the exact `via_<32 lowercase hex>`
//     shape before ANY path is built from it, in both this file and bin/viaid.mjs.
//   - SAT-961 (MEDIUM, fixed here): `appendLog`'s caller pattern (load whole badge, mutate,
//     overwrite) had no protection against two concurrent CLI invocations racing — last writer
//     wins, the other's log entry silently vanishes, no error, no visible hash-chain break
//     (the dropped entry never entered the chain, so there's nothing to detect it by). Fixed
//     with a zero-dependency exclusive lockfile (`fs.openSync(lockPath, 'wx')`, i.e. atomic
//     create-fails-if-exists) around every mutating badge operation, with bounded retry/backoff
//     and a stale-lock takeover (a lock older than LOCK_STALE_MS is assumed abandoned by a
//     crashed process and reclaimed) so a crash can't permanently wedge the badge.
//   - SAT-962 (LOW, partially fixed — see report to Paul for the full discrepancy): the finding
//     as filed said "revokeBadge() doesn't append a log entry for the revocation event" — that
//     is NOT accurate against this source; `_revokeEvent()` always appends a real, attested log
//     entry (action/reason/signed_by/triggered_by). What genuinely WAS missing, across every
//     log entry type (not just revoke), is any timestamp. Fixed narrowly here for revoke only
//     (`revoked_at` in the revoke detail) since that's what was actually asked for and is the
//     highest-value single field for "if/when/why" — extending timestamps to every log entry
//     type is a broader schema change flagged to Paul, not assumed/done silently here.

import { generateKeyPairSync, sign as edSign, verify as edVerify, createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync, realpathSync, chmodSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';

const SCHEMA = 'viaid.badge/0.1';
const DEFAULT_BADGE_TTL_SECONDS = 90 * 24 * 3600; // 90 days

// ---- canonical JSON (stable key order) so hashes/signatures are reproducible ----
// `undefined` handling mirrors JSON.stringify's own semantics (drop undefined object keys,
// null-out undefined array elements) — found by adversarial testing 2026-07-30: the previous
// version let `canonical(undefined)` return the bare JS value `undefined`, which string-
// concatenates into the output as the literal (non-JSON) token `undefined`, producing a
// signed message that parses fine in-memory but fails JSON.parse after a save/load round-trip.
export function canonical(obj) {
  if (obj === undefined) return 'null';
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map((v) => (v === undefined ? 'null' : canonical(v))).join(',') + ']';
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
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

// ---- SAT-959: agent_id/id format validation, enforced before ANY path is built from one ----
// Exact shape mintBadge() actually produces: 'via_' + 32 lowercase hex chars. Anything else —
// path separators, '..', absolute paths, null bytes, wrong length — is refused outright rather
// than reaching join()/writeFileSync. This is checked at every entry point that turns an
// externally-influenced id (a CLI arg, or a loaded badge's own `.agent_id` field, which is
// attacker-controlled in a crafted badge.json) into a filesystem path.
const AGENT_ID_RE = /^via_[0-9a-f]{32}$/;
export function isValidAgentId(id) {
  return typeof id === 'string' && AGENT_ID_RE.test(id);
}
function assertValidAgentId(id) {
  if (!isValidAgentId(id)) {
    throw new Error(`invalid agent id (expected via_<32 lowercase hex>, got ${JSON.stringify(id)}) — refusing to build a path from it`);
  }
  return id;
}

// ---- keystore (PROTOTYPE ONLY) ----
// SAT-957: keys are private key material — the directory and every file in it are created/
// tightened to owner-only (0700 / 0600). `mkdirSync`'s own `mode` option only applies reliably
// to the LEAF directory it creates (and is silently skipped entirely if the directory already
// exists), and `writeFileSync`'s `mode` option only takes effect when the file doesn't already
// exist — so both are backed by an explicit `chmodSync` afterward, which unconditionally sets
// the requested mode regardless of umask, prior runs, or a pre-fix keystore already on disk.
const KEYSTORE_DIR_MODE = 0o700;
const KEYSTORE_FILE_MODE = 0o600;
function keystoreDir(root) { return join(root, '.keys'); }
function keystorePath(root, agentId) {
  assertValidAgentId(agentId);
  return join(keystoreDir(root), agentId + '.json');
}
function ensureKeystoreDir(root) {
  const dir = keystoreDir(root);
  mkdirSync(dir, { recursive: true, mode: KEYSTORE_DIR_MODE });
  try { chmodSync(dir, KEYSTORE_DIR_MODE); } catch { /* best-effort on platforms without POSIX perms (e.g. some Windows FS) */ }
  return dir;
}
function saveKeys(root, agentId, keys) {
  ensureKeystoreDir(root);
  const p = keystorePath(root, agentId);
  writeFileSync(p, JSON.stringify(keys, null, 2), { mode: KEYSTORE_FILE_MODE });
  try { chmodSync(p, KEYSTORE_FILE_MODE); } catch { /* best-effort, see above */ }
}
function loadKeys(root, agentId) {
  const p = keystorePath(root, agentId);
  // Opportunistic self-heal: a keystore written before this fix (or by any other tool) may
  // still be sitting at looser permissions — tighten it on read too, not just on write, so
  // existing installs close the gap the next time they touch a badge, no migration step needed.
  try { chmodSync(p, KEYSTORE_FILE_MODE); } catch { /* file may not exist yet, or platform lacks POSIX perms */ }
  return JSON.parse(readFileSync(p, 'utf8'));
}

// ---- SAT-961: zero-dependency exclusive lock around mutating badge operations ----
// `fs.openSync(path, 'wx')` is atomic create-fails-if-already-exists at the OS level — the
// same primitive real lockfile libraries use, without adding a dependency (this package's
// stated design: zero deps beyond node:crypto/fs/etc). Bounded retry with backoff, plus a
// stale-lock takeover so a crashed process (which never reaches the `finally` unlock) can't
// wedge a badge forever.
const LOCK_STALE_MS = 30_000;
const LOCK_RETRY_MS = 25;
const LOCK_MAX_WAIT_MS = 5_000;
function lockPathFor(workRoot, agentId) {
  assertValidAgentId(agentId);
  return join(workRoot, `.${agentId}.lock`);
}
function acquireLock(workRoot, agentId) {
  mkdirSync(workRoot, { recursive: true });
  const p = lockPathFor(workRoot, agentId);
  const deadline = Date.now() + LOCK_MAX_WAIT_MS;
  for (;;) {
    try {
      const fd = openSync(p, 'wx'); // atomic: throws EEXIST if the lock is already held
      writeFileSync(p, String(process.pid));
      closeSync(fd);
      return p;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      // Stale-lock takeover: a lock file older than LOCK_STALE_MS is assumed abandoned
      // (the holder crashed before its `finally` block ran) and is safe to steal.
      try {
        const age = Date.now() - statSync(p).mtimeMs;
        if (age > LOCK_STALE_MS) { unlinkSync(p); continue; }
      } catch { /* lock disappeared between the failed open and this check — just retry */ }
      if (Date.now() > deadline) {
        throw new Error(`could not acquire lock for ${agentId} after ${LOCK_MAX_WAIT_MS}ms — another process is holding it`);
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, LOCK_RETRY_MS); // sync sleep, no deps
    }
  }
}
function releaseLock(lockPath) {
  try { unlinkSync(lockPath); } catch { /* already gone — fine */ }
}
// Runs `fn()` (which reads + mutates + persists a badge) holding an exclusive per-agent_id
// lock, so two concurrent callers can never interleave a read-modify-write and silently drop
// one side's update. Exported so bin/viaid.mjs can wrap its own load→mutate→save sequence too
// (the lock has to span the CLI's read of the badge file, not just this module's internals).
export function withBadgeLock(workRoot, agentId, fn) {
  const lockPath = acquireLock(workRoot, agentId);
  try { return fn(); }
  finally { releaseLock(lockPath); }
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

// Domain-separated message for any PER-EVENT single-role attestation (rotation's
// `voucher_attestation`, revoke's `revoke_attestation`). Binds the signed bytes to THIS badge
// (agent_id), THIS position in the log (seq), and THIS action type — not just the free-form
// `detail` object. Found by adversarial testing 2026-07-30: signing bare `canonical(detail)`
// let an attacker copy a genuine ROTATION event's `voucher_attestation` + its `detail` verbatim
// into a fabricated `VOUCHER_REVOKE` log entry — since the signed bytes (`canonical(detail)`)
// were identical, the copied signature verified, forging a revoke with ZERO private key
// material. Binding agent_id/seq/action into what's actually signed closes that cross-action,
// cross-seq, and cross-badge replay path.
function attestationMessage(agentId, seq, action, detail) {
  return canonical({ agent_id: agentId, seq, action, detail });
}

// ---- code/tool-manifest hashing (D-25, VIA-090 — v1: file-tree content hash) ----
// Walks a directory, hashes each regular file's content, and combines the sorted
// {relative_path, sha256} pairs into one deterministic digest. This is the v1,
// buildable-now signal; GraphSmith's eval adapter (VIA-094, Wave 1) re-runs this
// independently at eval time and compares it against the frozen inception value.
// STATED LIMITATION (D-25): this alone is not independent of the agent's own
// environment yet — a compromised agent could feed a decoy directory. Real
// independence needs gateway/traffic-fingerprinting (VIA-104, Wave 4).
// `node_modules` is deliberately NOT skipped (2026-07-30 revision): it's real code that
// executes as part of the agent, and excluding it from code_commitment was a bypass an
// attacker (or a compromised dependency) could exploit — code planted there was invisible to
// the hash. STATED TRADEOFF: this means code_hash now changes on every dependency install/
// update, which is noisy for a fast-moving prototype; that noise is the honest price of the
// commitment actually meaning something. `.git`/`.keys`/`viaid-work` stay skipped — they're
// this tool's own control/metadata directories, never the agent's executable code.
const SKIP_DIRS = new Set(['.git', '.keys', 'viaid-work']);
function walkFiles(root, base = root, acc = [], seen = new Set(), depth = 0) {
  // Defense-in-depth against a symlink cycle (found by adversarial testing 2026-07-30: the
  // statSync-based symlink-follow fix above, on its own, hangs indefinitely — exponentially,
  // once nested — on a self-referential symlink loop). `seen` dedupes by REAL resolved path so
  // a cycle is visited once and then skipped; `depth` is a hard backstop for any other
  // pathological tree shape (doesn't rely solely on the realpath check being reachable).
  if (depth > 64) return acc;
  let real;
  try { real = realpathSync(root); } catch { return acc; }
  if (seen.has(real)) return acc;
  seen.add(real);
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = join(root, entry.name);
    // Resolve symlinks via statSync (follows links) rather than trusting dirent.isFile()/
    // isDirectory() alone — those report false for a symlink itself, which would silently
    // skip a symlinked source file's actual content. Found by adversarial testing 2026-07-30:
    // routing real code through a symlink would otherwise dodge code_hash entirely.
    let st;
    try { st = statSync(full); } catch { continue; } // dangling symlink — nothing to hash
    if (st.isDirectory()) walkFiles(full, base, acc, seen, depth + 1);
    else if (st.isFile()) acc.push(relative(base, full).split('\\').join('/'));
  }
  return acc;
}
export function hashCodeTree(codePath) {
  if (!codePath || !existsSync(codePath)) return sha256('NO_CODE_PATH_DECLARED');
  const files = walkFiles(codePath).sort();
  const digestList = files.map((f) => ({ path: f, sha256: sha256(readFileSync(join(codePath, f))) }));
  return sha256(canonical(digestList));
}
export function hashToolManifest(toolManifestPath) {
  // v1 placeholder when no manifest is declared — an honest, explicit "nothing pinned yet"
  // value rather than a silently-skipped field. No tool-manifest file convention exists in
  // this codebase yet; this hash has nothing real to check against until one does.
  if (!toolManifestPath || !existsSync(toolManifestPath)) return sha256(canonical({}));
  const parsed = JSON.parse(readFileSync(toolManifestPath, 'utf8'));
  return sha256(canonical(parsed));
}
function normalizeDeep(v) {
  if (typeof v === 'string') return v.normalize('NFC');
  if (Array.isArray(v)) return v.map(normalizeDeep);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v)) out[k] = normalizeDeep(v[k]);
    return out;
  }
  return v;
}
export function canonicalModelSet(modelSet = []) {
  // D-25: a declared ALLOWED ROSTER, not one fixed running state.
  // Found by adversarial testing 2026-07-30: the original `localeCompare`-based sort is NOT a
  // stable total order (locale-dependent — the same roster could sort differently on different
  // machines/locales), had no Unicode normalization (visually-identical strings in different
  // normalization forms would compare unequal), and didn't dedupe — any of which could make the
  // same *logical* roster hash into a DIFFERENT `agent_id`, defeating the whole point of
  // freezing it into an identity commitment. Fixed: normalize (NFC) every string field first,
  // dedupe by canonical content, then sort by plain code-unit comparison of that canonical
  // string (locale-independent, a genuine total order).
  const items = modelSet.map((m) => {
    const item = normalizeDeep(m);
    return { item, key: canonical(item) };
  });
  const seen = new Set();
  const deduped = [];
  for (const { item, key } of items) {
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push({ item, key });
  }
  deduped.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return deduped.map((d) => d.item);
}

// ---- mint a badge (viaid init) ----
export function mintBadge({
  name, owner = 'local-dev', workRoot, badge_ttl = DEFAULT_BADGE_TTL_SECONDS,
  codePath = null, toolManifestPath = null, modelSet = [],
}) {
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
    code_commitment: {                       // D-25 / VIA-090 — frozen into agent_id like the pubkeys
      code_hash: hashCodeTree(codePath),
      tool_manifest_hash: hashToolManifest(toolManifestPath),
    },
    model_set: canonicalModelSet(modelSet),  // D-25 / VIA-090 — declared allowed roster
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
    revocation_state: 'FRESH',              // best-effort CACHE (D-24): FRESH | REVOKED — verify derives
                                             // ground truth from the log, never trusts this field verbatim.
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

// ---- SAT-958 follow-up: WITNESSED-tier port (2026-08-01) ----
// mintWitnessedBadge() and verifyBadgeWitnessed() (further down, after verifyBadge()) are
// ported, functionally unchanged, from viaid-locked's prototype/src/agentid.mjs (SAT-933/934,
// merged to that repo's main on 2026-08-01) — pulled via `git show origin/main:prototype/src/
// agentid.mjs` and read directly, not assumed from ticket text or the local prototype checkout,
// which was found ~40 commits behind its own origin/main during this port. This is the piece
// that makes SAT-958's disclosed SELF-tier limitation (an attacker holding a revoked badge's
// public JSON can strip trailing revoke log entries and get a byte-identical VALID/FRESH
// verdict) actually closable: a WITNESSED-tier badge gets an online, server-side revocation
// check that a locally-doctored log copy cannot spoof.
//
// NOT ported here, flagged rather than silently done or silently skipped: prototype/src/
// agentid.mjs also carries a second, independent round of har