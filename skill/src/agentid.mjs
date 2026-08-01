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
// agentid.mjs also carries a second, independent round of hardening (Codex adversarial review,
// 2026-07-31, fixes #10-15 — isRevoked()'s cache-field fallback, SKIP_DIRS depth-0 scoping,
// model_set moved out of inception to a top-level signed field, verifyBadgeInner()'s log-array
// rejection, appendLog()'s reserved-action-name guard) that this file does not yet have. Porting
// those is a separate, broader sync task across all 3 mirrored copies of agentid.mjs (this one,
// prototype's, and viaid-web/lib/agentid-core.mjs) — out of scope for "port the WITNESSED
// wrapper" specifically, so this file is now current on WITNESSED-tier but NOT fully synced
// with prototype's other hardening.
//
// Layered ON TOP of mintBadge() rather than folded into it, so mintBadge() stays 100%
// synchronous and behavior-identical for every existing SELF-tier caller. Fail-closed: any
// registration failure throws and returns no badge at all — never a silent SELF-tier fallback.
const WITNESS_HTTP_TIMEOUT_MS = Number(process.env.VIAID_WITNESS_TIMEOUT_MS || 10000);
// Single swap point for the production witness service URL — flip only this line (or set
// VIAID_WITNESS_URL) if the deployed domain changes.
const WITNESS_SERVICE_URL = process.env.VIAID_WITNESS_URL || 'https://witness.viaid.ai';

// Mirrors viaid-witness's lib/witness.mjs registrationAttestationMessage() byte for byte (same
// canonical() algorithm, same field set) — the server recomputes and checks this exact message,
// so any drift here makes owner_sig/voucher_sig fail server-side verification.
function registrationAttestationMessage(agentId, ownerPub, voucherPub) {
  return canonical({ purpose: 'witness_registration', agent_id: agentId, owner_pub: ownerPub, voucher_pub: voucherPub });
}

export async function mintWitnessedBadge(opts) {
  const witnessServiceUrl = (opts && opts.witnessServiceUrl) || WITNESS_SERVICE_URL;

  // Step 1: mint exactly as SELF-tier, via the existing unchanged path — same inception, same
  // agent_id derivation, same keystore write. No new failure surface introduced here.
  const badge = mintBadge(opts);
  const keys = loadKeys(opts.workRoot, badge.agent_id);

  // Step 2: sign the registration attestation with the REAL owner/voucher private keys — never
  // agent (matches REVOKE_ROLE_PUB_FIELD's established "agent never self-attests a mutation").
  const msg = registrationAttestationMessage(badge.agent_id, badge.inception.owner_pub, badge.inception.voucher_pub);
  const owner_sig = signB64(keys.owner.priv, msg);
  const voucher_sig = signB64(keys.voucher.priv, msg);

  // Step 3: register with the witness service. Fail-closed — see header comment above.
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), WITNESS_HTTP_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${witnessServiceUrl}/api/witness-register`, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ inception: badge.inception, owner_sig, voucher_sig }),
    });
  } catch (e) {
    throw new Error(`WITNESSED mint failed: witness-register request to ${witnessServiceUrl} errored — ${e.message}`);
  } finally {
    clearTimeout(timer);
  }
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON error body — fall through with body=null */ }
  if (!res.ok) {
    throw new Error(`WITNESSED mint failed: witness-register returned HTTP ${res.status}${body && body.error ? ` — ${body.error}` : ''}`);
  }

  // Step 4: only NOW claim WITNESSED — re-sign the whole badge core so the tier change itself
  // is covered by the same whole-badge signature every other field already is.
  badge.assurance_tier = 'WITNESSED';
  return resign(badge, keys);
}

// ---- append a hash-chained log entry (viaid log) ----
export function appendLog(badge, workRoot, { action, model_used = null, detail = null }) {
  // Found by adversarial testing 2026-07-30: nothing previously stopped normal activity from
  // being logged (and whole-badge-resigned!) onto an already-revoked badge, which both makes no
  // sense (a revoked badge is dead) and is the precondition for a verify-time double-revoke /
  // revoke-then-activity edge case. Refusing at the source is simpler than reasoning about it
  // at verify time — see coreAsSignedBeforeRevoke()'s comment for how this keeps the "trailing
  // run of revoke entries" assumption an enforced invariant, not just a hopeful heuristic.
  if (isRevoked(badge)) throw new Error('badge has a valid revoke event in its log — refusing to log further activity');
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
  if (isRevoked(badge)) throw new Error('badge has a valid revoke event in its log — refusing to rotate a revoked badge');
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
  const action = isCompromise ? 'COMPROMISE_ROTATION' : 'ROTATION';
  const seq = badge.log.length;
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
  // Domain-separated (agent_id/seq/action bound in) — see attestationMessage()'s comment for why.
  const voucher_attestation = signB64(keys.voucher.priv, attestationMessage(badge.agent_id, seq, action, detail));

  const prev_hash = badge.log.length ? badge.log[badge.log.length - 1].entry_hash : 'GENESIS';
  const body = { seq, action, model_used: null, detail, voucher_attestation, prev_hash };
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
  if (isRevoked(badge)) throw new Error('badge has a valid revoke event in its log — refusing to attach evidence to a revoked badge');
  badge.evidence = evidence; // { engine, status, confirmed_profiles, downgraded_profiles, note, evaluated_at_source }
  // Evidence raises the assurance the verdict can claim, but only what the evidence supports.
  return resign(badge, loadKeys(workRoot, badge.agent_id));
}

// ---- revoke (viaid revoke) — D-24: three independent per-role signed events ----
// Deliberately NOT routed through the whole-badge resign() — that would require
// owner+agent+voucher privs together, which defeats the point (revoke must be completable
// WITHOUT the cooperation of the party being revoked against). Each function below signs
// only ONE role's key over the event detail (mirroring rotateKey's `voucher_attestation`
// pattern), appends it as a normal hash-chained log entry, and updates the cache fields.
const REVOKE_ROLE_PUB_FIELD = { OWNER_REVOKE: 'owner_pub', VOUCHER_REVOKE: 'voucher_pub', AGENT_KEY_REVOKED: 'voucher_pub' };

// Ground-truth revocation check, reused by (a) the mutation guards above, so a revoked badge
// can never accumulate further non-revoke activity, and (b) verifyBadge()'s own log scan below
// — one implementation, so the two can never disagree about what counts as "really revoked".
function isRevoked(badge) {
  const inc = badge.inception || {};
  const log = Array.isArray(badge.log) ? badge.log : [];
  for (const e of log) {
    const pubField = REVOKE_ROLE_PUB_FIELD[e.action];
    if (!pubField) continue;
    const pub = pubField === 'owner_pub' ? inc.owner_pub : inc.voucher_pub;
    const msg = attestationMessage(badge.agent_id, e.seq, e.action, e.detail || {});
    if (verifyB64(pub, msg, e.revoke_attestation || '')) return true;
  }
  return false;
}

function _revokeEvent(badge, workRoot, role, action, reason, extraDetail = {}) {
  // PROTOTYPE-ONLY: this still loads the full local keystore (all 3 keys sit in one file per
  // this file's documented shortcut), but the event is signed with ONLY the one relevant
  // private key below — the logic is production-shaped even though this environment's key
  // custody isn't split yet. A production caller would only ever have `keys[role]` available.
  const keys = loadKeys(workRoot, badge.agent_id);
  const signerPriv = keys[role].priv;
  const seq = badge.log.length;
  // extraDetail spreads FIRST — protocol-computed fields (reason/signed_by/triggered_by) are
  // listed AFTER and always win. Found by adversarial testing 2026-07-30: the previous spread
  // order let a caller's extraDetail (e.g. agentKeyRevoked's mismatch evidence) silently
  // override the protocol fields, corrupting audit metadata (didn't defeat the cryptographic
  // verdict, since verification keys off `e.action`, but a `signed_by` that lies about who
  // signed is still a real integrity bug in the audit trail).
  // SAT-962: `revoked_at` added (2026-08-01) — the revoke path appended a log entry all along
  // (action/reason/signed_by/triggered_by were already recorded), but no entry type in this
  // codebase carried a timestamp. Adding it narrowly here, for revoke only, since that's what
  // was actually flagged; extending timestamps to every log-entry type is a separate, broader
  // schema question surfaced to Paul rather than assumed here.
  const detail = {
    ...extraDetail,
    reason,
    signed_by: role,                                              // D-24/VIA-091
    triggered_by: action === 'AGENT_KEY_REVOKED' ? 'system' : 'principal', // D-24/VIA-091
    revoked_at: new Date().toISOString(),                         // SAT-962
  };
  // Domain-separated attestation (agent_id/seq/action bound in) — see attestationMessage()'s
  // comment for why: without this, a genuine ROTATION event's voucher_attestation could be
  // replayed verbatim as a forged VOUCHER_REVOKE, needing zero private key material.
  const revoke_attestation = signB64(signerPriv, attestationMessage(badge.agent_id, seq, action, detail));
  const prev_hash = badge.log.length ? badge.log[badge.log.length - 1].entry_hash : 'GENESIS';
  const body = { seq, action, model_used: null, detail, revoke_attestation, prev_hash };
  const entry = { ...body, entry_hash: sha256(prev_hash + '\n' + canonical(body)) };
  badge.log.push(entry);
  // Cache fields only (D-24) — verifyBadge() derives ground truth from the log-scan below,
  // regardless of what these say. Kept for fast-path convenience (e.g. a future dashboard
  // list view that doesn't want to walk every badge's full log).
  badge.revocation_state = 'REVOKED';
  badge.revoked_reason = reason;
  return badge; // NOT whole-badge resigned — see file header + coreAsSignedBeforeRevoke().
}

// Owner/developer revokes unilaterally — no cooperation from agent or voucher needed.
export function ownerRevoke(badge, workRoot, reason = 'revoked') {
  return _revokeEvent(badge, workRoot, 'owner', 'OWNER_REVOKE', reason);
}
// VIA ID's own action — directly, or (D-28, Wave 3) on a partnered org's entitlement-gated
// behalf via the API Bridge. The org never touches badge key material either way.
export function voucherRevoke(badge, workRoot, reason = 'revoked') {
  return _revokeEvent(badge, workRoot, 'voucher', 'VOUCHER_REVOKE', reason);
}
// Never trust the agent to self-report a mutation (Paul, 2026-07-30) — this is never signed
// by agent.priv. Voucher attests because it's the only party positioned to attest independently.
// extraDetail is for the actual mismatch evidence (code_hash/model_set drift, etc.) — wiring
// that up to a real independent detector is GraphSmith's job (VIA-094, Wave 1), not this file.
export function agentKeyRevoked(badge, workRoot, reason = 'code_or_model_mismatch', extraDetail = {}) {
  return _revokeEvent(badge, workRoot, 'voucher', 'AGENT_KEY_REVOKED', reason, extraDetail);
}

// Computes the message the whole-badge `signatures` should be checked against, tolerating a
// trailing run of revoke-type log entries (which are deliberately NOT whole-badge-resigned,
// see above). For any badge with zero revoke events — which is every badge minted before this
// change, and the common case going forward — this is byte-for-byte identical to the old
// coreForSigning() check. Only badges that have actually been revoked take the alternate path.
function coreAsSignedBeforeRevoke(badge) {
  const log = Array.isArray(badge.log) ? badge.log : [];
  const inc = badge.inception || {};
  let cut = log.length;
  // Walk backward over the trailing run of revoke-type entries, but — unlike the original
  // version, which trusted the `action` string alone — only tolerate an entry here if its
  // attestation actually verifies against the correct role's pubkey. Found by adversarial
  // testing 2026-07-30: checking only `e.action` let an attacker append an UNSIGNED (or
  // wrong-key-signed) garbage entry labeled e.g. 'OWNER_REVOKE' at the tail, and the whole-badge
  // signature check would silently "tolerate" it as if it were a legitimate revoke — polluting
  // the tamper-evident log with unauthenticated content that cost the attacker nothing. Now,
  // the moment a trailing entry's own attestation fails to verify, the truncation stops there
  // and that entry (and anything above it) is treated as un-tolerated content the whole-badge
  // signature must still cover — which it won't, so verifyBadge correctly reports INVALID
  // instead of silently accepting the injected entry.
  while (cut > 0) {
    const e = log[cut - 1];
    const pubField = REVOKE_ROLE_PUB_FIELD[e.action];
    if (!pubField) break;
    const pub = pubField === 'owner_pub' ? inc.owner_pub : inc.voucher_pub;
    const msg = attestationMessage(badge.agent_id, e.seq, e.action, e.detail || {});
    if (!verifyB64(pub, msg, e.revoke_attestation || '')) break;
    cut--;
  }
  if (cut === log.length) return coreForSigning(badge); // no trailing revoke run — unchanged behavior
  // revocation_state must be RESET to its pre-revoke value ('FRESH' — the only value it can
  // ever have had before these revoke functions run), not deleted: the key was present and
  // signed at mint/last-resign time, so dropping it entirely would change the canonical key
  // set and break the match. revoked_reason, by contrast, never existed before revoke — drop it.
  const { signatures, revoked_reason, ...rest } = badge;
  return canonical({ ...rest, log: log.slice(0, cut), revocation_state: 'FRESH' });
}

// ---- verify (viaid verify / scan) → honest verdict ----
// Fail-closed shape for a badge verifyBadgeInner() couldn't even get through — same keys as a
// normal verdict, so callers never have to special-case a crash vs. a genuine INVALID.
function invalidVerdict(reason) {
  return {
    verdict: 'INVALID', agent_id: undefined, assurance_tier: undefined,
    coverage: 'no evaluation attached (identity + log only)',
    scope_note: 'This verdict attests identity, signatures, and log integrity — not the safety, correctness, or compliance of the agent.',
    confirmed_profiles: [], downgraded_profiles: [],
    key_seq: 0, last_rotation_reason: null, last_rotation_at: null,
    freshness_state: 'INVALID',
    steps: [{ step: 'verify', status: 'FAIL', detail: reason }],
  };
}

// SAT-958 / SAT-930-sync (2026-08-01): this repo's scope_note never carried the disclosure
// that shipped to viaid-web/viaid-locked under SAT-930. Ported verbatim (plus this repo's own
// more specific SELF-tier framing) so a caller of this library — not just a human reading the
// source comments above — sees the honest limitation on every SELF-tier verdict.
const SELF_TIER_SCOPE_NOTE =
  'This verdict attests identity, signatures, and log integrity — not the safety, correctness, or compliance of the agent. ' +
  'SELF-tier revocation is not externally witnessed: a holder of this badge\'s raw JSON before it was revoked can replay that ' +
  'copy, and a holder of the current JSON can strip trailing revoke log entries, producing a badge that verifies VALID/FRESH ' +
  'here. Closing this requires an online witness/transparency-log check (WITNESSED/HARDWARE assurance tiers, not yet built).';

function verifyBadgeInner(badge) {
  const steps = [];
  const push = (step, ok, detail) => steps.push({ step, status: ok ? 'PASS' : 'FAIL', detail });
  // Defensive normalization (found by adversarial testing 2026-07-30: hostile/malformed input —
  // `badge.log` null/undefined/a non-array — crashed with an unhandled TypeError instead of
  // returning INVALID). Every use below reads `log`, never `badge.log` directly.
  const inc = (badge.inception && typeof badge.inception === 'object') ? badge.inception : {};
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
  // defeats: forged rotation w/o voucher co-sign, replayed rotation, wrong key_seq. The
  // attestation check is domain-separated (agent_id/seq/action bound in, not bare
  // canonical(detail)) — see attestationMessage()'s comment.
  let seq = inc.key_seq ?? 0;
  let commitment = inc.next_key_commitment;
  let currentKey = inc.agent_pub;
  let rotationChainOk = true;
  let compromisedSince = null;
  const rotationEntries = log.filter((e) => e.action === 'ROTATION' || e.action === 'COMPROMISE_ROTATION');
  for (const e of rotationEntries) {
    const d = e.detail || {};
    const attestationOk = verifyB64(inc.voucher_pub, attestationMessage(badge.agent_id, e.seq, e.action, d), e.voucher_attestation || '');
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

  // 2c. revocation ground truth (D-24): scan the log for ANY valid per-role revoke event.
  // Any ONE of the three roles is sufficient, and — since the hash-chained log is append-only
  // and tamper-evident (step 4 below) — permanent: no later rotation event can clear it. This
  // is checked independently of, and takes precedence over, the cached `revocation_state` field.
  // Same domain-separated attestation check as isRevoked() (kept inline here so the reported
  // `revokeEvent` detail is available for the step's log line) — the two must never disagree.
  let revokedByLog = false;
  let revokeEvent = null;
  for (const e of log) {
    const pubField = REVOKE_ROLE_PUB_FIELD[e.action];
    if (!pubField) continue;
    const pub = pubField === 'owner_pub' ? inc.owner_pub : inc.voucher_pub;
    const msg = attestationMessage(badge.agent_id, e.seq, e.action, e.detail || {});
    if (verifyB64(pub, msg, e.revoke_attestation || '')) {
      revokedByLog = true;
      revokeEvent = e;
      break;
    }
  }
  push('revocation log scan', !revokedByLog, revokedByLog ? `${revokeEvent.action}: ${revokeEvent.detail?.reason || ''}` : 'no valid revoke event found');

  // 3. the three signatures — verified against the current (post-rotation) keys. Tolerates a
  // trailing run of VALIDLY-ATTESTED revoke-type log entries (D-24) via
  // coreAsSignedBeforeRevoke() — see its own comment above for why that's safe and
  // back-compatible, and for the unsigned-tail-injection fix.
  const msg = coreAsSignedBeforeRevoke(badge);
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

  // 4. hash-chain of the log (tamper-evident) — covers rotation AND revoke entries too
  // (generic over body; revoke's own single-role attestation is checked separately at 2c).
  // KNOWN, ACCEPTED LIMITATION (not fixable from inside a single offline file — flagged, not
  // silently claimed away): this chain proves entries present in `log` haven't been altered or
  // reordered, but proves nothing about entries that have been DELETED from the tail. A SELF-
  // tier badge has no external anchor (no witness/transparency-log service) committing to "the
  // log is at least N entries long", so an attacker holding nothing but the badge's own public
  // JSON can truncate a trailing revoke run and this check — and the whole-badge signature check
  // above, since both operate purely on whatever `log` currently contains — will not detect it.
  // Closing this requires an ONLINE tip-freshness check (WITNESSED/HARDWARE assurance_tier,
  // Wave 3/4+), not a change to this offline verifier. Never claim this chain proves
  // non-truncation; it only proves tamper-evidence of what's present.
  let chainOk = true, prev = 'GENESIS';
  for (const e of log) {
    const { entry_hash, ...body } = e;
    const expect = sha256(prev + '\n' + canonical(body));
    if (expect !== entry_hash || body.prev_hash !== prev) { chainOk = false; break; }
    prev = entry_hash;
  }
  push('log hash-chain intact', chainOk, `${log.length} entries`);

  // 5. offline freshness/revocation state. `revocation_state` is a best-effort CACHE (D-24) —
  // REVOKED is honored if EITHER the log-scan (2c, the real ground truth) OR the cached field
  // says so (kept as an OR-fallback purely for badges revoked by the pre-D-24 code path, which
  // never wrote a log entry — this can only ever ADD a true REVOKED, never hide one).
  // STALE/UNKNOWN are still COMPUTED at verify time, never stored (D-15 offline states).
  const issuedAtMs = inc.issued_at ? Date.parse(inc.issued_at) : NaN;
  const ttlMs = typeof inc.badge_ttl === 'number' ? inc.badge_ttl * 1000 : NaN;
  let offline_state;
  if (revokedByLog || badge.revocation_state === 'REVOKED') offline_state = 'REVOKED';
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
  // SAT-958/SAT-930-sync: SELF-tier badges always carry the honest external-witness disclosure
  // (see SELF_TIER_SCOPE_NOTE above); WITNESSED/HARDWARE tiers (not yet built) would not need
  // this specific caveat once they exist, so the check is tier-conditional even though only
  // SELF exists today.
  let scope_note = ev?.note
    || (assurance_tier === 'SELF' ? SELF_TIER_SCOPE_NOTE
      : 'This verdict attests identity, signatures, and log integrity — not the safety, correctness, or compliance of the agent.');
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

// ---- verify (viaid verify / scan) → honest verdict ----
// Thin fail-closed wrapper around verifyBadgeInner(): hostile/malformed input (found by
// adversarial testing 2026-07-30 — independently, from 3 different angles) must return a clean
// INVALID verdict, never throw an uncaught exception past this boundary.
export function verifyBadge(badge) {
  if (!badge || typeof badge !== 'object') return invalidVerdict('badge is not an object');
  try {
    return verifyBadgeInner(badge);
  } catch (e) {
    return invalidVerdict('verify crashed on malformed/hostile input: ' + (e && e.message ? e.message : String(e)));
  }
}

// ---- verify-time witness check (SAT-934, tier-conditional) — see the SAT-958 follow-up
// comment above mintWitnessedBadge() for provenance/scope. verifyBadge() itself stays 100%
// synchronous and byte-for-byte unchanged; verifyBadgeWitnessed() is a new, purely additive
// async wrapper around it.
//
// Tier-conditional: SELF-tier badges get witness_state: 'NOT_APPLICABLE' and ZERO network
// calls — byte-identical to what verifyBadge() already returns, with one field added.
// WITNESSED-tier badges get an online point-lookup against the witness service BY DEFAULT
// (the opt-in already happened at mint time); pass { checkWitness: false } to force-skip it.
//
// OR-ONLY RULE (mirrors isRevoked()'s local OR-fallback, and this file's own CLAIM DISCIPLINE
// header — never claim a stronger guarantee than what actually happened): the witness can only
// ever ADD a REVOKED verdict the local log doesn't show — it can never clear one the log does
// show, and it never upgrades a structurally INVALID badge into looking like a legitimately-
// signed-then-revoked one, which would misrepresent a forgery as a real prior badge.
//
// witness_state values: CHECKED_CLEAN / CHECKED_REVOKED / UNREACHABLE (call failed or timed
// out, fell back to local-log-only semantics) / NOT_APPLICABLE (SELF-tier) / SKIPPED (caller
// explicitly passed checkWitness: false — a different fact than UNREACHABLE, so kept distinct).
export async function verifyBadgeWitnessed(badge, { checkWitness = true, witnessServiceUrl } = {}) {
  const verdict = verifyBadge(badge);
  const tier = (badge && typeof badge === 'object') ? badge.assurance_tier : undefined;

  if (tier !== 'WITNESSED') {
    return { ...verdict, witness_state: 'NOT_APPLICABLE' };
  }
  if (!checkWitness) {
    return {
      ...verdict, witness_state: 'SKIPPED',
      scope_note: `${verdict.scope_note} The online witness check was explicitly skipped for this verify call — this verdict relies on local-log-only semantics, same as a SELF-tier badge.`,
    };
  }

  const url = witnessServiceUrl || WITNESS_SERVICE_URL;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), WITNESS_HTTP_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${url}/api/witness-status?agent_id=${encodeURIComponent(verdict.agent_id || badge.agent_id || '')}`, { signal: ctrl.signal });
  } catch {
    return {
      ...verdict, witness_state: 'UNREACHABLE',
      scope_note: `${verdict.scope_note} The online witness check was attempted but the witness service was unreachable — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.`,
    };
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    return {
      ...verdict, witness_state: 'UNREACHABLE',
      scope_note: `${verdict.scope_note} The online witness check was attempted but the witness service returned HTTP ${res.status} — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.`,
    };
  }
  let body;
  try { body = await res.json(); } catch {
    return {
      ...verdict, witness_state: 'UNREACHABLE',
      scope_note: `${verdict.scope_note} The online witness check was attempted but the witness service's response was not valid JSON — this verdict fell back to local-log-only semantics, same as a SELF-tier badge, despite being WITNESSED-tier.`,
    };
  }

  if (body && body.witnessed === true) {
    // OR-only escalation: never downgrade an already-INVALID verdict into looking like a
    // legitimately-signed-then-revoked badge — see the function header comment for why.
    const forcedVerdict = verdict.verdict === 'INVALID' ? verdict.verdict : 'REVOKED';
    return {
      ...verdict, verdict: forcedVerdict, witness_state: 'CHECKED_REVOKED',
      scope_note: `${verdict.scope_note} The witness service independently confirms a revocation (${body.action || 'unknown action'}) is on record for this agent_id — this holds even if the locally-presented badge's own log has been truncated to hide it, closing the SELF-tier log-truncation gap described above.`,
    };
  }
  return {
    ...verdict, witness_state: 'CHECKED_CLEAN',
    scope_note: `${verdict.scope_note} The witness service independently confirms no revocation is on record for this agent_id — unlike SELF-tier, this is not solely reliant on the locally-presented badge's own (potentially truncated) log.`,
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
