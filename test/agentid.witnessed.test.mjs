// Regression tests for the SAT-958 WITNESSED-tier code (src/agentid.mjs), added after an
// adversarial multi-model review found 10 confirmed bugs in the original PR. Each test below is
// anchored to one specific finding from that review — see the comment on each `test()` block.
//
// No test framework dependency: node:test + node:assert/strict are built into Node >=18 (this
// package's own engines requirement), so this adds zero new dependencies. Network is never
// touched — `globalThis.fetch` is mocked per test and restored afterward.
//
// VIAID_WITNESS_TIMEOUT_MS is set to a small value BEFORE the dynamic import below so the
// module-level WITNESS_HTTP_TIMEOUT_MS constant picks it up at load time — this keeps the
// timeout/hang tests fast (tens of ms) instead of waiting out a real 10s default.
process.env.VIAID_WITNESS_TIMEOUT_MS = '80';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const aid = await import('../src/agentid.mjs');

function withMockFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return fn().finally(() => { globalThis.fetch = original; });
}

// Bot finding (CodeRabbit test_quality, Major): the two stalled-response-body tests below exist
// specifically to catch a regression in the production abort/timeout wiring (Bug #1). If that
// exact regression reappeared, the mocked hangUntilAborted response would never settle -- its
// promise only resolves when the source code's own AbortController fires, and a regression is
// precisely "the abort never fires" -- so the awaited call would never resolve, and node:test's
// run would hang on this test instead of failing it. Deliberately NOT the same mechanism as the
// code under test (that would just duplicate the bug, not catch it): an independent deadline that
// fails the test on its own terms if the real timeout doesn't fire well within it.
function withDeadline(promise, ms, label) {
  let timer;
  const deadline = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(
      `${label}: exceeded this test's own ${ms}ms deadline -- the production timeout/abort path this test exists to check likely regressed`,
    )), ms);
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

function tmpRoot() {
  return mkdtempSync(join(tmpdir(), 'viaid-test-'));
}

// `signal` must be threaded through from the mocked fetch()'s options so `hangUntilAborted`
// can behave like a REAL stalled fetch body: it only ever settles when the caller's
// AbortController fires, exactly like undici's real Response.json() does. A promise that just
// hangs unconditionally (`new Promise(() => {})`) would NOT reproduce the bug under test — it
// would leave a truly-dangling promise with no relationship to the timeout at all, which the
// source code's abort-driven fix could never resolve, causing node:test itself to flag a stuck
// test rather than exercising the timeout path.
function fakeResponse({ ok = true, status = 200, json, hangUntilAborted = false } = {}, signal) {
  return {
    ok,
    status,
    json: () => {
      if (hangUntilAborted) {
        return new Promise((_resolve, reject) => {
          const abortError = () => reject(new DOMException('The operation was aborted.', 'AbortError'));
          if (signal?.aborted) return abortError();
          signal?.addEventListener('abort', abortError, { once: true });
        });
      }
      if (json instanceof Error) return Promise.reject(json);
      return Promise.resolve(json);
    },
  };
}

// Mirrors mintBadge()'s own agent_id derivation ('via_' + sha256(canonical(inception)).slice(0,32),
// see src/agentid.mjs) so mock witness-register responses below can echo back the SAME agent_id the
// client just derived -- needed now that mintWitnessedBadge() checks the registration response
// actually confirms ITS agent_id (SEC-003, wave 6), mirroring the equivalent check
// verifyBadgeWitnessed() has always applied to witness-status responses.
function computeAgentId(inception) {
  return 'via_' + createHash('sha256').update(aid.canonical(inception)).digest('hex').slice(0, 32);
}

// ---- helpers to get a WITNESSED-tier badge without a real network call, for verify-side tests ----
async function mintFakeWitnessedBadge(root) {
  return withMockFetch(
    async (_url, opts) => {
      const { inception } = JSON.parse(opts.body);
      return fakeResponse({ ok: true, status: 201, json: { already_registered: false, agent_id: computeAgentId(inception) } });
    },
    () => aid.mintWitnessedBadge({ name: 'test-agent', owner: 'tester', workRoot: root }),
  );
}

// ============================================================================================
// Bug #2 [HIGH]: verifyBadgeWitnessed(null) threw instead of returning an invalid verdict — the
// intended `tier` guard ran AFTER verifyBadge(badge), which already crashed on null first.
// ============================================================================================
test('verifyBadgeWitnessed(null) returns an INVALID verdict instead of throwing', async () => {
  const result = await aid.verifyBadgeWitnessed(null);
  assert.equal(result.verdict, 'INVALID');
  assert.equal(result.witness_state, 'NOT_APPLICABLE');
});

test('verifyBadgeWitnessed(undefined) and verifyBadgeWitnessed("string") also do not throw', async () => {
  const r1 = await aid.verifyBadgeWitnessed(undefined);
  assert.equal(r1.verdict, 'INVALID');
  const r2 = await aid.verifyBadgeWitnessed('not-a-badge');
  assert.equal(r2.verdict, 'INVALID');
});

// ============================================================================================
// Bug #3 [HIGH]: the synchronous verifyBadge() gave zero disclosure when called directly on a
// WITNESSED badge (e.g. by the CLI's `viaid verify`, which never calls verifyBadgeWitnessed()).
// ============================================================================================
test('verifyBadge() discloses that a WITNESSED-tier badge was NOT online-checked synchronously', async () => {
  const root = tmpRoot();
  try {
    // POST-REVIEW FIX (decision 1, wave 6): this used to build its fixture via
    // `aid.mintBadge(...)` + a direct `badge.assurance_tier = 'WITNESSED'` mutation with no
    // resign() -- since assurance_tier IS part of the signed core, that mutation silently made
    // the badge structurally INVALID (sigOk false) from the start. That was invisible before
    // because this test never asserted on `.verdict`, only on scope_note text (which the
    // WITNESSED-disclosure branch appends regardless of sigOk). Now that verdict is asserted
    // below, the fixture must be genuinely valid -- mintFakeWitnessedBadge() runs the real
    // mintWitnessedBadge() path (mocked network only) and resigns properly, same as production.
    const badge = await mintFakeWitnessedBadge(root);
    const v = aid.verifyBadge(badge);
    assert.match(v.scope_note, /did not perform the online witness lookup/);
    assert.match(v.scope_note, /verifyBadgeWitnessed/);
    // A fresh, structurally-valid badge would otherwise read VALID here even though the one check
    // WITNESSED tier exists to provide was never attempted -- downgraded to UNKNOWN (round 4/5's
    // confirmed security-1/SEC-001 finding).
    assert.equal(v.verdict, 'UNKNOWN');
    assert.match(v.scope_note, /downgraded from VALID to UNKNOWN/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// POST-REVIEW FIX (decision 1, wave 6): the downgrade above must never SOFTEN an already-worse
// verdict -- INVALID/REVOKED are the worst realistic states a badge can present, and an
// unconfirmed online check must not make either of them read as the merely-uncertain UNKNOWN.
test('verifyBadge() called directly on a WITNESSED badge never masks an already-INVALID or REVOKED verdict', () => {
  const root = tmpRoot();
  try {
    // INVALID case: break id integrity.
    const badgeA = aid.mintBadge({ name: 'a', workRoot: root });
    badgeA.assurance_tier = 'WITNESSED';
    badgeA.agent_id = 'via_tampered0000000000000000000000';
    const vA = aid.verifyBadge(badgeA);
    assert.equal(vA.verdict, 'INVALID');

    // REVOKED case: genuinely revoked (via the real revokeBadge() path, so it stays correctly
    // signed) but never online-checked -- REVOKED must still win, not get "helpfully" downgraded.
    let badgeB = aid.mintBadge({ name: 'b', workRoot: root });
    badgeB.assurance_tier = 'WITNESSED';
    badgeB = aid.revokeBadge(badgeB, root);
    const vB = aid.verifyBadge(badgeB);
    assert.equal(vB.verdict, 'REVOKED');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadge() on a SELF-tier badge keeps its original disclosure (no regression)', () => {
  const root = tmpRoot();
  try {
    const badge = aid.mintBadge({ name: 'a', workRoot: root });
    const v = aid.verifyBadge(badge);
    assert.match(v.scope_note, /SELF-tier revocation is not externally witnessed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ============================================================================================
// Bug #5 [HIGH]: a non-numeric VIAID_WITNESS_TIMEOUT_MS silently collapsed to ~0ms
// (Number("10s") -> NaN -> setTimeout fires almost immediately) instead of the documented 10s
// default. Tested directly against the exported pure parser, independent of module-load timing.
// ============================================================================================
test('parseWitnessTimeoutMs falls back to the default on non-numeric input', () => {
  assert.equal(aid.parseWitnessTimeoutMs('10s'), 10000);
  assert.equal(aid.parseWitnessTimeoutMs(undefined), 10000);
  assert.equal(aid.parseWitnessTimeoutMs(''), 10000);
  assert.equal(aid.parseWitnessTimeoutMs('0'), 10000);
  assert.equal(aid.parseWitnessTimeoutMs('-5'), 10000);
  assert.equal(aid.parseWitnessTimeoutMs(null), 10000);
});

test('parseWitnessTimeoutMs accepts a valid positive numeric override', () => {
  assert.equal(aid.parseWitnessTimeoutMs('5000'), 5000);
  assert.equal(aid.parseWitnessTimeoutMs('250', 10000), 250);
});

// ============================================================================================
// Bug #1 [CRITICAL]: the timeout timer was cleared right after fetch() resolved (headers only),
// so a response that stalled mid-body could hang the call forever. Both call sites are tested.
// ============================================================================================
test('verifyBadgeWitnessed times out a stalled response body instead of hanging forever', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    const start = Date.now();
    const result = await withMockFetch(
      async (_url, opts) => fakeResponse({ ok: true, status: 200, hangUntilAborted: true }, opts?.signal),
      () => withDeadline(aid.verifyBadgeWitnessed(badge), 2000, 'verifyBadgeWitnessed stalled-body test'),
    );
    const elapsedMs = Date.now() - start;
    assert.ok(elapsedMs < 2000, `expected the stalled body to time out quickly, took ${elapsedMs}ms`);
    assert.equal(result.witness_state, 'UNREACHABLE');
    assert.match(result.scope_note, /timed out reading the response body/);
    // Decision 2 [wave 6]: a stalled body is also a connectivity problem, not a badge issue.
    assert.match(result.scope_note, /poor or interrupted network connection/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('mintWitnessedBadge times out a stalled registration response body instead of hanging forever', async () => {
  const root = tmpRoot();
  try {
    const start = Date.now();
    await assert.rejects(
      () => withMockFetch(
        async (_url, opts) => fakeResponse({ ok: true, status: 201, hangUntilAborted: true }, opts?.signal),
        () => withDeadline(aid.mintWitnessedBadge({ name: 'a', workRoot: root }), 2000, 'mintWitnessedBadge stalled-body test'),
      ),
      (err) => {
        assert.match(err.message, /timed out reading the response body/);
        // Decision 2 [wave 6]: a stalled body is also a connectivity problem, not a badge issue.
        assert.match(err.message, /poor or interrupted network connection/);
        return true;
      },
    );
    const elapsedMs = Date.now() - start;
    assert.ok(elapsedMs < 2000, `expected the stalled body to time out quickly, took ${elapsedMs}ms`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// Decision 2 [wave 6]: the fetch()-level catch (DNS failure, connection refused, TLS failure, or
// an abort firing before headers ever arrive) is almost always a connectivity problem on the
// CALLER's end, not a badge or witness-service-logic problem. Paul's explicit direction
// (2026-08-09): tell the user that plainly, scoped ONLY to genuine connectivity failures.
test('mintWitnessedBadge tells the user this looks like a connection problem when the request itself fails', async () => {
  const root = tmpRoot();
  await assert.rejects(
    () => withMockFetch(
      async () => { throw new Error('ECONNREFUSED'); },
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
    ),
    (err) => {
      assert.match(err.message, /ECONNREFUSED/, 'the underlying error detail must still be present');
      assert.match(err.message, /poor or interrupted network connection/, 'must tell the user this looks like a connection problem');
      return true;
    },
  );
  rmSync(root, { recursive: true, force: true });
});

// ============================================================================================
// Bug #7 [HIGH]: a witness-check FAILURE returned the identical top-level `verdict` as a genuine
// online confirmation — only the easy-to-miss `witness_state` field differed, so blocking network
// access to the witness service could force a naive caller (checking only `.verdict`) to see
// "VALID" for a badge whose revocation status was never actually confirmed.
// ============================================================================================
test('verifyBadgeWitnessed downgrades verdict to UNKNOWN when the witness service is unreachable', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    const result = await withMockFetch(
      async () => { throw new Error('ECONNREFUSED'); },
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(result.witness_state, 'UNREACHABLE');
    assert.equal(result.verdict, 'UNKNOWN');
    assert.notEqual(result.verdict, 'VALID');
    // Decision 2 [wave 6]: a rejected fetch() is almost always a connectivity problem on the
    // caller's end -- say so plainly rather than leaving the reader to guess.
    assert.match(result.scope_note, /poor or interrupted network connection/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadgeWitnessed downgrades verdict to UNKNOWN on a non-OK HTTP status', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    const result = await withMockFetch(
      async () => fakeResponse({ ok: false, status: 503 }),
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(result.witness_state, 'UNREACHABLE');
    assert.equal(result.verdict, 'UNKNOWN');
    // Decision 2 [wave 6]: an HTTP error status is a server-side issue, not a connectivity
    // problem on the caller's end -- the retry language must NOT appear here.
    assert.doesNotMatch(result.scope_note, /poor or interrupted network connection/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadgeWitnessed downgrades verdict to UNKNOWN on an invalid JSON body', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    const result = await withMockFetch(
      async () => fakeResponse({ ok: true, status: 200, json: new Error('unexpected token') }),
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(result.witness_state, 'UNREACHABLE');
    assert.equal(result.verdict, 'UNKNOWN');
    // Decision 2 [wave 6]: malformed JSON (not a timeout) is a witness-service-side issue, not a
    // connectivity problem -- "check your connection and retry" would not fix this, so the retry
    // language must NOT appear here. Locks in the precise scoping Paul asked for.
    assert.doesNotMatch(result.scope_note, /poor or interrupted network connection/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadgeWitnessed never masks an already-INVALID verdict, even when the witness service is unreachable', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    badge.agent_id = 'via_tampered0000000000000000000000'; // breaks id integrity -> INVALID
    const result = await withMockFetch(
      async () => { throw new Error('ECONNREFUSED'); },
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(result.verdict, 'INVALID');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ============================================================================================
// Happy-path coverage (not a specific numbered finding, but the functions had zero tests at all
// before this file — bug #8/#9/#10 — so the success paths need direct coverage too).
// ============================================================================================
test('verifyBadgeWitnessed reports CHECKED_REVOKED and forces verdict=REVOKED when witnessed:true', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    const result = await withMockFetch(
      async () => fakeResponse({ ok: true, status: 200, json: { agent_id: badge.agent_id, witnessed: true, action: 'OWNER_REVOKE' } }),
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(result.witness_state, 'CHECKED_REVOKED');
    assert.equal(result.verdict, 'REVOKED');
    assert.match(result.scope_note, /OWNER_REVOKE/);
    // POST-REVIEW FIX (3rd round): scope_note used to still carry verifyBadge()'s "did not
    // perform the online witness lookup" sentence even after the lookup ran and came back
    // positive — directly contradicting the sentence right after it. Caught by CLI smoke-test.
    assert.doesNotMatch(result.scope_note, /did not perform the online witness lookup/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadgeWitnessed reports CHECKED_CLEAN and leaves verdict unchanged when witnessed:false', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    const result = await withMockFetch(
      async () => fakeResponse({ ok: true, status: 200, json: { agent_id: badge.agent_id, witnessed: false } }),
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(result.witness_state, 'CHECKED_CLEAN');
    assert.equal(result.verdict, 'VALID');
    // POST-REVIEW FIX (3rd round): same stale-disclosure bug as the CHECKED_REVOKED case above —
    // "did not perform the online witness lookup" immediately followed by "The witness service
    // independently confirms no revocation is on record" read as self-contradictory.
    assert.doesNotMatch(result.scope_note, /did not perform the online witness lookup/);
    assert.match(result.scope_note, /independently confirms no revocation/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadgeWitnessed on a SELF-tier badge is NOT_APPLICABLE and never calls fetch', async () => {
  const root = tmpRoot();
  try {
    const badge = aid.mintBadge({ name: 'a', workRoot: root });
    let fetchCalled = false;
    const result = await withMockFetch(
      async () => { fetchCalled = true; return fakeResponse(); },
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(result.witness_state, 'NOT_APPLICABLE');
    assert.equal(fetchCalled, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadgeWitnessed with checkWitness:false is SKIPPED and never calls fetch', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    let fetchCalled = false;
    const result = await withMockFetch(
      async () => { fetchCalled = true; return fakeResponse(); },
      () => aid.verifyBadgeWitnessed(badge, { checkWitness: false }),
    );
    assert.equal(result.witness_state, 'SKIPPED');
    // POST-REVIEW FIX (decision 1, wave 6): previously VALID -- an explicitly-skipped online check
    // used to read identically to a genuinely-confirmed-clean one to any caller checking only
    // `.verdict`. Now downgraded to UNKNOWN, matching the check-FAILED case (round 4/5's confirmed
    // security-1/SEC-001 finding; Paul's decision 2026-08-09).
    assert.equal(result.verdict, 'UNKNOWN');
    assert.equal(fetchCalled, false);
    // POST-REVIEW FIX (3rd round): same fix as CHECKED_CLEAN/CHECKED_REVOKED above, covering the
    // fallback-path family (SKIPPED/UNREACHABLE) that previously also re-stated the now-superseded
    // "did not perform the online witness lookup" sentence redundantly alongside their own text.
    assert.doesNotMatch(result.scope_note, /did not perform the online witness lookup/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// POST-REVIEW FIX (decision 1, wave 6): same "never mask a worse verdict" invariant as the direct
// verifyBadge() test above, exercised through the SKIPPED path specifically.
test('verifyBadgeWitnessed with checkWitness:false never masks an already-INVALID or REVOKED verdict', async () => {
  const root = tmpRoot();
  try {
    const badgeA = await mintFakeWitnessedBadge(root);
    badgeA.agent_id = 'via_tampered0000000000000000000000';
    const vA = await aid.verifyBadgeWitnessed(badgeA, { checkWitness: false });
    assert.equal(vA.witness_state, 'SKIPPED');
    assert.equal(vA.verdict, 'INVALID');

    let badgeB = await mintFakeWitnessedBadge(root);
    badgeB = aid.revokeBadge(badgeB, root);
    const vB = await aid.verifyBadgeWitnessed(badgeB, { checkWitness: false });
    assert.equal(vB.witness_state, 'SKIPPED');
    assert.equal(vB.verdict, 'REVOKED');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ============================================================================================
// Bug #4 [HIGH]: raw PII (owner_id, name) is sent to the witness service. This is architecturally
// required (the server recomputes agent_id from the full inception object — see the PRIVACY NOTE
// comment in mintWitnessedBadge()), so this is not "fixable" by withholding fields; the test below
// pins down the disclosed, intentional contract so a future change can't silently start sending
// EVEN MORE than documented without a test noticing, and confirms the mint path still succeeds.
// ============================================================================================
test('mintWitnessedBadge sends the full inception object (documented, disclosed PII contract)', async () => {
  const root = tmpRoot();
  try {
    let sentBody = null;
    const badge = await withMockFetch(
      async (_url, opts) => {
        sentBody = JSON.parse(opts.body);
        return fakeResponse({ ok: true, status: 201, json: { already_registered: false, agent_id: computeAgentId(sentBody.inception) } });
      },
      () => aid.mintWitnessedBadge({ name: 'agent-name', owner: 'owner-identifier', workRoot: root }),
    );
    assert.equal(badge.assurance_tier, 'WITNESSED');
    // Bot finding (CodeRabbit test_quality, Major/Data Integrity): checking only 2 of inception's
    // fields individually meant a future change that silently dropped or altered any OTHER field
    // (owner_pub, agent_pub, voucher_pub, next_key_commitment, key_seq, issued_at, badge_ttl,
    // schema) would still pass this test -- exactly the fields the witness service's agent_id
    // binding depends on (see registrationAttestationMessage()'s header comment: the witness
    // independently recomputes agent_id = hash(canonical(inception)), so any drift here makes
    // every signature fail server-side verification). Full deep-equal against the actual minted
    // badge's inception object catches drift in ANY field, not just the two checked before.
    assert.deepEqual(sentBody.inception, badge.inception, 'the witness must receive the EXACT inception object the badge itself carries, not just name/owner_id');
    assert.ok(sentBody.owner_sig && sentBody.voucher_sig, 'registration must be signed, not bare data');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('mintWitnessedBadge throws a clear error on a non-OK registration response', async () => {
  const root = tmpRoot();
  await assert.rejects(
    () => withMockFetch(
      async () => fakeResponse({ ok: false, status: 409, json: { error: 'agent_id already registered with different keys' } }),
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
    ),
    (err) => {
      assert.match(err.message, /witness-register returned HTTP 409/);
      // Decision 2 [wave 6]: an HTTP error status is a server-side conflict, not a connectivity
      // problem -- the retry language must NOT appear here.
      assert.doesNotMatch(err.message, /poor or interrupted network connection/);
      return true;
    },
  );
  rmSync(root, { recursive: true, force: true });
});

// ============================================================================================
// Second-round findings (from the re-review of the first fix commit) below. Each is anchored to
// one specific finding from that re-review, same pattern as above.
// ============================================================================================

// A malformed badge (object-shaped but missing/empty `.log`) crashed verifyBadge()'s hash-chain
// walk with "undefined is not iterable" instead of surfacing as an INVALID verdict.
//
// POST-REVIEW FIX (3rd review round, 4th fix round): `.log` present but the WRONG shape (a
// non-array truthy value, or an array containing a non-object entry) crashed the same way one
// step earlier/later than the missing-`.log` case above — `badge.log || []` is a truthy test,
// not a type test, so `{}` sailed through unchanged into a `.filter()`/`for...of` that can't
// accept it, and `[null]` passed the array check but broke on destructuring the null entry.
test('verifyBadge / verifyBadgeWitnessed do not crash on a malformed but object-shaped badge', () => {
  for (const malformed of [{}, [], { assurance_tier: 'WITNESSED', inception: {} }, { log: {} }, { log: [null] }, { log: ['not-an-object'] }]) {
    assert.doesNotThrow(() => aid.verifyBadge(malformed));
    const v = aid.verifyBadge(malformed);
    assert.equal(v.verdict, 'INVALID');
  }
});

test('verifyBadgeWitnessed does not crash on a malformed but object-shaped badge', async () => {
  for (const malformed of [{}, [], { assurance_tier: 'WITNESSED', inception: {} }, { log: {} }, { log: [null] }]) {
    const v = await aid.verifyBadgeWitnessed(malformed);
    assert.equal(v.verdict, 'INVALID');
  }
});

// POST-REVIEW FIX (round 6, correctness-2 — confirmed independently by all 5 reviewers this
// round, zero refutations): the test right above this one calls
// `verifyBadgeWitnessed({ assurance_tier: 'WITNESSED', inception: {} })` with NO mocked fetch —
// before this round's fix, that silently sent a real network request to the production default
// WITNESS_SERVICE_URL on every `npm test` run, and that test's own assertion never caught it
// because `verdict` stays 'INVALID' whether or not the call actually fires. This test asserts
// the mechanism directly: fetch must never be invoked at all for a badge that already fails
// local signature/structure verification, regardless of what `witness_service_url` it names —
// closing the SSRF-adjacent/data-leak path an attacker-supplied, never-validly-signed badge
// could otherwise force (arbitrary outbound host, this badge's `agent_id`, and the verifier's
// own IP/timing, all leaked before there was any reason to believe the badge was real).
test('verifyBadgeWitnessed never calls fetch for a badge that is already locally INVALID', async () => {
  let fetchCalls = 0;
  const badge = {
    assurance_tier: 'WITNESSED',
    witness_service_url: 'https://attacker.example', // must never be dialed
    agent_id: 'via_not-the-real-hash',
    inception: {},
    log: [],
  };
  await withMockFetch(
    async () => { fetchCalls++; return fakeResponse({ ok: true, status: 200, json: { agent_id: badge.agent_id, witnessed: false } }); },
    async () => {
      const v = await aid.verifyBadgeWitnessed(badge);
      assert.equal(v.verdict, 'INVALID', 'a structurally-invalid badge must stay INVALID');
      assert.equal(v.witness_state, 'SKIPPED', 'no online check should be attempted for an already-invalid badge');
    },
  );
  assert.equal(fetchCalls, 0, 'fetch must never be called for a badge that already failed local verification — this is the SSRF/leak vector correctness-2 flagged');
});

// POST-REVIEW FIX (3rd review round, 4th fix round): plain verifyBadge() threw on a null/
// undefined/non-object `badge`, and separately crashed on an explicit `null` second argument
// (default-parameter destructuring only covers `undefined`) -- the exact same two bug classes
// already fixed on verifyBadgeWitnessed(), never mirrored onto this function itself.
// verifyBadgeWitnessed()'s OWN null-guard exists specifically because calling verifyBadge()
// directly with a bad badge used to throw (see the comment there) -- that guard protected
// verifyBadgeWitnessed()'s callers but never fixed verifyBadge() for its OTHER callers (the CLI,
// or any library consumer calling it directly), which is what this test pins down.
test('verifyBadge(null/undefined/non-object) returns INVALID instead of throwing', () => {
  for (const bad of [null, undefined, 'not-a-badge', 42, true]) {
    assert.doesNotThrow(() => aid.verifyBadge(bad), `verifyBadge(${JSON.stringify(bad)}) should not throw`);
    const v = aid.verifyBadge(bad);
    assert.equal(v.verdict, 'INVALID');
  }
});

test('verifyBadge(validBadge, null) does not crash', () => {
  const root = tmpRoot();
  try {
    const badge = aid.mintBadge({ name: 'a', workRoot: root });
    assert.doesNotThrow(() => aid.verifyBadge(badge, null));
    assert.equal(aid.verifyBadge(badge, null).verdict, 'VALID');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// An oversized VIAID_WITNESS_TIMEOUT_MS silently collapsed to ~1ms too -- Node's setTimeout
// clamps any delay above 2^31-1ms to ~1ms rather than erroring, so the original NaN-only guard
// let a huge value straight through.
test('parseWitnessTimeoutMs falls back to the default on an oversized value', () => {
  assert.equal(aid.parseWitnessTimeoutMs('9999999999'), 10000);
  assert.equal(aid.parseWitnessTimeoutMs(2 ** 31), 10000);
  assert.equal(aid.parseWitnessTimeoutMs('300000'), 300000); // exactly at the cap: still allowed
  assert.equal(aid.parseWitnessTimeoutMs('300001'), 10000); // just over: falls back
});

// verifyBadgeWitnessed(badge, null) crashed on destructuring `null` -- default parameters only
// apply to `undefined`, not `null`.
test('verifyBadgeWitnessed(badge, null) does not crash', async () => {
  const root = tmpRoot();
  try {
    const badge = aid.mintBadge({ name: 'a', workRoot: root });
    const v = await aid.verifyBadgeWitnessed(badge, null);
    assert.equal(v.witness_state, 'NOT_APPLICABLE'); // SELF-tier badge, opts otherwise ignored
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// A type-skewed `witnessed` field (string "true" / number 1, instead of a real boolean) used to
// fall through to the same branch as `witnessed: false` (silently read as clean) since only
// `=== true` was ever checked positively.
test('verifyBadgeWitnessed treats a non-boolean witnessed field as ambiguous, not clean', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    for (const weirdWitnessed of ['true', 1, 'false', 0, null, undefined]) {
      const result = await withMockFetch(
        async () => fakeResponse({ ok: true, status: 200, json: { agent_id: badge.agent_id, witnessed: weirdWitnessed } }),
        () => aid.verifyBadgeWitnessed(badge),
      );
      assert.equal(result.witness_state, 'UNREACHABLE', `witnessed=${JSON.stringify(weirdWitnessed)} should not be treated as a confirmed answer`);
      assert.equal(result.verdict, 'UNKNOWN');
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// No scheme check previously existed on the witness service URL -- an http:// override would
// silently send signed registration data / revocation queries over plaintext.
test('mintWitnessedBadge refuses a non-HTTPS witness service URL', async () => {
  const root = tmpRoot();
  await assert.rejects(
    () => aid.mintWitnessedBadge({ name: 'a', workRoot: root, witnessServiceUrl: 'http://evil.example.com' }),
    /refusing non-HTTPS/,
  );
  rmSync(root, { recursive: true, force: true });
});

test('mintWitnessedBadge allows http:// to localhost for local development', async () => {
  const root = tmpRoot();
  try {
    const badge = await withMockFetch(
      async (_url, opts) => {
        const { inception } = JSON.parse(opts.body);
        return fakeResponse({ ok: true, status: 201, json: { already_registered: false, agent_id: computeAgentId(inception) } });
      },
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root, witnessServiceUrl: 'http://localhost:4000' }),
    );
    assert.equal(badge.assurance_tier, 'WITNESSED');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadgeWitnessed treats a non-HTTPS witness service URL as an unreachable fallback, never throws, never calls fetch', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    let fetchCalled = false;
    const result = await withMockFetch(
      async () => { fetchCalled = true; return fakeResponse(); },
      () => aid.verifyBadgeWitnessed(badge, { witnessServiceUrl: 'http://evil.example.com' }),
    );
    assert.equal(result.witness_state, 'UNREACHABLE');
    assert.equal(result.verdict, 'UNKNOWN');
    assert.equal(fetchCalled, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ============================================================================================
// Bot finding (CodeRabbit correctness-8): which witness a badge was actually registered against
// was never recorded on the badge itself. Two real consequences, not just missing metadata: (1)
// a recipient couldn't tell a badge registered against the real, official witness apart from one
// registered against a throwaway/test instance; (2) verifyBadgeWitnessed() defaulted to the
// global WITNESS_SERVICE_URL whenever no explicit override was passed, so verifying a badge
// minted against a NON-default witness (e.g. staging) silently checked the WRONG service instead
// of the one it was actually registered with.
// ============================================================================================
test('mintWitnessedBadge records the witness service URL it actually registered against, on the badge', async () => {
  const root = tmpRoot();
  try {
    const badge = await withMockFetch(
      async (_url, opts) => {
        const { inception } = JSON.parse(opts.body);
        return fakeResponse({ ok: true, status: 201, json: { already_registered: false, agent_id: computeAgentId(inception) } });
      },
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root, witnessServiceUrl: 'https://staging.witness.example.com' }),
    );
    assert.equal(badge.witness_service_url, 'https://staging.witness.example.com');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('mintWitnessedBadge records the global default witness URL on the badge when no override is given', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    assert.equal(badge.witness_service_url, 'https://witness.viaid.ai');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("verifyBadgeWitnessed defaults to the badge's own recorded witness_service_url, not the global default, when no explicit override is passed", async () => {
  const root = tmpRoot();
  try {
    const badge = await withMockFetch(
      async (_url, opts) => {
        const { inception } = JSON.parse(opts.body);
        return fakeResponse({ ok: true, status: 201, json: { already_registered: false, agent_id: computeAgentId(inception) } });
      },
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root, witnessServiceUrl: 'https://staging.witness.example.com' }),
    );
    let calledUrl = null;
    const result = await withMockFetch(
      async (url) => { calledUrl = url; return fakeResponse({ ok: true, status: 200, json: { agent_id: badge.agent_id, witnessed: false } }); },
      () => aid.verifyBadgeWitnessed(badge), // no opts — must NOT fall back to the global default
    );
    assert.ok(calledUrl.startsWith('https://staging.witness.example.com'), `expected the badge's own witness URL, got ${calledUrl}`);
    assert.equal(result.witness_state, 'CHECKED_CLEAN');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// POST-REVIEW FIX (round 6, exposed while fixing correctness-2): this test used to
// `delete badge.witness_service_url` on an already-signed badge WITHOUT re-signing it — but
// `witness_service_url` is itself part of the signed core (mintWitnessedBadge sets it, then
// resigns), so deleting it after the fact is indistinguishable from tampering: verifyBadge()
// correctly now sees a broken signature (verdict 'INVALID'), which correctness-2's own fix
// correctly refuses to make an online call for. Fixed by re-signing after the mutation (via the
// now-exported resign()/loadKeys()) so this fixture is what it claims to be — a VALIDLY SIGNED
// badge that genuinely predates the witness_service_url field — not a corrupted one.
test('verifyBadgeWitnessed falls back to the global default witness URL for a pre-existing badge with no witness_service_url field (backward compat)', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    delete badge.witness_service_url; // simulate a badge minted before this fix shipped
    aid.resign(badge, aid.loadKeys(root, badge.agent_id)); // ...and re-sign, exactly like a badge that was genuinely minted without this field would legitimately have been
    let calledUrl = null;
    const result = await withMockFetch(
      async (url) => { calledUrl = url; return fakeResponse({ ok: true, status: 200, json: { agent_id: badge.agent_id, witnessed: false } }); },
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.ok(calledUrl.startsWith('https://witness.viaid.ai'), `expected the global default witness URL, got ${calledUrl}`);
    assert.equal(result.witness_state, 'CHECKED_CLEAN');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("verifyBadgeWitnessed: an explicit opts.witnessServiceUrl override still wins over the badge's own recorded URL", async () => {
  const root = tmpRoot();
  try {
    const badge = await withMockFetch(
      async (_url, opts) => {
        const { inception } = JSON.parse(opts.body);
        return fakeResponse({ ok: true, status: 201, json: { already_registered: false, agent_id: computeAgentId(inception) } });
      },
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root, witnessServiceUrl: 'https://staging.witness.example.com' }),
    );
    let calledUrl = null;
    await withMockFetch(
      async (url) => { calledUrl = url; return fakeResponse({ ok: true, status: 200, json: { agent_id: badge.agent_id, witnessed: false } }); },
      () => aid.verifyBadgeWitnessed(badge, { witnessServiceUrl: 'https://localhost:9999' }),
    );
    assert.ok(calledUrl.startsWith('https://localhost:9999'), `expected the explicit override to win, got ${calledUrl}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ============================================================================================
// 4th review round findings below. Each is anchored to one specific finding from that round,
// same pattern as the 2nd/3rd round sections above.
// ============================================================================================

// test_quality-6 [HIGH]: three separate rounds each added a bespoke regression test for ONE
// specific malformed field right after it crashed verifyBadge() (`.log` missing, then `.log`'s
// shape, now `.evidence.confirmed_profiles`/`downgraded_profiles` — see correctness-3 below) —
// each fix closed exactly the field it found and no other, so a 4th round found yet another one.
// This test asserts the general "never throws, always returns a verdict" contract this file's own
// header comment already claims: first across every TOP-LEVEL object-shaped field verifyBadge()
// reads from (a field replaced wholesale), then across the specific nested array-typed fields one
// level down that the top-level sweep can't reach on its own (a field's own SUB-field replaced).
// Between the two, the NEXT undiscovered malformed field at either level fails HERE generically
// instead of needing its own bespoke round of review to find. (verifyBadgeWitnessed() is not
// separately fuzzed here: it delegates all of this structural checking to verifyBadge()
// internally, and fuzzing it directly would require mocking fetch for every case, which the
// malformed-badge tests above already cover for the shapes that matter there.)
test('verifyBadge never throws for any malformed field, top-level or nested, whatever the garbage shape', () => {
  const GARBAGE = [{}, [], 'x', 42, true, null];
  const FIELDS = ['log', 'inception', 'keys', 'signatures', 'evidence'];
  for (const field of FIELDS) {
    for (const garbage of GARBAGE) {
      const badge = { schema: 'viaid.badge/0.1', agent_id: 'via_test', assurance_tier: 'SELF', [field]: garbage };
      assert.doesNotThrow(() => aid.verifyBadge(badge), `verifyBadge crashed with ${field}=${JSON.stringify(garbage)}`);
      const v = aid.verifyBadge(badge);
      assert.equal(typeof v.verdict, 'string');
      assert.ok(Array.isArray(v.confirmed_profiles), `confirmed_profiles must stay an array with ${field}=${JSON.stringify(garbage)}`);
      assert.ok(Array.isArray(v.downgraded_profiles), `downgraded_profiles must stay an array with ${field}=${JSON.stringify(garbage)}`);
    }
  }
  // Nested one level deeper: `evidence` itself being a well-formed object is exactly the case the
  // top-level sweep above can't exercise (a `{}` `evidence` has no `.confirmed_profiles` to break
  // on) — this is the actual shape correctness-3 crashed on.
  const NESTED_GARBAGE = [{}, 'x', 42, true, null]; // (omit `[]` — that IS the correct type here)
  for (const garbage of NESTED_GARBAGE) {
    for (const badge of [{ evidence: { confirmed_profiles: garbage } }, { evidence: { downgraded_profiles: garbage } }]) {
      assert.doesNotThrow(() => aid.verifyBadge(badge), `verifyBadge crashed on ${JSON.stringify(badge)}`);
    }
  }
});

// correctness-3 [HIGH]: `badge.evidence.confirmed_profiles`/`downgraded_profiles` set to a truthy
// non-array (e.g. `{}`) crashed the `coverage` computation's `.join()` call — the exact same bug
// class as the `.log` fixes above, just a different field, which is why the fuzz test above and
// the shared asArray() helper (src/agentid.mjs) now cover both with one mechanism.
test('verifyBadge does not crash on malformed badge.evidence.confirmed_profiles/downgraded_profiles', () => {
  for (const badge of [
    { evidence: { confirmed_profiles: {}, downgraded_profiles: [] } },
    { evidence: { confirmed_profiles: 'oops' } },
    { evidence: { confirmed_profiles: 42 } },
    { evidence: { confirmed_profiles: [], downgraded_profiles: {} } },
    { evidence: { confirmed_profiles: [{}], downgraded_profiles: [null] } },
  ]) {
    assert.doesNotThrow(() => aid.verifyBadge(badge), `verifyBadge crashed on ${JSON.stringify(badge)}`);
    const v = aid.verifyBadge(badge);
    assert.ok(Array.isArray(v.confirmed_profiles));
    assert.ok(Array.isArray(v.downgraded_profiles));
  }
});

// Self-discovered (not from any review round's panel, but surfaced by this round's mutation-
// testing gate: StrykerJS flagged surviving mutants at the hash-chain walk with zero test coverage
// tampering it directly). The chain-walk logic itself was already correct — these tests prove it,
// closing the coverage gap rather than fixing a live bug. Each asserts on the SPECIFIC
// "log hash-chain intact" step, not just the aggregate verdict, so a mutant that broke only this
// check (while the badge stayed otherwise valid) would still be caught even if some other check
// happened to also fail for the same tampered badge.
test('verifyBadge detects a tampered log entry (hash-chain integrity)', () => {
  const root = tmpRoot();
  try {
    let badge = aid.mintBadge({ name: 'a', workRoot: root });
    badge = aid.appendLog(badge, root, { action: 'deployed', model_used: 'test-model' });
    assert.equal(aid.verifyBadge(badge).verdict, 'VALID', 'sanity: untampered badge is VALID first');

    const tampered = JSON.parse(JSON.stringify(badge));
    tampered.log[0].action = 'something-else'; // mutate a hash-chained field in place
    const v = aid.verifyBadge(tampered);
    assert.equal(v.verdict, 'INVALID');
    const chainStep = v.steps.find((s) => s.step === 'log hash-chain intact');
    assert.equal(chainStep.status, 'FAIL', 'the hash-chain check itself must catch this, not just some other unrelated check');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadge detects a truncated log (a dropped entry breaks the hash chain)', () => {
  const root = tmpRoot();
  try {
    let badge = aid.mintBadge({ name: 'a', workRoot: root });
    badge = aid.appendLog(badge, root, { action: 'first', model_used: null });
    badge = aid.appendLog(badge, root, { action: 'second', model_used: null });
    assert.equal(badge.log.length, 2);

    const truncated = JSON.parse(JSON.stringify(badge));
    truncated.log = [truncated.log[1]]; // drop the first entry; its prev_hash no longer resolves
    const v = aid.verifyBadge(truncated);
    assert.equal(v.verdict, 'INVALID');
    const chainStep = v.steps.find((s) => s.step === 'log hash-chain intact');
    assert.equal(chainStep.status, 'FAIL');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// correctness-2 [HIGH]: an HTTP 2xx status alone used to be treated as proof of a successful
// registration, even when the response body couldn't confirm anything happened server-side.
test('mintWitnessedBadge rejects a 2xx registration response that does not confirm registration', async () => {
  const root = tmpRoot();
  const cases = [
    { label: 'empty object', json: {} },
    { label: 'explicit in-body error', json: { status: 'error', error: 'duplicate agent_id' } },
    { label: 'unparseable body', json: new Error('unexpected token') },
  ];
  for (const { label, json } of cases) {
    await assert.rejects(
      () => withMockFetch(
        async () => fakeResponse({ ok: true, status: 201, json }),
        () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
      ),
      /did not confirm registration/,
      `expected a rejection for ${label}`,
    );
  }
  rmSync(root, { recursive: true, force: true });
});

test('mintWitnessedBadge accepts already_registered:true as a confirmed (idempotent) registration', async () => {
  const root = tmpRoot();
  try {
    const badge = await withMockFetch(
      async (_url, opts) => {
        const { inception } = JSON.parse(opts.body);
        return fakeResponse({ ok: true, status: 200, json: { already_registered: true, agent_id: computeAgentId(inception) } });
      },
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
    );
    assert.equal(badge.assurance_tier, 'WITNESSED');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// Self-discovered (not from any review round's panel): step 1 of mintWitnessedBadge() already
// writes real owner/agent/voucher/next-agent PRIVATE KEY material to workRoot/.keys/<agent_id>.json
// before the network call that can fail. A failed registration used to leave that file orphaned on
// disk forever — referenced by no badge, with no command to find or clean it up. Covers three
// distinct failure modes (non-OK status, service unavailable, unconfirmed-but-2xx) to prove this
// isn't specific to one error path, and loops to prove failures don't accumulate orphans either.
test('mintWitnessedBadge cleans up its keystore file when registration fails — no orphaned private keys, even across repeated failures', async () => {
  const root = tmpRoot();
  try {
    const failures = [
      () => fakeResponse({ ok: false, status: 409, json: { error: 'agent_id already registered with different keys' } }),
      () => fakeResponse({ ok: false, status: 503 }),
      () => fakeResponse({ ok: true, status: 201, json: {} }), // 2xx but unconfirmed — must also clean up
    ];
    for (let i = 0; i < failures.length; i++) {
      await assert.rejects(
        () => withMockFetch(async () => failures[i](), () => aid.mintWitnessedBadge({ name: `agent-${i}`, workRoot: root })),
      );
    }
    const keysDir = join(root, '.keys');
    const remaining = existsSync(keysDir) ? readdirSync(keysDir) : [];
    assert.deepEqual(remaining, [], `expected zero orphaned keystore files after repeated failed mint attempts, found: ${remaining.join(', ')}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// security-3/correctness-4 [medium, not gate-blocking — fixed anyway since it's a small, contained
// addition to code already being touched this round]: the witness-status response was never
// checked to actually be ABOUT the agent_id just queried — a caching bug, a load-balancer routing
// mix-up, or a buggy witness deployment ignoring the query param would previously be trusted
// blindly.
test('verifyBadgeWitnessed treats a witness response for the WRONG agent_id as untrustworthy (UNREACHABLE)', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    const result = await withMockFetch(
      async () => fakeResponse({ ok: true, status: 200, json: { agent_id: 'via_some_other_agent_entirely', witnessed: false } }),
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(result.witness_state, 'UNREACHABLE');
    assert.equal(result.verdict, 'UNKNOWN');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadgeWitnessed treats a witness response missing agent_id entirely as untrustworthy (UNREACHABLE)', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    const result = await withMockFetch(
      async () => fakeResponse({ ok: true, status: 200, json: { witnessed: false } }), // no agent_id field at all
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(result.witness_state, 'UNREACHABLE');
    assert.equal(result.verdict, 'UNKNOWN');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ============================================================================================
// SEC-003 [wave 6, decision 3]: the witness-register (mint) response was never checked to
// actually confirm registration for THIS badge's agent_id -- a generic success response with no
// agent_id, or (in a misconfigured/multi-tenant deployment) someone else's agent_id, was
// previously still accepted as proof of a successful registration. Mirrors the equivalent
// witness-status checks directly above (correctness-4/security-3, wave 4), now added to the mint
// side. Confirmed safe against viaid-witness's real contract before implementing (2026-08-09):
// both success paths (new registration and idempotent already-registered retry) are guaranteed by
// the server's own SQL (RETURNING/SELECT agent_id, lib/db.mjs) and its own e2e test suite to
// include the correct agent_id -- see src/agentid.mjs's comment at this check for the sourcing.
// ============================================================================================
test('mintWitnessedBadge rejects a registration response missing agent_id entirely, and leaves no orphaned keys', async () => {
  const root = tmpRoot();
  await assert.rejects(
    () => withMockFetch(
      async () => fakeResponse({ ok: true, status: 201, json: { already_registered: false } }), // no agent_id field at all
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
    ),
    /refusing to trust a response for the wrong agent/,
  );
  const keysDir = join(root, '.keys');
  const remaining = existsSync(keysDir) ? readdirSync(keysDir) : [];
  assert.deepEqual(remaining, [], 'a rejected (unconfirmed-agent) registration must not leave orphaned keys');
  rmSync(root, { recursive: true, force: true });
});

test('mintWitnessedBadge rejects a registration response confirming the WRONG agent_id, and leaves no orphaned keys', async () => {
  const root = tmpRoot();
  await assert.rejects(
    () => withMockFetch(
      async () => fakeResponse({ ok: true, status: 201, json: { already_registered: false, agent_id: 'via_some_other_agent_entirely' } }),
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
    ),
    /refusing to trust a response for the wrong agent/,
  );
  const keysDir = join(root, '.keys');
  const remaining = existsSync(keysDir) ? readdirSync(keysDir) : [];
  assert.deepEqual(remaining, [], 'a rejected (wrong-agent) registration must not leave orphaned keys');
  rmSync(root, { recursive: true, force: true });
});

test("mintWitnessedBadge accepts a registration response that correctly confirms this badge's agent_id", async () => {
  const root = tmpRoot();
  try {
    const badge = await withMockFetch(
      async (_url, opts) => {
        const { inception } = JSON.parse(opts.body);
        return fakeResponse({ ok: true, status: 201, json: { already_registered: false, agent_id: computeAgentId(inception) } });
      },
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
    );
    assert.equal(badge.assurance_tier, 'WITNESSED');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ============================================================================================
// 5th review round findings below (this round's own adversarial review, found independently by
// three reviewers: correctness-2, data_privacy-F1, SEC-004).
// ============================================================================================

// Regression test for the mintBadge()/loadKeys() try-block boundary fix: previously these ran
// BEFORE the try block that protects against orphaned keys, so a failure between them (or inside
// mintBadge() itself) was either unprotected or, in mintBadge()'s specific case, unreachable via
// the catch's `badge.agent_id` reference (badge didn't exist yet). This drives a real failure
// through mintBadge() itself (workRoot is a FILE, not a directory, so the internal saveKeys() ->
// mkdirSync(dirname(p), {recursive:true}) throws ENOTDIR before anything is written anywhere) and
// confirms the error propagates cleanly with no crash in the cleanup path itself.
test('mintWitnessedBadge propagates a mintBadge()-level failure cleanly (nothing was ever written, so cleanup is correctly skipped)', async () => {
  const root = tmpRoot();
  try {
    const workRootAsFile = join(root, 'not-a-directory');
    writeFileSync(workRootAsFile, 'x');
    // Asserts the SPECIFIC original filesystem error (code ENOTDIR) propagates unchanged, not
    // just "some" rejection -- a buggy cleanup guard that crashed on `badge` being undefined
    // (e.g. an unconditional `badge.agent_id` access instead of the `if (badge && ...)` check)
    // would also reject, but with a DIFFERENT (TypeError) message, which a bare assert.rejects()
    // with no pattern would not have caught.
    await assert.rejects(
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: workRootAsFile }),
      (err) => err.code === 'ENOTDIR',
      'expected the original ENOTDIR error to propagate unchanged, not a secondary error from the cleanup guard',
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// SEC-002 regression: assertSafeWitnessUrl() only validates the INITIAL URL; fetch() follows
// redirects by default with no scheme re-validation on the target. Both fetch() call sites now
// pass redirect:'manual', which turns a redirect into an opaqueredirect response (ok:false,
// status:0) instead of following it. Each test below asserts TWO things, deliberately: (1) that
// the source code actually requests redirect:'manual' on the call (inspecting the mock's own
// `opts` argument) -- without this, a test that only supplies a canned opaqueredirect-shaped
// response would still pass even if the fix were reverted, since the pre-existing `!res.ok`
// handling (added in an earlier round for ordinary non-2xx responses) would coincidentally also
// "handle" a hand-crafted opaqueredirect object without redirect:'manual' ever being set for
// real; and (2) that this codebase's own handling of the resulting response shape fails closed
// (the redirect-vs-follow behavior itself is a Node/undici guarantee, not retested here).
test('mintWitnessedBadge requests redirect:manual and fails closed on a redirect response, leaving no orphaned keys', async () => {
  const root = tmpRoot();
  try {
    let sawRedirectOption;
    await assert.rejects(
      () => withMockFetch(
        async (_url, opts) => {
          sawRedirectOption = opts?.redirect;
          return { ok: false, status: 0, type: 'opaqueredirect', json: () => Promise.reject(new Error('no body on an opaque redirect')) };
        },
        () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
      ),
      /witness-register returned HTTP 0/,
    );
    assert.equal(sawRedirectOption, 'manual', 'the witness-register fetch() must set redirect:"manual" so a redirect is never silently followed');
    const keysDir = join(root, '.keys');
    const remaining = existsSync(keysDir) ? readdirSync(keysDir) : [];
    assert.deepEqual(remaining, [], 'a rejected (redirected) registration must not leave orphaned keys either');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('verifyBadgeWitnessed requests redirect:manual and treats a redirect response as unreachable (UNKNOWN)', async () => {
  const root = tmpRoot();
  try {
    const badge = await mintFakeWitnessedBadge(root);
    let sawRedirectOption;
    const result = await withMockFetch(
      async (_url, opts) => {
        sawRedirectOption = opts?.redirect;
        return { ok: false, status: 0, type: 'opaqueredirect', json: () => Promise.reject(new Error('no body on an opaque redirect')) };
      },
      () => aid.verifyBadgeWitnessed(badge),
    );
    assert.equal(sawRedirectOption, 'manual', 'the witness-status fetch() must set redirect:"manual" so a redirect is never silently followed');
    assert.equal(result.witness_state, 'UNREACHABLE');
    assert.equal(result.verdict, 'UNKNOWN');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ============================================================================================
// reliability-3 / test_quality-F2 (5th review round): removeOrphanedKeys() used to swallow any
// cleanup failure other than ENOENT — logged via console.warn, then fully discarded, with no way
// for a caller to know private key material might still be sitting on disk. This exercises a
// GENUINE cleanup failure (not a mock): the keystore file mintBadge() actually wrote is swapped
// out for a directory at the same path before the registration call fails, so removeOrphanedKeys()'s
// own unlinkSync() call hits a real EISDIR/EPERM. This works identically whether the test runs as
// root or not — unlike a chmod-based permission test, which root bypasses — because unlink() on a
// directory is rejected by the kernel unconditionally, not by a permission check.
// ============================================================================================
test('mintWitnessedBadge surfaces a cleanup failure on the original error instead of silently swallowing it', async () => {
  const root = tmpRoot();
  try {
    await assert.rejects(
      () => withMockFetch(
        async () => {
          const keysDir = join(root, '.keys');
          const [keystoreFile] = readdirSync(keysDir);
          const keystorePath = join(keysDir, keystoreFile);
          rmSync(keystorePath, { force: true });
          mkdirSync(keystorePath); // same path, now a directory -> unlinkSync() must fail, not silently succeed
          return fakeResponse({ ok: false, status: 503 });
        },
        () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
      ),
      (err) => {
        assert.match(err.message, /witness-register returned HTTP 503/, 'the ORIGINAL registration error must still propagate unchanged -- cleanup failing must never mask it');
        assert.equal(err.keystoreCleanupFailed, true, 'the original error must be annotated when cleanup itself also fails');
        assert.ok(err.keystoreCleanupError, 'the underlying cleanup error must be attached, not discarded');
        assert.notEqual(err.keystoreCleanupError.code, 'ENOENT', 'sanity: this must be a real non-ENOENT cleanup failure, not the already-covered missing-file case');
        return true;
      },
    );
  } finally {
    rmSync(root, { recursive: true, force: true }); // recursive:true handles the now-a-directory keystore path fine
  }
});

test('mintWitnessedBadge does NOT set keystoreCleanupFailed when cleanup genuinely succeeds (no regression on the happy path)', async () => {
  const root = tmpRoot();
  await assert.rejects(
    () => withMockFetch(
      async () => fakeResponse({ ok: false, status: 503 }),
      () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
    ),
    (err) => {
      assert.equal(err.keystoreCleanupFailed, undefined);
      assert.equal(err.keystoreCleanupError, undefined);
      return true;
    },
  );
  rmSync(root, { recursive: true, force: true });
});
