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
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const aid = await import('../src/agentid.mjs');

function withMockFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return fn().finally(() => { globalThis.fetch = original; });
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

// ---- helpers to get a WITNESSED-tier badge without a real network call, for verify-side tests ----
async function mintFakeWitnessedBadge(root) {
  return withMockFetch(
    async () => fakeResponse({ ok: true, status: 201, json: { already_registered: false } }),
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
test('verifyBadge() discloses that a WITNESSED-tier badge was NOT online-checked synchronously', () => {
  const root = tmpRoot();
  try {
    const badge = aid.mintBadge({ name: 'a', workRoot: root });
    badge.assurance_tier = 'WITNESSED'; // simulate a WITNESSED badge without the network round trip
    const v = aid.verifyBadge(badge);
    assert.match(v.scope_note, /did not perform the online witness lookup/);
    assert.match(v.scope_note, /verifyBadgeWitnessed/);
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
      () => aid.verifyBadgeWitnessed(badge),
    );
    const elapsedMs = Date.now() - start;
    assert.ok(elapsedMs < 2000, `expected the stalled body to time out quickly, took ${elapsedMs}ms`);
    assert.equal(result.witness_state, 'UNREACHABLE');
    assert.match(result.scope_note, /timed out reading the response body/);
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
        () => aid.mintWitnessedBadge({ name: 'a', workRoot: root }),
      ),
      /timed out reading the response body/,
    );
    const elapsedMs = Date.now() - start;
    assert.ok(elapsedMs < 2000, `expected the stalled body to time out quickly, took ${elapsedMs}ms`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
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
    assert.equal(result.verdict, 'VALID');
    assert.equal(fetchCalled, false);
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
      async (_url, opts) => { sentBody = JSON.parse(opts.body); return fakeResponse({ ok: true, status: 201, json: { already_registered: false } }); },
      () => aid.mintWitnessedBadge({ name: 'agent-name', owner: 'owner-identifier', workRoot: root }),
    );
    assert.equal(badge.assurance_tier, 'WITNESSED');
    assert.equal(sentBody.inception.name, 'agent-name');
    assert.equal(sentBody.inception.owner_id, 'owner-identifier');
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
    /witness-register returned HTTP 409/,
  );
  rmSync(root, { recursive: true, force: true });
});
