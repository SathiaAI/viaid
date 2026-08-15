// CLI-level integration test — regression guard for the CRITICAL finding from the 2nd
// adversarial review round: mintWitnessedBadge()/verifyBadgeWitnessed() existed in
// src/agentid.mjs but bin/viaid.mjs never called them (no `await`, no `--witnessed` flag, no
// tier dispatch in verify/scan) — the WITNESSED tier was reachable only by importing the
// library directly, never by anyone actually running `viaid`. Every other test in this suite
// imports src/agentid.mjs directly, so none of them could have caught that gap — only actually
// spawning the real `bin/viaid.mjs` binary as a subprocess proves the wiring itself works.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, readFileSync, readdirSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { canonical } from '../src/agentid.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '..', 'bin', 'viaid.mjs');

// A real (not mocked) local HTTP server standing in for witness.viaid.ai, so this test exercises
// actual loopback network I/O through the CLI subprocess, not an in-process fetch mock.
function startMockWitness({ witnessed = false } = {}) {
  const calls = [];
  const server = createServer((req, res) => {
    calls.push(`${req.method} ${req.url}`);
    if (req.method === 'POST' && req.url.startsWith('/api/witness-register')) {
      // POST-REVIEW FIX (decision 3, wave 6, SEC-003): the real contract echoes `agent_id` back in
      // the registration response too, not just witness-status (see src/agentid.mjs's
      // mintWitnessedBadge() agent_id-matching check, and its comment for the confirmed sourcing
      // against viaid-witness's actual code). This mock now derives and returns it the same way
      // the real witness service does (hash of the client-sent `inception`, imported from the
      // same canonical() this repo's own client and the real server both use) instead of a
      // generic body that would now fail that check. Only `canonical()` — a pure, I/O-free
      // function — is imported here; the subprocess/real-network-I/O property this file's header
      // comment describes is unaffected.
      let raw = '';
      req.on('data', (chunk) => { raw += chunk; });
      req.on('end', () => {
        let agentId = '';
        try {
          const { inception } = JSON.parse(raw);
          agentId = 'via_' + createHash('sha256').update(canonical(inception)).digest('hex').slice(0, 32);
        } catch { /* malformed body -- leave agentId empty, not this test file's concern */ }
        res.writeHead(201, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ already_registered: false, agent_id: agentId }));
      });
      return;
    }
    if (req.method === 'GET' && req.url.startsWith('/api/witness-status')) {
      // POST-REVIEW FIX (4th round): the real contract echoes `agent_id` back in the response so
      // the caller can confirm it got an answer about the agent it actually queried (see
      // src/agentid.mjs's verifyBadgeWitnessed() agent_id-matching check) — this mock now does
      // the same instead of always answering generically, which would fail that check.
      const agentId = new URL(req.url, 'http://127.0.0.1').searchParams.get('agent_id') || '';
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ agent_id: agentId, witnessed }));
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found in mock' }));
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, calls, port: server.address().port }));
  });
}

// Bounded with its own kill-on-timeout safeguard, independent of node:test's own timeout, so a
// regression that makes the CLI hang fails fast with a clear message instead of hanging the run.
function runCli(args, env, { timeoutMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env });
    let stdout = '', stderr = '', settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new Error(`CLI process timed out after ${timeoutMs}ms: viaid ${args.join(' ')}\nstdout so far: ${stdout}\nstderr so far: ${stderr}`));
    }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => { if (settled) return; settled = true; clearTimeout(timer); reject(e); });
    child.on('close', (code) => { if (settled) return; settled = true; clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

test('CLI: init --witnessed / verify / scan actually talk to the witness service end-to-end', async () => {
  const { server, calls, port } = await startMockWitness({ witnessed: false });
  const work = mkdtempSync(join(tmpdir(), 'viaid-cli-test-'));
  try {
    const env = { ...process.env, VIAID_WORK: work, VIAID_WITNESS_URL: `http://127.0.0.1:${port}`, VIAID_WITNESS_TIMEOUT_MS: '3000' };

    const init = await runCli(['init', 'cli-test-agent', '--witnessed'], env);
    assert.equal(init.code, 0, `init --witnessed exited nonzero: ${init.stderr}`);
    assert.match(init.stdout, /tier=WITNESSED/);
    const idMatch = init.stdout.match(/via_[a-f0-9]+/);
    assert.ok(idMatch, `no agent_id found in init output: ${init.stdout}`);
    const id = idMatch[0];

    const verify = await runCli(['verify', id], env);
    assert.equal(verify.code, 0, `verify exited nonzero: ${verify.stderr}`);
    assert.match(verify.stdout, /witness=CHECKED_CLEAN/);

    const scan = await runCli(['scan', id], env);
    assert.equal(scan.code, 0, `scan exited nonzero: ${scan.stderr}`);
    assert.match(scan.stdout, /witness=CHECKED_CLEAN/);

    // The actual regression guard: prove the CLI process really reached the witness service over
    // the network, not just that it printed plausible-looking text.
    assert.ok(
      calls.some((c) => c.startsWith('POST /api/witness-register')),
      `expected a witness-register call from init --witnessed; calls seen: ${calls.join(', ') || '(none)'}`,
    );
    assert.ok(
      calls.filter((c) => c.startsWith('GET /api/witness-status')).length >= 2,
      `expected 2 witness-status calls (verify + scan); calls seen: ${calls.join(', ') || '(none)'}`,
    );
  } finally {
    server.close();
    rmSync(work, { recursive: true, force: true });
  }
});

// POST-REVIEW FIX (4th round, correctness-1): `init([name = 'my-agent', ...flags])` treated argv
// position 0 as the name unconditionally, so `--witnessed` appearing BEFORE (or instead of) a
// name argument was never recognized as a flag at all — it silently became the badge's `name`
// while the real name (if any) was discarded and the badge minted at SELF tier with no error. The
// test above already covers the one ordering that happened to work (name then flag); these two
// cover the two that didn't.
test('CLI: init --witnessed (no explicit name) still mints WITNESSED tier, not a SELF-tier badge literally named "--witnessed"', async () => {
  const { server, calls, port } = await startMockWitness({ witnessed: false });
  const work = mkdtempSync(join(tmpdir(), 'viaid-cli-test-'));
  try {
    const env = { ...process.env, VIAID_WORK: work, VIAID_WITNESS_URL: `http://127.0.0.1:${port}`, VIAID_WITNESS_TIMEOUT_MS: '3000' };
    const init = await runCli(['init', '--witnessed'], env);
    assert.equal(init.code, 0, `init --witnessed exited nonzero: ${init.stderr}`);
    assert.match(init.stdout, /tier=WITNESSED/, 'flag-before-name (here: no name at all) must still mint WITNESSED tier');
    assert.ok(
      calls.some((c) => c.startsWith('POST /api/witness-register')),
      `expected a witness-register call; calls seen: ${calls.join(', ') || '(none)'}`,
    );
    const idMatch = init.stdout.match(/via_[a-f0-9]+/);
    assert.ok(idMatch, `no agent_id found in init output: ${init.stdout}`);
    const badge = JSON.parse(readFileSync(join(work, `${idMatch[0]}.badge.json`), 'utf8'));
    assert.equal(badge.inception.name, 'my-agent', 'omitting the name entirely should fall back to the documented default, not literally become "--witnessed"');
  } finally {
    server.close();
    rmSync(work, { recursive: true, force: true });
  }
});

test('CLI: init --witnessed my-named-agent (flag before an explicit name) mints WITNESSED tier and keeps the given name', async () => {
  const { server, port } = await startMockWitness({ witnessed: false });
  const work = mkdtempSync(join(tmpdir(), 'viaid-cli-test-'));
  try {
    const env = { ...process.env, VIAID_WORK: work, VIAID_WITNESS_URL: `http://127.0.0.1:${port}`, VIAID_WITNESS_TIMEOUT_MS: '3000' };
    const init = await runCli(['init', '--witnessed', 'my-named-agent'], env);
    assert.equal(init.code, 0, `init exited nonzero: ${init.stderr}`);
    assert.match(init.stdout, /tier=WITNESSED/);
    const idMatch = init.stdout.match(/via_[a-f0-9]+/);
    assert.ok(idMatch, `no agent_id found in init output: ${init.stdout}`);
    const badge = JSON.parse(readFileSync(join(work, `${idMatch[0]}.badge.json`), 'utf8'));
    assert.equal(badge.inception.name, 'my-named-agent', 'the explicit name must survive, not be swallowed by the flag');
  } finally {
    server.close();
    rmSync(work, { recursive: true, force: true });
  }
});

test('CLI: init without --witnessed stays SELF-tier and never talks to the witness service', async () => {
  const { server, calls, port } = await startMockWitness();
  const work = mkdtempSync(join(tmpdir(), 'viaid-cli-test-'));
  try {
    const env = { ...process.env, VIAID_WORK: work, VIAID_WITNESS_URL: `http://127.0.0.1:${port}`, VIAID_WITNESS_TIMEOUT_MS: '3000' };

    const init = await runCli(['init', 'cli-test-agent'], env);
    assert.equal(init.code, 0, `init exited nonzero: ${init.stderr}`);
    assert.match(init.stdout, /tier=SELF/);
    const idMatch = init.stdout.match(/via_[a-f0-9]+/);
    assert.ok(idMatch, `no agent_id found in init output: ${init.stdout}`);
    const id = idMatch[0];

    const verify = await runCli(['verify', id], env);
    assert.equal(verify.code, 0, `verify exited nonzero: ${verify.stderr}`);
    assert.doesNotMatch(verify.stdout, /witness=/);

    // Bot finding (CodeRabbit nitpick): this test covered `verify` staying offline for a
    // SELF-tier badge, but not `scan` -- the CLI's other command that branches on assurance_tier
    // the same way (see bin/viaid.mjs's scan()). A regression that routed SELF-tier `scan`
    // through verifyBadgeWitnessed() would still have passed this test.
    const scan = await runCli(['scan', id], env);
    assert.equal(scan.code, 0, `scan exited nonzero: ${scan.stderr}`);
    assert.doesNotMatch(scan.stdout, /witness=/);

    assert.equal(calls.length, 0, `expected zero witness-service calls for a SELF-tier badge; calls seen: ${calls.join(', ') || '(none)'}`);
  } finally {
    server.close();
    rmSync(work, { recursive: true, force: true });
  }
});

// POST-REVIEW FIX (wave 6, reliability-3 follow-up): src/agentid.mjs's mintWitnessedBadge() has
// annotated a mint error with keystoreCleanupFailed/keystoreCleanupError since the 5th review
// round (see the library-level 'mintWitnessedBadge surfaces a cleanup failure...' test in
// test/agentid.witnessed.test.mjs), but bin/viaid.mjs's top-level catch never read those
// properties — a real `viaid` run silently dropped this diagnostic. This is the CLI-level
// counterpart of that library-level test: a real subprocess, a real registration failure, and a
// real (root-independent) cleanup failure, verifying the extra line actually reaches the user's
// terminal. Uses the SAME swap-the-keystore-file-for-a-directory technique as the library-level
// test — unlinkSync() on a directory is rejected by the kernel unconditionally, unlike a
// chmod-based permission test, which root (this sandbox's user) would bypass. The swap happens
// from the mock witness server's own request handler, which runs in THIS (parent) process and
// shares the real filesystem with the child CLI subprocess — by the time a POST /api/
// witness-register request arrives, the child has already synchronously written its keystore
// file (mintBadge() runs before the network call), so this is a safe, deterministic
// synchronization point, not a timing race.
test('CLI: surfaces a keystore-cleanup failure to the user when one happens alongside a mint failure', async () => {
  const work = mkdtempSync(join(tmpdir(), 'viaid-cli-test-'));
  const server = createServer((req, res) => {
    if (req.method === 'POST' && req.url.startsWith('/api/witness-register')) {
      req.resume();
      req.on('end', () => {
        const keysDir = join(work, '.keys');
        const [keystoreFile] = readdirSync(keysDir);
        const keystorePath = join(keysDir, keystoreFile);
        rmSync(keystorePath, { force: true });
        mkdirSync(keystorePath); // same path, now a directory -> the client's cleanup unlinkSync() must fail
        res.writeHead(503, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'service unavailable' }));
      });
      return;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found in mock' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = server.address().port;
    const env = { ...process.env, VIAID_WORK: work, VIAID_WITNESS_URL: `http://127.0.0.1:${port}`, VIAID_WITNESS_TIMEOUT_MS: '3000' };
    const init = await runCli(['init', 'cleanup-fail-agent', '--witnessed'], env);
    assert.notEqual(init.code, 0, 'a failed registration must still exit nonzero');
    assert.match(init.stderr, /witness-register returned HTTP 503/, 'the original mint error must still be shown, not masked by the cleanup failure');
    assert.match(init.stderr, /could not clean up the local private-key file/i, 'a keystore-cleanup failure must be surfaced to the user, not silently dropped');
  } finally {
    server.close();
    rmSync(work, { recursive: true, force: true });
  }
});
