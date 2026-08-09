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
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '..', 'bin', 'viaid.mjs');

// A real (not mocked) local HTTP server standing in for witness.viaid.ai, so this test exercises
// actual loopback network I/O through the CLI subprocess, not an in-process fetch mock.
function startMockWitness({ witnessed = false } = {}) {
  const calls = [];
  const server = createServer((req, res) => {
    calls.push(`${req.method} ${req.url}`);
    if (req.method === 'POST' && req.url.startsWith('/api/witness-register')) {
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ already_registered: false }));
      return;
    }
    if (req.method === 'GET' && req.url.startsWith('/api/witness-status')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ witnessed }));
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

    assert.equal(calls.length, 0, `expected zero witness-service calls for a SELF-tier badge; calls seen: ${calls.join(', ') || '(none)'}`);
  } finally {
    server.close();
    rmSync(work, { recursive: true, force: true });
  }
});
