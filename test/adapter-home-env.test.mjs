import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import * as gs from "../src/adapters/graphsmith.mjs";
import * as ks from "../src/adapters/knosky.mjs";

// SAT-960: graphsmith.mjs and knosky.mjs used to default GRAPHSMITH_HOME/KNOSKY_HOME to a
// fixed, shared, predictable path under /tmp ('/tmp/gs-src', '/tmp/ks-src') whenever the env
// var wasn't set. Both adapters execute code found under that directory (evaluate() spawns
// `node` against a script there; knosky's core() dynamically import()s modules from it, and
// buildCity() spawns its indexer script), so any other local user/process able to write to
// /tmp could pre-place content at that exact path ahead of time. Fixed: neither adapter falls
// back to a default any more -- the env var must be set explicitly, or the adapter is simply
// unavailable / fails loudly the moment something tries to actually use it.

async function withEnv(name, value, fn) {
  const had = Object.prototype.hasOwnProperty.call(process.env, name);
  const prev = process.env[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
  try {
    return await fn();
  } finally {
    if (had) process.env[name] = prev;
    else delete process.env[name];
  }
}

// -------- GraphSmith --------

test("graphsmithAvailable() returns false (not a thrown error) when GRAPHSMITH_HOME is unset", async () => {
  await withEnv("GRAPHSMITH_HOME", undefined, () => {
    assert.equal(gs.graphsmithAvailable(), false);
  });
});

test("evaluate() fails loudly naming GRAPHSMITH_HOME when it is unset, instead of silently trying a shared /tmp default", async () => {
  await withEnv("GRAPHSMITH_HOME", undefined, () => {
    assert.throws(() => gs.evaluate(os.tmpdir()), /GRAPHSMITH_HOME is not set/);
  });
});

test("evaluate() reports a distinct 'not found at <path>' error once GRAPHSMITH_HOME is set but incomplete, proving the env var (not a /tmp fallback) is what's consulted", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-gs-home-empty-"));
  try {
    await withEnv("GRAPHSMITH_HOME", home, () => {
      assert.equal(gs.graphsmithAvailable(), false, "no scripts/verify.js present, so not available");
      assert.throws(
        () => gs.evaluate(os.tmpdir()),
        (err) => {
          assert.match(err.message, /GraphSmith not found at/);
          assert.ok(err.message.includes(home), "error should name the configured home, not a hidden /tmp default");
          return true;
        }
      );
    });
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("graphsmithAvailable() returns true once GRAPHSMITH_HOME points at a real-looking checkout", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-gs-home-real-"));
  try {
    fs.mkdirSync(path.join(home, "scripts"), { recursive: true });
    fs.writeFileSync(path.join(home, "scripts", "verify.js"), "// fake\n");
    await withEnv("GRAPHSMITH_HOME", home, () => {
      assert.equal(gs.graphsmithAvailable(), true);
    });
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// -------- KnoSky --------

test("knoskyAvailable() returns false (not a thrown error) when KNOSKY_HOME is unset", async () => {
  await withEnv("KNOSKY_HOME", undefined, () => {
    assert.equal(ks.knoskyAvailable(), false);
  });
});

test("buildCity() fails loudly naming KNOSKY_HOME when it is unset, instead of silently trying a shared /tmp default", async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-ks-out-"));
  try {
    await withEnv("KNOSKY_HOME", undefined, () => {
      assert.throws(
        () => ks.buildCity(out, path.join(out, "city.json")),
        /KNOSKY_HOME is not set/
      );
    });
  } finally {
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test("issuePass() (KnoSky core modules, resolved via dynamic import) also fails loudly when KNOSKY_HOME is unset", async () => {
  await withEnv("KNOSKY_HOME", undefined, () =>
    assert.rejects(
      () => ks.issuePass(os.tmpdir(), "via_" + "0".repeat(32)),
      /KNOSKY_HOME is not set/
    )
  );
});

test("knoskyAvailable() returns true once KNOSKY_HOME points at a real-looking checkout", async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-ks-home-real-"));
  try {
    fs.mkdirSync(path.join(home, "core"), { recursive: true });
    fs.writeFileSync(path.join(home, "core", "mode-b.mjs"), "// fake\n");
    fs.mkdirSync(path.join(home, "node_modules"), { recursive: true });
    await withEnv("KNOSKY_HOME", home, () => {
      assert.equal(ks.knoskyAvailable(), true);
    });
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
