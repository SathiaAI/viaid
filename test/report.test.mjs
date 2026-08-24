import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// `viaid report <dir>` — local-only badge count for whoever operates a workRoot (a solo dev,
// or a company running VIA ID for its own internal fleet). No network call is involved; these
// tests only exercise the local file-walking/aggregation behavior.

const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.join(here, "..", "bin", "viaid.mjs");

function fakeBadge({ tier = "SELF", revoked = false } = {}) {
  return JSON.stringify({
    agent_id: `via_test_${Math.random().toString(16).slice(2)}`,
    assurance_tier: tier,
    revocation_state: revoked ? "REVOKED" : "FRESH",
    inception: { issued_at: new Date().toISOString() },
    log: [],
  });
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function runReport(dir) {
  return execFileSync(process.execPath, [cli, "report", dir], {
    timeout: 10_000,
    encoding: "utf8",
  });
}

test("report counts badges by tier and active/revoked state", () => {
  const dir = tmpDir("viaid-report-basic-");
  try {
    fs.writeFileSync(path.join(dir, "a.badge.json"), fakeBadge({ tier: "SELF" }));
    fs.writeFileSync(path.join(dir, "b.badge.json"), fakeBadge({ tier: "WITNESSED" }));
    fs.writeFileSync(path.join(dir, "c.badge.json"), fakeBadge({ tier: "WITNESSED", revoked: true }));

    const output = runReport(dir);

    assert.match(output, /Badges in .*: 3\s+\(active 2, revoked 1, 0 file\(s\) skipped\)/);
    assert.match(output, /SELF: 1/);
    assert.match(output, /WITNESSED: 2/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("report against an empty directory reports all-zero counts without crashing", () => {
  const dir = tmpDir("viaid-report-empty-");
  try {
    const output = runReport(dir);
    assert.match(output, /Badges in .*: 0\s+\(active 0, revoked 0, 0 file\(s\) skipped\)/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("report skips a corrupted badge file with a warning instead of crashing or miscounting it", () => {
  const dir = tmpDir("viaid-report-corrupt-");
  try {
    fs.writeFileSync(path.join(dir, "good.badge.json"), fakeBadge({ tier: "SELF" }));
    fs.writeFileSync(path.join(dir, "broken.badge.json"), "{not valid json");

    const output = runReport(dir);

    assert.match(output, /⚠ skipping broken\.badge\.json/, "should warn about the broken file by name");
    assert.match(output, /Badges in .*: 1\s+\(active 1, revoked 0, 1 file\(s\) skipped\)/, "the corrupted file must not count toward the total");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("report ignores files that don't end in .badge.json", () => {
  const dir = tmpDir("viaid-report-ignore-");
  try {
    fs.writeFileSync(path.join(dir, "a.badge.json"), fakeBadge({ tier: "SELF" }));
    fs.writeFileSync(path.join(dir, "README.md"), "# not a badge\n");
    fs.writeFileSync(path.join(dir, "notes.json"), "{}");

    const output = runReport(dir);

    assert.match(output, /Badges in .*: 1\s+\(active 1, revoked 0, 0 file\(s\) skipped\)/, "non-.badge.json files should not be walked at all, not even counted as skipped");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("report on a nonexistent directory fails loudly rather than silently reporting zero", () => {
  const dir = path.join(os.tmpdir(), "viaid-report-does-not-exist-" + Math.random().toString(16).slice(2));
  assert.throws(
    () => runReport(dir),
    (err) => {
      assert.equal(err.status, 1);
      assert.match(err.stderr.toString(), /no such directory/);
      return true;
    }
  );
});

test("report skips a null badge file with a warning instead of crashing the whole command", () => {
  // Regression test: JSON.parse("null") succeeds and returns `null`, so a *.badge.json file
  // containing exactly `null` used to pass loadBadge() untouched, then crash the entire
  // report (outside any per-file try/catch) the moment its properties were read.
  const dir = tmpDir("viaid-report-null-");
  try {
    fs.writeFileSync(path.join(dir, "good.badge.json"), fakeBadge({ tier: "SELF" }));
    fs.writeFileSync(path.join(dir, "null.badge.json"), "null");

    const output = runReport(dir);

    assert.match(output, /⚠ skipping null\.badge\.json/, "should warn about the null-valued file by name");
    assert.match(output, /Badges in .*: 1\s+\(active 1, revoked 0, 1 file\(s\) skipped\)/, "a file containing only `null` must not crash the report or count toward the total");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("report skips a badge file whose JSON is an array rather than an object", () => {
  const dir = tmpDir("viaid-report-array-");
  try {
    fs.writeFileSync(path.join(dir, "good.badge.json"), fakeBadge({ tier: "SELF" }));
    fs.writeFileSync(path.join(dir, "array.badge.json"), "[1,2,3]");

    const output = runReport(dir);

    assert.match(output, /⚠ skipping array\.badge\.json/, "should warn about the array-shaped file by name");
    assert.match(output, /Badges in .*: 1\s+\(active 1, revoked 0, 1 file\(s\) skipped\)/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("report does not follow a symlink to read badge data from outside the scanned directory", () => {
  const dir = tmpDir("viaid-report-symlink-");
  const outside = tmpDir("viaid-report-outside-");
  try {
    fs.writeFileSync(path.join(dir, "good.badge.json"), fakeBadge({ tier: "SELF" }));
    const externalBadge = path.join(outside, "external.badge.json");
    fs.writeFileSync(externalBadge, fakeBadge({ tier: "WITNESSED" }));
    fs.symlinkSync(externalBadge, path.join(dir, "linked.badge.json"));

    const output = runReport(dir);

    assert.match(output, /⚠ skipping linked\.badge\.json/, "a symlink must be skipped, not followed, to keep data from outside dir out of the count");
    assert.match(output, /Badges in .*: 1\s+\(active 1, revoked 0, 1 file\(s\) skipped\)/, "only the one real file inside dir should count");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("report skips a named pipe (FIFO) without hanging, now that it's opened rather than just lstat'd", () => {
  // Regression test for the O_NOFOLLOW/O_NONBLOCK hardening: report now opens each file
  // (rather than lstat-then-read on the path) to close a symlink-swap race window. That
  // means a special file like a named pipe is genuinely opened, not just stat'd, so this
  // proves the O_NONBLOCK flag is doing its job — a FIFO with no writer must still be
  // skipped promptly, not hang the whole report. runReport()'s own 10s exec timeout would
  // fail this test with a timeout error if that ever regressed.
  const dir = tmpDir("viaid-report-fifo-");
  try {
    fs.writeFileSync(path.join(dir, "good.badge.json"), fakeBadge({ tier: "SELF" }));
    execFileSync("mkfifo", [path.join(dir, "pipe.badge.json")]);

    const output = runReport(dir);

    assert.match(output, /⚠ skipping pipe\.badge\.json/, "a named pipe must be skipped, not read, and must not block the report");
    assert.match(output, /Badges in .*: 1\s+\(active 1, revoked 0, 1 file\(s\) skipped\)/, "only the one real file inside dir should count");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("report never writes into or otherwise mutates the directory it scans", () => {
  const dir = tmpDir("viaid-report-readonly-");
  try {
    fs.writeFileSync(path.join(dir, "a.badge.json"), fakeBadge({ tier: "SELF" }));
    const before = fs.readdirSync(dir).sort();
    runReport(dir);
    const after = fs.readdirSync(dir).sort();
    assert.deepEqual(after, before, "report is read-only: it must not create, delete, or modify any file in the scanned directory");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
