import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const checker = path.join(repoRoot, ".github", "claude-code", "check-managed-settings.py");
const pinJson = path.join(repoRoot, ".github", "claude-code", "managed-settings.json");
const wrapper = path.join(repoRoot, ".github", "claude-code", "ar-panel-run");
const panelPy = path.join(repoRoot, ".claude", "skills", "adversarial-review", "scripts", "panel.py");
const commonPy = path.join(repoRoot, ".claude", "skills", "adversarial-review", "scripts");

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, {
    encoding: "utf8",
    timeout: 15_000,
    cwd: repoRoot,
    ...opts,
    env: { ...process.env, ...(opts.env || {}) },
  });
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("committed managed-settings.json passes parse-or-refuse", () => {
  const r = run("python3", [checker, pinJson]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /OK: managed-settings readable and parseable/);
});

test("committed managed-settings.json locks fail-closed keys and the closed wrapper", () => {
  const data = JSON.parse(fs.readFileSync(pinJson, "utf8"));
  assert.equal(data.allowManagedPermissionRulesOnly, true);
  assert.equal(data.permissions.defaultMode, "dontAsk");
  assert.equal(data.permissions.disableBypassPermissionsMode, "disable");
  assert.ok(data.permissions.allow.includes("Bash(/usr/local/bin/ar-panel-run)"));
  assert.ok(
    data.permissions.allow.every((rule) => !rule.includes("panel.py run")),
    "panel.py run must not be allowlisted directly",
  );
  assert.ok(
    data.permissions.deny.some((rule) => rule.includes("panel.py run")),
    "panel.py run must be denied as a backstop",
  );
});

test("parse-or-refuse fails on missing file", () => {
  const r = run("python3", [checker, path.join(os.tmpdir(), "no-such-managed-settings.json")]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /missing file/);
});

test("parse-or-refuse fails on unparseable JSON", () => {
  const dir = tmpDir("viaid-ms-badjson-");
  const bad = path.join(dir, "managed-settings.json");
  try {
    fs.writeFileSync(bad, "{ not json\n");
    const r = run("python3", [checker, bad]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /unparseable JSON/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse fails on empty file", () => {
  const dir = tmpDir("viaid-ms-empty-");
  const empty = path.join(dir, "managed-settings.json");
  try {
    fs.writeFileSync(empty, "   \n");
    const r = run("python3", [checker, empty]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /empty file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse fails when required lock keys are missing", () => {
  const dir = tmpDir("viaid-ms-nokeys-");
  const file = path.join(dir, "managed-settings.json");
  try {
    fs.writeFileSync(file, JSON.stringify({ permissions: { allow: ["Bash(*)"] } }));
    const r = run("python3", [checker, file]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /allowManagedPermissionRulesOnly/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse fails if a PR-style panel.py run:* allow sneaks in", () => {
  const dir = tmpDir("viaid-ms-wildcard-");
  const file = path.join(dir, "managed-settings.json");
  try {
    const data = JSON.parse(fs.readFileSync(pinJson, "utf8"));
    data.permissions.allow.push(
      "Bash(python3 .claude/skills/adversarial-review/scripts/panel.py run:*)",
    );
    fs.writeFileSync(file, JSON.stringify(data));
    const r = run("python3", [checker, file]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /panel\.py run/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse refuses a symlink dest", () => {
  const dir = tmpDir("viaid-ms-symlink-");
  const real = path.join(dir, "real.json");
  const link = path.join(dir, "managed-settings.json");
  try {
    fs.copyFileSync(pinJson, real);
    fs.symlinkSync(real, link);
    const r = run("python3", [checker, link]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /symlink/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("concur --prompt-file refuses a path outside AR_RUN_DIR", () => {
  const runDir = tmpDir("viaid-ar-run-");
  const outside = path.join(os.tmpdir(), `viaid-outside-${process.pid}.txt`);
  try {
    fs.writeFileSync(outside, "secret=1\n");
    const r = run("python3", [panelPy, "concur", "--prompt-file", outside], {
      env: { AR_RUN_DIR: runDir },
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /must be under AR_RUN_DIR/);
    assert.doesNotMatch(r.stderr, /OPENROUTER|api key|catalog/i);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
    fs.rmSync(outside, { force: true });
  }
});

test("concur --prompt-file refuses a symlink that escapes AR_RUN_DIR", () => {
  const runDir = tmpDir("viaid-ar-run-");
  const leak = path.join(os.tmpdir(), `viaid-environ-${process.pid}.txt`);
  const decoy = path.join(runDir, "prompt.md");
  try {
    fs.writeFileSync(leak, "SECRET=exfil\n");
    fs.symlinkSync(leak, decoy);
    const r = run("python3", [panelPy, "concur", "--prompt-file", decoy], {
      env: { AR_RUN_DIR: runDir },
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /must be under AR_RUN_DIR/);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
    fs.rmSync(leak, { force: true });
  }
});

test("require_under_run_root accepts a real file inside AR_RUN_DIR", () => {
  const runDir = tmpDir("viaid-ar-run-");
  const prompt = path.join(runDir, "validation-prompt.md");
  try {
    fs.writeFileSync(prompt, "finding evidence\n");
    const code = `
import sys
sys.path.insert(0, ${JSON.stringify(commonPy)})
from _common import require_under_run_root
print(require_under_run_root(${JSON.stringify(prompt)}, "--prompt-file"))
`;
    const r = run("python3", ["-c", code], { env: { AR_RUN_DIR: runDir } });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(fs.realpathSync(r.stdout.trim()), fs.realpathSync(prompt));
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test("closed wrapper refuses extra arguments", () => {
  const r = run("bash", [wrapper, "--context-file", "context.md"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /closed wrapper/);
});

test("closed wrapper refuses when AR_RUN_DIR is unset", () => {
  const env = { ...process.env };
  delete env.AR_RUN_DIR;
  const r = run("bash", [wrapper], { env });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /AR_RUN_DIR is unset/);
});

test("closed wrapper refuses a context.md symlink that escapes AR_RUN_DIR", () => {
  const runDir = tmpDir("viaid-ar-wrap-");
  const leak = path.join(os.tmpdir(), `viaid-wrap-leak-${process.pid}.md`);
  try {
    fs.writeFileSync(leak, "leak\n");
    fs.symlinkSync(leak, path.join(runDir, "context.md"));
    const r = run("bash", [wrapper], {
      env: { AR_RUN_DIR: runDir, GITHUB_WORKSPACE: repoRoot },
    });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /outside AR_RUN_DIR/);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
    fs.rmSync(leak, { force: true });
  }
});

test("workflow writes managed settings from a non-PR source before Claude", () => {
  const yml = fs.readFileSync(
    path.join(repoRoot, ".github", "workflows", "adversarial-review-gate.yml"),
    "utf8",
  );
  const writeIdx = yml.indexOf("Write Claude managed settings (non-PR source, parse-or-refuse)");
  const claudeIdx = yml.indexOf("anthropics/claude-code-action@");
  assert.ok(writeIdx !== -1, "missing managed-settings write step");
  assert.ok(claudeIdx !== -1, "missing claude-code-action step");
  assert.ok(writeIdx < claudeIdx, "managed settings must be written before claude-code-action");
  assert.match(yml, /\/etc\/claude-code\/managed-settings\.json/);
  assert.match(yml, /secrets\.CLAUDE_MANAGED_SETTINGS/);
  assert.match(yml, /_viaid-enforcement-pin/);
  assert.match(yml, /github\.event\.pull_request\.base\.sha/);
  assert.match(yml, /workflow-owned-bootstrap/);
  assert.match(yml, /parse-or-refuse/);
  assert.doesNotMatch(
    yml.slice(writeIdx, claudeIdx),
    /cp\s+[^\n]*\.claude\/settings\.json/,
    "write step must not copy PR-controlled .claude/settings.json",
  );
});
