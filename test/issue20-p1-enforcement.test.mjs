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

function pinClone() {
  return JSON.parse(fs.readFileSync(pinJson, "utf8"));
}

function writeSettings(dir, data) {
  const file = path.join(dir, "managed-settings.json");
  fs.writeFileSync(file, JSON.stringify(data));
  return file;
}

test("committed managed-settings.json locks fail-closed keys and the closed wrapper", () => {
  const data = pinClone();
  assert.equal(data.allowManagedPermissionRulesOnly, true);
  assert.equal(data.permissions.defaultMode, "dontAsk");
  assert.equal(data.permissions.disableBypassPermissionsMode, "disable");
  assert.equal(data.permissions.disableAutoMode, "disable");
  assert.ok(data.permissions.allow.includes("Bash(/usr/local/bin/ar-panel-run)"));
  assert.ok(
    data.permissions.allow.every((rule) => !rule.includes("panel.py run")),
    "panel.py run must not be allowlisted directly",
  );
  assert.ok(
    data.permissions.deny.includes(
      "Bash(python .claude/skills/adversarial-review/scripts/panel.py run:*)",
    ),
  );
  assert.ok(
    data.permissions.deny.includes(
      "Bash(python3 .claude/skills/adversarial-review/scripts/panel.py run:*)",
    ),
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
  try {
    const data = pinClone();
    data.permissions.allow.push(
      "Bash(python3 .claude/skills/adversarial-review/scripts/panel.py run:*)",
    );
    const r = run("python3", [checker, writeSettings(dir, data)]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /panel\.py run/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse fails when permissions.disableAutoMode is missing", () => {
  const dir = tmpDir("viaid-ms-noauto-");
  try {
    const data = pinClone();
    delete data.permissions.disableAutoMode;
    const r = run("python3", [checker, writeSettings(dir, data)]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /disableAutoMode/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse fails when permissions.disableAutoMode is not disable", () => {
  const dir = tmpDir("viaid-ms-badauto-");
  try {
    const data = pinClone();
    data.permissions.disableAutoMode = true;
    const r = run("python3", [checker, writeSettings(dir, data)]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /disableAutoMode/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse rejects Bash(*) even when the wrapper rule is present", () => {
  const dir = tmpDir("viaid-ms-bashstar-");
  try {
    const data = pinClone();
    data.permissions.allow.push("Bash(*)");
    const r = run("python3", [checker, writeSettings(dir, data)]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /Bash\(\*\)/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse rejects a panel.py:* superset that re-enables run", () => {
  const dir = tmpDir("viaid-ms-panelsuper-");
  try {
    const data = pinClone();
    data.permissions.allow.push(
      "Bash(python3 .claude/skills/adversarial-review/scripts/panel.py:*)",
    );
    const r = run("python3", [checker, writeSettings(dir, data)]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /panel\.py run|rejected/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse rejects Bash(python3:*) as a panel-run superset", () => {
  const dir = tmpDir("viaid-ms-py3star-");
  try {
    const data = pinClone();
    data.permissions.allow.push("Bash(python3:*)");
    const r = run("python3", [checker, writeSettings(dir, data)]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /panel\.py run|unbounded|rejected/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("parse-or-refuse fails when the panel.py run deny backstop is missing", () => {
  const dir = tmpDir("viaid-ms-nodeny-");
  try {
    const data = pinClone();
    data.permissions.deny = data.permissions.deny.filter(
      (rule) => !rule.includes("panel.py run"),
    );
    const r = run("python3", [checker, writeSettings(dir, data)]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /permissions\.deny must include/);
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
    assert.match(r.stderr, /symlink|no-follow|must be under AR_RUN_DIR/);
    assert.doesNotMatch(r.stderr, /OPENROUTER|api key|catalog/i);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
    fs.rmSync(leak, { force: true });
  }
});

test("concur --prompt-file refuses an unreadable file before catalog work", () => {
  const runDir = tmpDir("viaid-ar-run-");
  const prompt = path.join(runDir, "prompt.md");
  try {
    fs.writeFileSync(prompt, "finding evidence\n");
    fs.chmodSync(prompt, 0);
    const r = run("python3", [panelPy, "concur", "--prompt-file", prompt], {
      env: { AR_RUN_DIR: runDir },
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /cannot open|not a readable|Permission denied/i);
    assert.doesNotMatch(r.stderr, /OPENROUTER|api key|catalog/i);
  } finally {
    fs.chmodSync(prompt, 0o644);
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test("prepare --context-file refuses a path outside AR_RUN_DIR", () => {
  const runDir = tmpDir("viaid-ar-run-");
  const outside = path.join(os.tmpdir(), `viaid-prep-outside-${process.pid}.md`);
  try {
    fs.writeFileSync(outside, "secret=1\n");
    const r = run("python3", [panelPy, "prepare", "--context-file", outside], {
      env: { AR_RUN_DIR: runDir },
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /must be under AR_RUN_DIR/);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
    fs.rmSync(outside, { force: true });
  }
});

test("prepare --context-file refuses a symlink that escapes AR_RUN_DIR", () => {
  const runDir = tmpDir("viaid-ar-run-");
  const leak = path.join(os.tmpdir(), `viaid-prep-leak-${process.pid}.md`);
  const decoy = path.join(runDir, "context.md");
  try {
    fs.writeFileSync(leak, "SECRET=exfil\n");
    fs.symlinkSync(leak, decoy);
    const r = run("python3", [panelPy, "prepare", "--context-file", decoy], {
      env: { AR_RUN_DIR: runDir },
    });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /symlink|no-follow|must be under AR_RUN_DIR/);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
    fs.rmSync(leak, { force: true });
  }
});

test("panel.py run --context-file refuses a path outside AR_RUN_DIR", () => {
  const runDir = tmpDir("viaid-ar-run-");
  const outside = path.join(os.tmpdir(), `viaid-run-outside-${process.pid}.md`);
  try {
    fs.writeFileSync(outside, "context\n");
    const r = run("python3", [panelPy, "run", "--context-file", outside], {
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

test("read_under_run_root returns file bytes from a single no-follow open", () => {
  const runDir = tmpDir("viaid-ar-run-");
  const prompt = path.join(runDir, "validation-prompt.md");
  try {
    fs.writeFileSync(prompt, "finding evidence\n");
    const code = `
import sys
sys.path.insert(0, ${JSON.stringify(commonPy)})
from _common import read_under_run_root
print(read_under_run_root(${JSON.stringify(prompt)}, "--prompt-file"), end="")
`;
    const r = run("python3", ["-c", code], { env: { AR_RUN_DIR: runDir } });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, "finding evidence\n");
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
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
    assert.match(r.stderr, /outside AR_RUN_DIR|symlink|no-follow/);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
    fs.rmSync(leak, { force: true });
  }
});

test("closed wrapper refuses an in-tree context.md symlink (no-follow)", () => {
  const runDir = tmpDir("viaid-ar-wrap-");
  try {
    fs.writeFileSync(path.join(runDir, "real-context.md"), "ok\n");
    fs.symlinkSync(path.join(runDir, "real-context.md"), path.join(runDir, "context.md"));
    const r = run("bash", [wrapper], {
      env: { AR_RUN_DIR: runDir, GITHUB_WORKSPACE: repoRoot },
    });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /symlink|no-follow/);
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
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
  assert.match(yml, /disableAutoMode must be "disable"/);
  assert.match(yml, /Bash\(\*\)/);
  assert.match(yml, /permissions\.deny must include/);
  assert.doesNotMatch(
    yml.slice(writeIdx, claudeIdx),
    /cp\s+[^\n]*\.claude\/settings\.json/,
    "write step must not copy PR-controlled .claude/settings.json",
  );
});
