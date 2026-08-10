import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const realInstallJs = path.join(here, "..", "scripts", "install.js");
const SKIP_MESSAGE = /skipped — destination is inside this package's own source/;

// Isolated $HOME so the installer's unconditional USER_TARGETS scan (~/.claude,
// ~/.codex, ~/.gemini, ...) can never see — or write into — whatever real agent
// directories happen to exist on the machine running this test. Without this, the
// child process inherits the real HOME and a fake test package can get installed for
// real (this happened to this repo once already, from this exact test file).
function isolatedHomeEnv() {
  const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-home-"));
  return { fakeHome, env: { ...process.env, HOME: fakeHome, USERPROFILE: fakeHome } };
}

test("install.js --project run from its own source root does not recursively copy itself", () => {
  // Minimal fake package laid out the same way as the real repo (scripts/install.js
  // at the top level) so SRC = path.resolve(__dirname, "..") resolves to `tmp` — the
  // exact condition that used to trigger a runaway self-copy when no .cursor/.windsurf/
  // .devin directory is present and --project falls back to installing into cwd.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-test-"));
  const { fakeHome, env } = isolatedHomeEnv();
  try {
    fs.mkdirSync(path.join(tmp, "scripts"));
    fs.copyFileSync(realInstallJs, path.join(tmp, "scripts", "install.js"));
    fs.writeFileSync(path.join(tmp, "SKILL.md"), "# fake skill\n");

    const output = execFileSync(process.execPath, [path.join(tmp, "scripts", "install.js"), "--project"], {
      cwd: tmp,
      env,
      timeout: 10_000,
      encoding: "utf8",
    });

    assert.match(output, SKIP_MESSAGE, "should print the self-copy skip message");
    const dst = path.join(tmp, ".agents", "skills", "viaid");
    assert.ok(!fs.existsSync(dst), "should skip rather than copy the source into itself");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.rmSync(fakeHome, { recursive: true, force: true });
  }
});

test("install.js --project skips when the destination is reached through a symlink into the source", () => {
  // Same failure mode as above, but reached one hop removed: the agent's skills dir is
  // a symlink pointing back into the package's own source tree (e.g. a dev symlinking
  // ~/.claude/skills at a checkout for local iteration). A purely lexical
  // path.resolve(dst) comparison can't see through this — only realpath-based
  // resolution (fs.realpathSync.native) catches it before copyDir starts writing.
  const pkg = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-symlink-pkg-"));
  const { fakeHome, env } = isolatedHomeEnv();
  try {
    fs.mkdirSync(path.join(pkg, "scripts"));
    fs.copyFileSync(realInstallJs, path.join(pkg, "scripts", "install.js"));
    fs.writeFileSync(path.join(pkg, "SKILL.md"), "# fake skill\n");

    fs.mkdirSync(path.join(fakeHome, ".claude"));
    fs.symlinkSync(pkg, path.join(fakeHome, ".claude", "skills"), "dir");

    const output = execFileSync(process.execPath, [path.join(pkg, "scripts", "install.js")], {
      cwd: fakeHome,
      env,
      timeout: 10_000,
      encoding: "utf8",
    });

    assert.match(output, SKIP_MESSAGE, "should print the self-copy skip message");
    // test_quality-2 (adversarial review, run-20260810-010724): this existsSync check
    // alone doesn't prove the containment guard specifically fired -- an unrelated
    // early failure would also leave "viaid" uncreated. The SKIP_MESSAGE match above is
    // the primary proof; this is a secondary, defense-in-depth check.
    assert.ok(
      !fs.existsSync(path.join(pkg, "viaid")),
      "should not have recursively copied the source into itself via the symlink"
    );
  } finally {
    fs.rmSync(pkg, { recursive: true, force: true });
    fs.rmSync(fakeHome, { recursive: true, force: true });
  }
});

test("install.js --project still installs normally when the destination is not inside the source", () => {
  // Same fake package, but run from a separate empty project directory (dst is not
  // inside SRC here) — the ordinary, most common --project case must keep working.
  const pkg = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-pkg-"));
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-proj-"));
  const { fakeHome, env } = isolatedHomeEnv();
  try {
    fs.mkdirSync(path.join(pkg, "scripts"));
    fs.copyFileSync(realInstallJs, path.join(pkg, "scripts", "install.js"));
    fs.writeFileSync(path.join(pkg, "SKILL.md"), "# fake skill\n");

    execFileSync(process.execPath, [path.join(pkg, "scripts", "install.js"), "--project"], {
      cwd: proj,
      env,
      timeout: 10_000,
    });

    const dst = path.join(proj, ".agents", "skills", "viaid");
    assert.ok(fs.existsSync(path.join(dst, "SKILL.md")), "should install into the target project");
  } finally {
    fs.rmSync(pkg, { recursive: true, force: true });
    fs.rmSync(proj, { recursive: true, force: true });
    fs.rmSync(fakeHome, { recursive: true, force: true });
  }
});

test("install.js --project skips a symlinked entry in the source tree instead of copying its target's contents", () => {
  // security-1 (adversarial review, run-20260810-010724): copyDir used to dereference
  // symlinks via fs.copyFileSync because Dirent.isDirectory() reports false for a
  // symlink even when it points at a directory -- so a symlink in the source tree
  // pointing at a sensitive file outside the package would have that file's *contents*
  // copied into every detected agent's skills directory. This proves the fix: a
  // symlinked entry is skipped entirely, not dereferenced.
  const pkg = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-symlink-src-pkg-"));
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-symlink-src-proj-"));
  const { fakeHome, env } = isolatedHomeEnv();
  const marker = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-marker-"));
  try {
    fs.mkdirSync(path.join(pkg, "scripts"));
    fs.copyFileSync(realInstallJs, path.join(pkg, "scripts", "install.js"));
    fs.writeFileSync(path.join(pkg, "SKILL.md"), "# fake skill\n");

    const markerFile = path.join(marker, "secret.txt");
    fs.writeFileSync(markerFile, "MARKER-CONTENT-SHOULD-NOT-BE-COPIED\n");
    fs.symlinkSync(markerFile, path.join(pkg, "secret-link"));

    execFileSync(process.execPath, [path.join(pkg, "scripts", "install.js"), "--project"], {
      cwd: proj,
      env,
      timeout: 10_000,
    });

    const dst = path.join(proj, ".agents", "skills", "viaid");
    assert.ok(fs.existsSync(path.join(dst, "SKILL.md")), "install should still succeed for the rest of the package");
    assert.ok(!fs.existsSync(path.join(dst, "secret-link")), "symlinked entry should not be copied at all");
  } finally {
    fs.rmSync(pkg, { recursive: true, force: true });
    fs.rmSync(proj, { recursive: true, force: true });
    fs.rmSync(fakeHome, { recursive: true, force: true });
    fs.rmSync(marker, { recursive: true, force: true });
  }
});

test("install.js --project never copies a .adversarial-review directory into the installed skill", () => {
  // security-3 / test_quality-1 (adversarial review, run-20260810-010724): copyDir's
  // exclusion list added ".adversarial-review" (gitignored local review-run data --
  // model reasoning, cost/token figures, full diffs sent to reviewers) but had no
  // regression test proving it. This is that test.
  const pkg = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-review-pkg-"));
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), "viaid-install-review-proj-"));
  const { fakeHome, env } = isolatedHomeEnv();
  try {
    fs.mkdirSync(path.join(pkg, "scripts"));
    fs.copyFileSync(realInstallJs, path.join(pkg, "scripts", "install.js"));
    fs.writeFileSync(path.join(pkg, "SKILL.md"), "# fake skill\n");
    fs.mkdirSync(path.join(pkg, ".adversarial-review"), { recursive: true });
    fs.writeFileSync(path.join(pkg, ".adversarial-review", "leak.txt"), "should not leave this machine\n");

    execFileSync(process.execPath, [path.join(pkg, "scripts", "install.js"), "--project"], {
      cwd: proj,
      env,
      timeout: 10_000,
    });

    const dst = path.join(proj, ".agents", "skills", "viaid");
    assert.ok(fs.existsSync(path.join(dst, "SKILL.md")), "install should still succeed for the rest of the package");
    assert.ok(!fs.existsSync(path.join(dst, ".adversarial-review")), ".adversarial-review must never be copied");
  } finally {
    fs.rmSync(pkg, { recursive: true, force: true });
    fs.rmSync(proj, { recursive: true, force: true });
    fs.rmSync(fakeHome, { recursive: true, force: true });
  }
});
