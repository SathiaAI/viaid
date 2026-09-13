import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as aid from "../src/agentid.mjs";

// SAT-959: badgePath() (bin/viaid.mjs) and keystorePath() (src/agentid.mjs) used to build
// filesystem paths directly from a caller-supplied id with no validation. A value containing
// '..' segments escapes the intended directory via join()'s ordinary traversal resolution.
// The canonical id format (the one mintBadge() actually produces) is 'via_' followed by exactly
// 32 lowercase hex characters. Both path-builders must now reject anything else, loudly, before
// the path is ever constructed — not silently sanitize the value and continue.

const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.join(here, "..", "bin", "viaid.mjs");

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function runCli(args, extraEnv = {}) {
  return execFileSync(process.execPath, [cli, ...args], {
    timeout: 10_000,
    encoding: "utf8",
    env: { ...process.env, ...extraEnv },
  });
}

// -------- unit-level: the shared validator in src/agentid.mjs --------

test("isValidAgentId accepts a real minted agent_id and rejects everything else", () => {
  const dir = tmpDir("viaid-validate-mint-");
  try {
    const badge = aid.mintBadge({ name: "t", workRoot: dir });
    assert.equal(aid.isValidAgentId(badge.agent_id), true, "a freshly minted agent_id must validate");

    const bad = [
      "../../../etc/passwd",
      "../secret",
      "via_short",
      "via_" + "a".repeat(31), // one char short
      "via_" + "a".repeat(33), // one char long
      "via_" + "A".repeat(32), // uppercase hex is not the canonical shape
      "via_" + "g".repeat(32), // non-hex character
      "not_via_prefixed_" + "a".repeat(32),
      "",
      "via_" + "a".repeat(32) + "/../x",
      "/etc/passwd",
      undefined,
      null,
      42,
    ];
    for (const id of bad) {
      assert.equal(aid.isValidAgentId(id), false, `should reject ${JSON.stringify(id)}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("appendLog rejects a badge whose agent_id (as read back from JSON file content) is a path-traversal payload", () => {
  // keystorePath()'s id can originate from a loaded badge's own `.agent_id` field, not just a
  // CLI arg -- appendLog/rotateKey/attachEvidence/revokeBadge all resolve the keystore via
  // `badge.agent_id`, which is exactly what a crafted/tampered *.badge.json file controls.
  const work = tmpDir("viaid-keystore-traversal-");
  try {
    const maliciousBadge = { agent_id: "../../../etc/passwd", log: [] };
    assert.throws(
      () => aid.appendLog(maliciousBadge, work, { action: "x" }),
      /invalid agent id/i
    );
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

// -------- CLI-level: bin/viaid.mjs's badgePath(), fed straight from argv --------

test("CLI rejects a malformed id on every command that resolves a badge by id", () => {
  const work = tmpDir("viaid-malformed-id-");
  try {
    const attempts = [
      ["log", "not-a-real-id", "action"],
      ["rotate", "not-a-real-id"],
      ["verify", "not-a-real-id"],
      ["scan", "not-a-real-id"],
    ];
    for (const args of attempts) {
      assert.throws(
        () => runCli(args, { VIAID_WORK: work }),
        (err) => {
          assert.equal(err.status, 1, `${args[0]} should exit 1`);
          assert.match(err.stderr.toString(), /invalid agent id/i, `${args[0]} should report invalid agent id`);
          return true;
        },
        `${args.join(" ")} should be rejected`
      );
    }
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

test("CLI rejects a path-traversal id instead of reading a badge file outside the work root", () => {
  const parent = tmpDir("viaid-traversal-parent-");
  const work = path.join(parent, "work");
  fs.mkdirSync(work);
  // Plant a sentinel one level above `work`, at exactly the location a '..'-based id would
  // resolve to (ROOT/../escaped.badge.json), so a successful traversal would be observable
  // (the sentinel's distinctive tier value would leak into the command's output) and a blocked
  // one provably never touches it.
  const sentinelTier = "SENTINEL-" + Math.random().toString(16).slice(2);
  fs.writeFileSync(
    path.join(parent, "escaped.badge.json"),
    JSON.stringify({ agent_id: "via_" + "0".repeat(32), assurance_tier: sentinelTier, revocation_state: "FRESH", log: [] })
  );
  try {
    assert.throws(
      () => runCli(["verify", "../escaped"], { VIAID_WORK: work }),
      (err) => {
        assert.equal(err.status, 1);
        assert.match(err.stderr.toString(), /invalid agent id/i);
        const combined = err.stdout.toString() + err.stderr.toString();
        assert.ok(!combined.includes(sentinelTier), "the sentinel file outside the work root must never be read");
        return true;
      }
    );
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("CLI still mints, logs, rotates, and verifies a badge normally with a valid (real) agent id", () => {
  const work = tmpDir("viaid-valid-flow-");
  try {
    const initOut = runCli(["init", "regression-agent"], { VIAID_WORK: work });
    const m = initOut.match(/minted AgentID (via_[0-9a-f]{32})/);
    assert.ok(m, `init output should report a canonical agent id, got: ${initOut}`);
    const id = m[1];

    const logOut = runCli(["log", id, "did-something"], { VIAID_WORK: work });
    assert.match(logOut, /log entry #0/);

    const rotateOut = runCli(["rotate", id], { VIAID_WORK: work });
    assert.match(rotateOut, /rotated agent key: key_seq 0 → 1/);

    const verifyOut = runCli(["verify", id], { VIAID_WORK: work });
    assert.match(verifyOut, /Verdict: VALID/);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});
