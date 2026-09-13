import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBadge, mintBadge } from "../src/agentid.mjs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// SAT-1009: regression tests for crash bugs the fuzz harness (test/fuzz/verify-badge.fuzz.mjs)
// found in verifyBadge() on `main` — malformed/adversarial badge JSON threw an uncaught
// exception instead of failing cleanly with an INVALID verdict. Each case here reproduces one
// concrete crash that was confirmed against the pre-fix code before verifyBadge() got its
// fail-closed wrapper (see the comment above invalidVerdict() in src/agentid.mjs). These are
// fast, deterministic companions to the fuzz harness, not a replacement for it — the harness
// covers the much larger space of malformed shapes; these pin the exact bugs found so far.

test("verifyBadge(null) returns an INVALID verdict instead of throwing", () => {
  const v = verifyBadge(null);
  assert.equal(v.verdict, "INVALID");
  assert.equal(Array.isArray(v.steps), true);
});

test("verifyBadge(undefined) returns an INVALID verdict instead of throwing", () => {
  const v = verifyBadge(undefined);
  assert.equal(v.verdict, "INVALID");
});

test("verifyBadge([...]) (array, not an object) returns an INVALID verdict instead of throwing", () => {
  const v = verifyBadge([1, 2, 3]);
  assert.equal(v.verdict, "INVALID");
});

test("verifyBadge(42) (primitive) returns an INVALID verdict instead of throwing", () => {
  const v = verifyBadge(42);
  assert.equal(v.verdict, "INVALID");
});

test("verifyBadge with a non-array `.log` (string) returns INVALID instead of throwing", () => {
  const v = verifyBadge({ schema: "viaid.badge/0.1", inception: {}, keys: {}, log: "not-an-array" });
  assert.equal(v.verdict, "INVALID");
});

test("verifyBadge with `evidence.confirmed_profiles` present but not an array returns INVALID instead of throwing", () => {
  const v = verifyBadge({
    schema: "viaid.badge/0.1",
    inception: {},
    keys: {},
    log: [],
    evidence: { status: "PASS", confirmed_profiles: "oops-not-an-array" },
  });
  assert.equal(v.verdict, "INVALID");
});

test("verifyBadge on a well-formed empty object still fails closed (no signatures, no inception)", () => {
  const v = verifyBadge({});
  assert.equal(v.verdict, "INVALID");
  assert.equal(v.freshness_state !== "FRESH", true, "an empty object must never verify as FRESH/VALID");
});

// SAT-1009 (CodeRabbit follow-up): the cases above are all negative (malformed/adversarial ->
// INVALID). Nothing pinned the POSITIVE path -- a genuine, freshly-minted badge must verify as
// VALID -- so a regression that made verifyBadge() over-reject a legitimate badge would have
// slipped through both this suite and the fuzz harness (the harness is deliberately a negative
// oracle: no-crash + no-bypass, and a byte-mutating fuzzer cannot forge the three Ed25519
// signatures a VALID verdict requires, so it can never reach VALID on its own). These three
// deterministic cases close that gap and bracket the authenticity check from both sides.

test("verifyBadge on a genuine freshly-minted badge returns VALID / FRESH (positive path)", () => {
  const work = mkdtempSync(join(tmpdir(), "viaid-verify-pos-"));
  try {
    const badge = mintBadge({ name: "positive-path", workRoot: work });
    const v = verifyBadge(badge);
    assert.equal(v.verdict, "VALID", "a genuine freshly-minted badge must verify as VALID");
    assert.equal(v.freshness_state, "FRESH");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("verifyBadge rejects a genuine badge whose owner signature was tampered (-> INVALID)", () => {
  const work = mkdtempSync(join(tmpdir(), "viaid-verify-sig-"));
  try {
    const badge = mintBadge({ name: "tampered-sig", workRoot: work });
    // flip the first base64 char to a guaranteed-different one so the signature always
    // changes (a freshly minted sig can itself begin with "AAAA"), breaking it deterministically
    const first = badge.signatures.owner_sig[0];
    badge.signatures.owner_sig = (first === "A" ? "B" : "A") + badge.signatures.owner_sig.slice(1);
    assert.equal(verifyBadge(badge).verdict, "INVALID");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("verifyBadge rejects a genuine badge whose agent_id no longer matches its inception (-> INVALID)", () => {
  const work = mkdtempSync(join(tmpdir(), "viaid-verify-id-"));
  try {
    const badge = mintBadge({ name: "tampered-id", workRoot: work });
    badge.agent_id = "via_" + "0".repeat(32); // valid shape, wrong value -> recomputed != agent_id
    assert.equal(verifyBadge(badge).verdict, "INVALID");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
