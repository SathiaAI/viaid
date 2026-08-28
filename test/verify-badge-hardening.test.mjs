import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBadge } from "../src/agentid.mjs";

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
