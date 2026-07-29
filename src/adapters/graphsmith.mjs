// VIA ID -> GraphSmith adapter (REAL, not a mock).
//
// GraphSmith is the eval->evidence engine a VIA ID badge stands on. This adapter
// shells the REAL GraphSmith verifier and consumes its real JSON output.
//
// Seam: in production this points at the installed `graphsmith` npm bin / Agent Skill.
// In this sandbox it points at the cloned repo via GRAPHSMITH_HOME (default /tmp/gs-src).
//
// Two GraphSmith surfaces (see TECHNICAL/35-REUSE-MAP): we use `verify.js --profiles`
// (repo-level capability profiles, zero-dep, always runnable). A full deployment would
// prefer `graphsmith verify <bundle.json> --keys --json` on a portable GSA bundle; the
// return shape below is deliberately identical so swapping is zero-rewrite.

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { existsSync } from 'node:fs';

const GS_HOME = process.env.GRAPHSMITH_HOME || '/tmp/gs-src';

export function graphsmithAvailable() {
  return existsSync(join(GS_HOME, 'scripts', 'verify.js'));
}

// evaluate(targetDir) -> { engine, status, confirmed_profiles[], downgraded_profiles[], note, evaluated_at_source, raw }
export function evaluate(targetDir) {
  const verifyJs = join(GS_HOME, 'scripts', 'verify.js');
  if (!existsSync(verifyJs)) {
    throw new Error(`GraphSmith not found at ${GS_HOME} (set GRAPHSMITH_HOME)`);
  }
  const r = spawnSync('node', [verifyJs, '--profiles', '--root', targetDir], {
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
  // verify.js writes pure JSON to stdout, human summary to stderr (contract: never blended).
  let report;
  try { report = JSON.parse(r.stdout); }
  catch (e) { throw new Error(`GraphSmith verify produced no JSON (exit ${r.status}): ${r.stderr?.slice(0, 300)}`); }

  const profiles = report.profiles || {};
  const confirmed = [], downgraded = [];
  for (const [letter, res] of Object.entries(profiles)) {
    if (res.status === 'verified') confirmed.push(letter);
    else if (res.status === 'unavailable') downgraded.push(letter); // NEVER surfaced as green
  }
  // A profiles PASS = at least one verified profile and no `failed`. Fail-closed on any failed.
  const anyFailed = Object.values(profiles).some((p) => p.status === 'failed');
  const status = anyFailed ? 'FAIL' : (confirmed.length ? 'PASS' : 'UNAVAILABLE');

  return {
    engine: `graphsmith-skill verify.js (${report.verifier_version || '?'})`,
    status,
    confirmed_profiles: confirmed,
    downgraded_profiles: downgraded,
    profile_string: report.profile_string || confirmed.map((c) => `${c}:verified`).join(' '),
    evaluated_at_source: report.evaluated_at_source || 'none',
    note: 'GraphSmith evidence is TESTED, not certified — a PASS records what the run requested/produced and that the record is unaltered, not that the agent is safe/correct/compliant.',
    raw: report,
  };
}
