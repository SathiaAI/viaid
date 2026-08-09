#!/usr/bin/env node
// VIA ID — thin runnable prototype CLI.
// S2 (dev): init · log · eval · verify        S1 (org): scan · gate · revoke
// `demo` runs the whole two-sided flow end-to-end against the REAL GraphSmith + KnoSky.
//
// NOT throwaway: the badge layer (src/agentid.mjs) is production-path; GraphSmith and
// KnoSky are reached through adapter seams (src/adapters/*) that point at the installed
// packages in production and at the cloned repos here (GRAPHSMITH_HOME / KNOSKY_HOME).

import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as aid from '../src/agentid.mjs';
import * as gs from '../src/adapters/graphsmith.mjs';
import * as ks from '../src/adapters/knosky.mjs';
import { renderVerifyPage } from '../src/verify-page.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = process.env.VIAID_WORK || join(HERE, '..', 'viaid-work');
const badgePath = (id) => join(ROOT, id + '.badge.json');
const log = (...a) => console.log(...a);
const hr = () => log('─'.repeat(64));

function ensureRoot() { mkdirSync(ROOT, { recursive: true }); }

const cmds = {
  // ---------- S2: developer badges an agent it sends out ----------
  // POST-REVIEW FIX (SAT-958, 2nd round): mintWitnessedBadge()/verifyBadgeWitnessed() existed in
  // src/agentid.mjs but nothing in this CLI ever called them — the WITNESSED tier was reachable
  // only by importing the library directly, not by anyone actually running `viaid`. `--witnessed`
  // wires the one missing entry point; `verify`/`scan` below wire the other two.
  async init(argv) {
    ensureRoot();
    // POST-REVIEW FIX (4th round): `[name = 'my-agent', ...flags]` treated ARGV POSITION 0 as the
    // name unconditionally — `init --witnessed` (no explicit name) silently minted a SELF-tier
    // badge literally NAMED "--witnessed" with the flag never recognized, and `init --witnessed
    // my-agent` (flag before name) did the same while silently discarding "my-agent" entirely.
    // Only `init my-agent --witnessed` (flag last) happened to work. Flags (`--*`) and positionals
    // are now separated regardless of order, matching how `--witnessed` is already read below.
    const flags = argv.filter((a) => a.startsWith('--'));
    const positionals = argv.filter((a) => !a.startsWith('--'));
    const name = positionals[0] || 'my-agent';
    const witnessed = flags.includes('--witnessed');
    const badge = witnessed
      ? await aid.mintWitnessedBadge({ name, workRoot: ROOT })
      : aid.mintBadge({ name, workRoot: ROOT });
    aid.saveBadge(badgePath(badge.agent_id), badge);
    log(`✔ minted AgentID ${badge.agent_id}  (state=${badge.revocation_state}, tier=${badge.assurance_tier})`);
    log(`  badge → ${badgePath(badge.agent_id)}`);
    return badge.agent_id;
  },
  log([id, action = 'ran', model = null]) {
    let badge = aid.loadBadge(badgePath(id));
    badge = aid.appendLog(badge, ROOT, { action, model_used: model });
    aid.saveBadge(badgePath(id), badge);
    log(`✔ log entry #${badge.log.length - 1} "${action}" appended (hash-chained)`);
  },
  // reason: 'routine' (default) — pass 'compromise' as a 3rd arg + an ISO timestamp as a 4th
  // to emit a COMPROMISE_ROTATION event instead (D-15).
  rotate([id, reason = 'routine', compromisedSince = null]) {
    let badge = aid.loadBadge(badgePath(id));
    const prevSeq = badge.key_seq ?? 0;
    badge = aid.rotateKey(badge, ROOT, { reason, compromisedSince: reason === 'compromise' ? (compromisedSince || new Date().toISOString()) : null });
    aid.saveBadge(badgePath(id), badge);
    log(`✔ rotated agent key: key_seq ${prevSeq} → ${badge.key_seq}  (reason: ${badge.last_rotation_reason})`);
  },
  async eval([id, targetDir]) {
    if (!gs.graphsmithAvailable()) throw new Error('GraphSmith not available (set GRAPHSMITH_HOME)');
    let badge = aid.loadBadge(badgePath(id));
    const evidence = gs.evaluate(targetDir);
    badge = aid.attachEvidence(badge, ROOT, evidence);
    aid.saveBadge(badgePath(id), badge);
    log(`✔ GraphSmith eval: ${evidence.status}  profiles=[${evidence.confirmed_profiles.join(', ') || 'none'}]  (engine: ${evidence.engine})`);
    if (evidence.downgraded_profiles.length) log(`  unavailable (grey, never green): [${evidence.downgraded_profiles.join(', ')}]`);
  },
  // WITNESSED-tier badges get the online revocation check here; SELF-tier badges take the
  // existing synchronous, zero-network path unchanged (verifyBadge() itself still discloses,
  // in scope_note, when a WITNESSED badge is checked WITHOUT the online call — see there).
  async verify([id]) {
    const badge = aid.loadBadge(badgePath(id));
    const v = badge.assurance_tier === 'WITNESSED'
      ? await aid.verifyBadgeWitnessed(badge)
      : aid.verifyBadge(badge);
    log(`Verdict: ${v.verdict}   freshness=${v.freshness_state}   tier=${v.assurance_tier}   key_seq=${v.key_seq}${v.witness_state ? `   witness=${v.witness_state}` : ''}`);
    log(`Coverage: ${v.coverage}`);
    log(`Scope:    ${v.scope_note}`);
    for (const s of v.steps) log(`  [${s.status}] ${s.step}${s.detail ? ' — ' + s.detail : ''}`);
    return v;
  },
  // ---------- S1: org runs the desk on an inbound agent ----------
  async scan([id]) {
    const badge = aid.loadBadge(badgePath(id));
    const v = badge.assurance_tier === 'WITNESSED'
      ? await aid.verifyBadgeWitnessed(badge)
      : aid.verifyBadge(badge);
    // This is the actual SAT-958 threat scenario (an org screening an inbound agent), so the
    // tier/online-check status is always disclosed here, not just in the fuller `verify` output.
    const tierNote = v.witness_state
      ? `tier=${v.assurance_tier}, witness=${v.witness_state}`
      : `tier=${v.assurance_tier}, no online witness check performed`;
    log(`Inbound badge ${id}: ${v.verdict} (${tierNote}; issuer=native VIA ID → pre-cleared lane)`);
    return v;
  },
  async gate([id, destination = 'index.js']) {
    const domain = join(ROOT, 'org-domain', '.knosky');
    const city = join(ROOT, 'org-domain', 'city-data.json');
    mkdirSync(domain, { recursive: true });
    if (!existsSync(city)) ks.buildCity(join(ROOT, 'sample-agent'), city);
    const leaseId = await ks.issuePass(domain, id);
    const g = await ks.gate(domain, city, { leaseId, agentId: id, destination });
    log(`Gate "${destination}": ${g.decision_code}  (authorizing=${g.authorizing}, receipt=${g.receipt_id || '—'})`);
    return { leaseId, ...g };
  },
  // ---------- demo: the whole thing ----------
  async demo() {
    if (existsSync(ROOT)) rmSync(ROOT, { recursive: true, force: true });
    ensureRoot();
    // a tiny sample agent project for GraphSmith to evaluate + KnoSky to index
    const sample = join(ROOT, 'sample-agent');
    mkdirSync(sample, { recursive: true });
    writeFileSync(join(sample, 'index.js'), "export function run(){ return 'ok'; }\n");
    writeFileSync(join(sample, 'README.md'), '# sample agent\nPublic demo agent.\n');

    hr(); log('S2 — DEV: badge an agent I send out'); hr();
    const id = await cmds.init(['acme-ops-agent']);
    cmds.log([id, 'deployed', 'claude-sonnet']);
    cmds.log([id, 'called payments API', 'claude-sonnet']);
    await cmds.eval([id, sample]);
    log(''); const v1 = await cmds.verify([id]);

    // write the public verify page
    const page = join(ROOT, id + '.verify.html');
    writeFileSync(page, renderVerifyPage(aid.loadBadge(badgePath(id)), v1));
    log(`\n  verify page → ${page}`);

    hr(); log('S1 — ORG: run the desk on this agent (scan → pass → gate → kill)'); hr();
    await cmds.scan([id]);
    const domain = join(ROOT, 'org-domain', '.knosky');
    const city = join(ROOT, 'org-domain', 'city-data.json');
    mkdirSync(domain, { recursive: true });
    ks.buildCity(sample, city);
    const leaseId = await ks.issuePass(domain, id);
    log(`✔ issued visitor pass (lease ${leaseId})`);
    const g1 = await ks.gate(domain, city, { leaseId, agentId: id, destination: 'index.js' });
    log(`Gate before kill: ${g1.decision_code}  (receipt=${g1.receipt_id || '—'})`);
    const chain1 = await ks.verifyLog(domain);
    log(`Receipt chain: ${chain1.ok ? 'OK' : 'BROKEN'} (${chain1.count} entries)`);

    log('\n  … org decides to KILL the agent (revoke + gate-refuse; NOT remote-terminate) …');
    const k = await ks.kill(domain, city, { leaseId, agentId: id });
    log(`✔ lease ${leaseId} → ${k.status}`);
    // reflect on the badge too
    let badge = aid.revokeBadge(aid.loadBadge(badgePath(id)), ROOT, 'org_revoked');
    aid.saveBadge(badgePath(id), badge);
    const g2 = await ks.gate(domain, city, { leaseId, agentId: id, destination: 'index.js' });
    log(`Gate after kill:  ${g2.decision_code}  ← the desk now refuses it`);
    log(''); await cmds.verify([id]);

    hr();
    log('DONE. Reused: GraphSmith (eval→evidence) + KnoSky (identity→policy→receipt→refuse).');
    log(`Open the verify page: ${page}`);
    hr();
  },
};

const [cmd, ...args] = process.argv.slice(2);
const fn = cmds[cmd];
if (!fn) {
  log('viaid — thin prototype\n  S2: init <name> [--witnessed] · log <id> <action> · rotate <id> [reason|compromise] [suspected_since] · eval <id> <dir> · verify <id>\n  S1: scan <id> · gate <id> [dest] · (revoke via demo)\n  demo  — full two-sided flow\n  --witnessed on init mints a WITNESSED-tier badge (online revocation check at verify/scan time); default is SELF-tier (offline).');
  process.exit(cmd ? 1 : 0);
}
try { await fn(args); }
catch (e) { console.error('✖', e.message); process.exit(1); }
