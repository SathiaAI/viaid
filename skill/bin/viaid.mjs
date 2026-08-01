#!/usr/bin/env node
// VIA ID — thin runnable prototype CLI.
// S2 (dev): init · log · rotate · eval · verify · revoke        S1 (org): scan · gate
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
// SAT-959: `id` reaches badgePath() from raw CLI argv on every command below. Without
// validation an id like `../../../../etc/cron.d/x` or an absolute path walks the resulting
// join() outside ROOT entirely. Reuse agentid.mjs's own AGENT_ID_RE check (the same shape a
// legitimately-minted agent_id always has) so every command rejects a malformed/malicious id
// before it ever becomes part of a filesystem path, instead of each command re-implementing
// its own check (or forgetting to).
const badgePath = (id) => {
  if (!aid.isValidAgentId(id)) {
    throw new Error(`invalid agent id (expected via_<32 lowercase hex>, got ${JSON.stringify(id)}) — refusing to build a path from it`);
  }
  return join(ROOT, id + '.badge.json');
};
const log = (...a) => console.log(...a);
const hr = () => log('─'.repeat(64));

function ensureRoot() { mkdirSync(ROOT, { recursive: true }); }

const cmds = {
  // ---------- S2: developer badges an agent it sends out ----------
  // codePath (VIA-090, D-25): the directory hashed into inception.code_commitment.code_hash.
  // Defaults to cwd — no established convention yet for "where the agent's own code lives
  // relative to where `viaid init` is run"; flagged as a judgment call for review, not a
  // ratified decision (D-25 itself doesn't specify a default).
  init([name = 'my-agent', codePath = process.cwd()]) {
    ensureRoot();
    const badge = aid.mintBadge({ name, workRoot: ROOT, codePath });
    aid.saveBadge(badgePath(badge.agent_id), badge);
    log(`✔ minted AgentID ${badge.agent_id}  (state=${badge.revocation_state}, tier=${badge.assurance_tier})`);
    log(`  badge → ${badgePath(badge.agent_id)}`);
    log(`  code_commitment.code_hash computed from: ${codePath}`);
    return badge.agent_id;
  },
  // SAT-961: wrapped in withBadgeLock so a concurrent log/rotate/eval/revoke on the same id
  // can't interleave a load→mutate→save cycle with this one and silently drop an update — the
  // lock has to span this CLI's own read of the badge file, not just agentid.mjs's internals,
  // which is why withBadgeLock is exported rather than kept private to that module.
  log([id, action = 'ran', model = null]) {
    aid.withBadgeLock(ROOT, id, () => {
      let badge = aid.loadBadge(badgePath(id));
      badge = aid.appendLog(badge, ROOT, { action, model_used: model });
      aid.saveBadge(badgePath(id), badge);
      log(`✔ log entry #${badge.log.length - 1} "${action}" appended (hash-chained)`);
    });
  },
  // reason: 'routine' (default) — pass 'compromise' as a 3rd arg + an ISO timestamp as a 4th
  // to emit a COMPROMISE_ROTATION event instead (D-15).
  rotate([id, reason = 'routine', compromisedSince = null]) {
    aid.withBadgeLock(ROOT, id, () => {
      let badge = aid.loadBadge(badgePath(id));
      const prevSeq = badge.key_seq ?? 0;
      badge = aid.rotateKey(badge, ROOT, { reason, compromisedSince: reason === 'compromise' ? (compromisedSince || new Date().toISOString()) : null });
      aid.saveBadge(badgePath(id), badge);
      log(`✔ rotated agent key: key_seq ${prevSeq} → ${badge.key_seq}  (reason: ${badge.last_rotation_reason})`);
    });
  },
  async eval([id, targetDir]) {
    if (!gs.graphsmithAvailable()) throw new Error('GraphSmith not available (set GRAPHSMITH_HOME)');
    aid.withBadgeLock(ROOT, id, () => {
      let badge = aid.loadBadge(badgePath(id));
      const evidence = gs.evaluate(targetDir);
      badge = aid.attachEvidence(badge, ROOT, evidence);
      aid.saveBadge(badgePath(id), badge);
      log(`✔ GraphSmith eval: ${evidence.status}  profiles=[${evidence.confirmed_profiles.join(', ') || 'none'}]  (engine: ${evidence.engine})`);
      if (evidence.downgraded_profiles.length) log(`  unavailable (grey, never green): [${evidence.downgraded_profiles.join(', ')}]`);
    });
  },
  verify([id]) {
    const badge = aid.loadBadge(badgePath(id));
    const v = aid.verifyBadge(badge);
    log(`Verdict: ${v.verdict}   freshness=${v.freshness_state}   tier=${v.assurance_tier}   key_seq=${v.key_seq}`);
    log(`Coverage: ${v.coverage}`);
    log(`Scope:    ${v.scope_note}`);
    for (const s of v.steps) log(`  [${s.status}] ${s.step}${s.detail ? ' — ' + s.detail : ''}`);
    return v;
  },
  // D-26: standalone revoke, shipping D-01's own four-command lock for real. Uses D-24's
  // per-role signing — whoever runs this CLI directly is the owner/dev, so this is the
  // OWNER_REVOKE path (unilateral, no agent/voucher cooperation needed). The other two paths
  // (VOUCHER_REVOKE, AGENT_KEY_REVOKED) are triggered by VIA ID's own service / GraphSmith,
  // not from this CLI — see aid.voucherRevoke()/aid.agentKeyRevoked().
  revoke([id, reason = 'revoked']) {
    return aid.withBadgeLock(ROOT, id, () => {
      let badge = aid.loadBadge(badgePath(id));
      badge = aid.ownerRevoke(badge, ROOT, reason);
      aid.saveBadge(badgePath(id), badge);
      log(`✔ revoked (OWNER_REVOKE): ${id}  (reason: ${reason})`);
      return badge;
    });
  },
  // ---------- S1: org runs the desk on an inbound agent ----------
  scan([id]) {
    const badge = aid.loadBadge(badgePath(id));
    const v = aid.verifyBadge(badge);
    log(`Inbound badge ${id}: ${v.verdict} (issuer=native VIA ID → pre-cleared lane)`);
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
    const id = cmds.init(['acme-ops-agent']);
    cmds.log([id, 'deployed', 'claude-sonnet']);
    cmds.log([id, 'called payments API', 'claude-sonnet']);
    await cmds.eval([id, sample]);
    log(''); const v1 = cmds.verify([id]);

    // write the public verify page
    const page = join(ROOT, id + '.verify.html');
    writeFileSync(page, renderVerifyPage(aid.loadBadge(badgePath(id)), v1));
    log(`\n  verify page → ${page}`);

    hr(); log('S1 — ORG: run the desk on this agent (scan → pass → gate → kill)'); hr();
    cmds.scan([id]);
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
    // reflect on the badge too — an org-triggered kill maps to VOUCHER_REVOKE (D-28: the org
    // never holds badge key material; VIA ID's own voucher key acts on its authorized behalf).
    let badge = aid.voucherRevoke(aid.loadBadge(badgePath(id)), ROOT, 'org_revoked');
    aid.saveBadge(badgePath(id), badge);
    const g2 = await ks.gate(domain, city, { leaseId, agentId: id, destination: 'index.js' });
    log(`Gate after kill:  ${g2.decision_code}  ← the desk now refuses it`);
    log(''); cmds.verify([id]);

    hr();
    log('DONE. Reused: GraphSmith (eval→evidence) + KnoSky (identity→policy→receipt→refuse).');
    log(`Open the verify page: ${page}`);
    hr();
  },
};

const [cmd, ...args] = process.argv.slice(2);
const fn = cmds[cmd];
if (!fn) {
  log('viaid — thin prototype\n  S2: init <name> [codePath] · log <id> <action> · rotate <id> [reason|compromise] [suspected_since] · eval <id> <dir> · verify <id> · revoke <id> [reason]\n  S1: scan <id> · gate <id> [dest]\n  demo  — full two-sided flow');
  process.exit(cmd ? 1 : 0);
}
try { await fn(args); }
catch (e) { console.error('✖', e.message); process.exit(1); }
