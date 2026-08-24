#!/usr/bin/env node
// VIA ID — thin runnable prototype CLI.
// S2 (dev): init · log · eval · verify · report        S1 (org): scan · gate · revoke
// `demo` runs the whole two-sided flow end-to-end against the REAL GraphSmith + KnoSky.
//
// NOT throwaway: the badge layer (src/agentid.mjs) is production-path; GraphSmith and
// KnoSky are reached through adapter seams (src/adapters/*) that point at the installed
// packages in production and at the cloned repos here (GRAPHSMITH_HOME / KNOSKY_HOME).

import { mkdirSync, writeFileSync, rmSync, existsSync, readdirSync, openSync, fstatSync, readFileSync, closeSync, constants as fsConstants } from 'node:fs';
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
  init([name = 'my-agent']) {
    ensureRoot();
    const badge = aid.mintBadge({ name, workRoot: ROOT });
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
  verify([id]) {
    const badge = aid.loadBadge(badgePath(id));
    const v = aid.verifyBadge(badge);
    log(`Verdict: ${v.verdict}   freshness=${v.freshness_state}   tier=${v.assurance_tier}   key_seq=${v.key_seq}`);
    log(`Coverage: ${v.coverage}`);
    log(`Scope:    ${v.scope_note}`);
    for (const s of v.steps) log(`  [${s.status}] ${s.step}${s.detail ? ' — ' + s.detail : ''}`);
    return v;
  },
  // Local-only badge count for whoever operates this workRoot (a solo dev, or a company
  // running VIA ID for its own internal fleet) — no network call, no data leaves this
  // directory. Walks *.badge.json files already sitting here and tallies them; does not
  // change verify/mint/revoke behavior or touch anything outside `dir`.
  //
  // "active" reflects each badge's own stored `revocation_state` (REVOKED vs. not) — it is
  // NOT a live freshness/signature check. A badge whose TTL has lapsed (STALE) or whose
  // signature no longer verifies (INVALID) still counts as active here; run `verify <id>`
  // for the real per-badge verdict. Deliberate: report is a fast, read-only sweep across a
  // whole directory, not a per-badge verification pass.
  report([dir = ROOT]) {
    if (!existsSync(dir)) throw new Error(`no such directory: ${dir}`);
    const files = readdirSync(dir).filter((f) => f.endsWith('.badge.json'));
    const counts = { total: 0, skipped: 0, active: 0, revoked: 0, byTier: {} };
    for (const f of files) {
      const full = join(dir, f);
      let badge;
      let fd;
      try {
        // Open once with O_NOFOLLOW + O_NONBLOCK and work from that single descriptor,
        // rather than checking the path (lstat) and then reading the path again — two
        // separate pathname lookups leave a window where the entry could be swapped for
        // a symlink in between the check and the read. O_NOFOLLOW makes the open itself
        // fail (ELOOP) on a symlink; O_NONBLOCK keeps it from blocking if a special file
        // like a named pipe sits here instead. fstat on the resulting descriptor is immune
        // to any further swap at the path, since it's already bound to the exact file we
        // opened, not to whatever the path currently resolves to.
        fd = openSync(full, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
        if (!fstatSync(fd).isFile()) throw new Error('not a regular file (symlink or special file)');
        badge = JSON.parse(readFileSync(fd, 'utf8'));
        if (badge === null || typeof badge !== 'object' || Array.isArray(badge)) {
          throw new Error('badge JSON must be an object');
        }
        counts.total++;
        const tier = badge.assurance_tier || 'unknown';
        counts.byTier[tier] = (counts.byTier[tier] || 0) + 1;
        if (badge.revocation_state === 'REVOKED') counts.revoked++;
        else counts.active++;
      } catch (e) {
        const reason = e.code === 'ELOOP' ? 'not a regular file (symlink or special file)' : e.message;
        log(`⚠ skipping ${f}: ${reason}`);
        counts.skipped++;
        continue;
      } finally {
        if (fd !== undefined) closeSync(fd);
      }
    }
    log(`Badges in ${dir}: ${counts.total}  (active ${counts.active}, revoked ${counts.revoked}, ${counts.skipped} file(s) skipped)`);
    for (const [tier, n] of Object.entries(counts.byTier)) log(`  ${tier}: ${n}`);
    return counts;
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
    // reflect on the badge too
    let badge = aid.revokeBadge(aid.loadBadge(badgePath(id)), ROOT, 'org_revoked');
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
  log('viaid — thin prototype\n  S2: init <name> · log <id> <action> · rotate <id> [reason|compromise] [suspected_since] · eval <id> <dir> · verify <id> · report [dir]\n  S1: scan <id> · gate <id> [dest] · (revoke via demo)\n  demo  — full two-sided flow');
  process.exit(cmd ? 1 : 0);
}
try { await fn(args); }
catch (e) { console.error('✖', e.message); process.exit(1); }
