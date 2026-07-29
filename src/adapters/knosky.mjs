// VIA ID -> KnoSky adapter (REAL, not a mock).
//
// KnoSky Mode B IS the security desk: identity -> policy -> receipt -> ALLOW/DENY_*.
// This adapter drives the REAL KnoSky core modules (no re-implementation):
//   issuePass -> registerAgentWithLease   (mint the visitor pass = lease)
//   gate      -> createModeBDoor().handle (identity check + scoped policy + receipt)
//   verifyLog -> verifyAuditChain         (prove the receipt chain is untampered)
//   kill      -> createSwarmCoordinator().revokeLease  (revoke; the gate then refuses)
//
// Seam: in production this points at the installed `knosky` npm package.
// In this sandbox it points at the cloned repo via KNOSKY_HOME (default /tmp/ks-src).
//
// HONEST LIMITS (must not overclaim): kill = revoke + gate-refuse (NEVER remote-terminate);
// lease-revoke here uses holder self-revoke for the demo — production S1 "org kills visitor"
// uses an operator-token revoke (KnoSky Wave-1: single operator token authorizes revoke).

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { existsSync } from 'node:fs';

const KS_HOME = process.env.KNOSKY_HOME || '/tmp/ks-src';
const core = (m) => import(pathToFileURL(join(KS_HOME, 'core', m)).href);

export function knoskyAvailable() {
  return existsSync(join(KS_HOME, 'core', 'mode-b.mjs')) && existsSync(join(KS_HOME, 'node_modules'));
}

// Build a real KnoSky "city" index from a sample dir (the genuine indexer flow).
export function buildCity(sampleDir, cityOut) {
  const indexer = join(KS_HOME, 'core', 'fs-indexer.mjs');
  const r = spawnSync('node', [indexer, '--root', sampleDir, '--out', cityOut, '--share-safe'],
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (!existsSync(cityOut)) throw new Error(`KnoSky indexer failed: ${r.stderr?.slice(0, 300)}`);
  return cityOut;
}

// Issue a scoped visitor pass = a KnoSky lease.
export async function issuePass(domainRoot, agentId, classes = ['public', 'internal']) {
  const { loadDomain, registerAgentWithLease } = await core('domain-store.mjs');
  const domain = loadDomain(domainRoot);
  const res = registerAgentWithLease(domain, { agentId, role: 'visitor', classes });
  if (!res.ok) throw new Error(`issuePass denied: ${res.reason}`);
  return res.leaseId;
}

// Gate a request: identity check + scoped policy + tamper-evident receipt.
export async function gate(domainRoot, cityPath, { leaseId, agentId, destination }) {
  const { load } = await core('retrieve.mjs');
  const { createModeBDoor } = await core('mode-b.mjs');
  const ctx = load(cityPath);
  const door = createModeBDoor({ cityCtx: ctx, cityPath, domainRoot, profile: 'coding' });
  const env = door.handle({ tool: 'policy_check', destination, leaseId, agentId });
  return {
    decision_code: env.decision_code,
    authorizing: env.authorizing === true,
    receipt_id: env.receipt_id || null,
    next_action: env.next_action || null,
    detail: env.payload || null,
  };
}

// Verify the receipt chain is intact (hash-chain + contiguous seq + high-water-mark).
export async function verifyLog(domainRoot) {
  const { verifyAuditChain } = await core('audit-writer.mjs');
  return verifyAuditChain(domainRoot);
}

// Kill = revoke the lease. After this, every gate() call returns DENY_IDENTITY.
export async function kill(domainRoot, cityPath, { leaseId, agentId, operatorToken = null }) {
  const { createSwarmCoordinator } = await core('swarm-coordinator.mjs');
  const { load } = await core('retrieve.mjs');
  const ctx = load(cityPath);
  const coord = createSwarmCoordinator({ domainRoot, cityPath, cityCtx: ctx });
  // holder self-revoke (demo) OR operator-token revoke (production S1 org-kill)
  const res = coord.revokeLease(leaseId, operatorToken ? { operatorToken } : { callerAgentId: agentId });
  if (!res.ok) throw new Error(`kill denied: ${res.reason || res.code}`);
  return { status: res.status, receipt_id: res.receipt_id || null };
}
