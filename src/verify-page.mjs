// Render a badge verdict to a self-contained verify page (viaid.ai/a/<slug>).
// Brand: "Shock Ink" (BRAND/01-VISUAL-SYSTEM-CONVERGED.md, converged 2026-07-27) —
// Ink #121016 + Accent #FF2079, replacing the rejected v1 palette (Desk Navy/Checkpoint
// Blue/Signal Amber). Verdict colors are RESERVED — never drawn from the brand ramp,
// never decorative: PASS #2fbf6b, REFUSE #ff3b5c, CAUTION (stale/unknown) #c98a12.
// Type: Zodiak (wordmark only) / Fraunces (hero) / Instrument Serif italic (the one
// first-person line) / Instrument Sans (everything read as UI) / Martian Mono (ids,
// hashes, log). Ogg is NOT used — dropped 2026-07-28, permanently replaced by Fraunces.
// UI style: neumorphic soft containers, but verdict pills stay FLAT/solid/high-contrast —
// the one hard rule that keeps "calm shell" and "unmistakable verdict" both true at once.
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
// Canonical production mark (BRAND/assets/via-id-mark-v2.svg) — inlined if present,
// falls back to a plain wordmark if the asset isn't staged in this environment.
function loadMark() {
  const candidates = [
    join(HERE, '..', '..', 'BRAND', 'assets', 'via-id-mark-v2.svg'),
    join(HERE, 'assets', 'via-id-mark-v2.svg'),
  ];
  for (const p of candidates) { if (existsSync(p)) return readFileSync(p, 'utf8'); }
  return null;
}
const MARK_SVG = loadMark();

// verdict + revocation-state color map — reserved palette, never the brand ramp.
const VERDICT_COLOR = { VALID: '#2fbf6b', REVOKED: '#ff3b5c', INVALID: '#ff3b5c' };
const STATE_COLOR = { FRESH: '#2fbf6b', STALE: '#c98a12', REVOKED: '#ff3b5c', UNKNOWN: '#c98a12' };

export function renderVerifyPage(badge, verdict) {
  const vColor = VERDICT_COLOR[verdict.verdict] || '#c98a12';
  // Read the COMPUTED freshness state (verdict.freshness_state), not the raw stored
  // badge.revocation_state field — STALE/UNKNOWN only ever exist as a function of "now"
  // (D-15), they're never written into the badge itself, so the stored field alone would
  // silently show FRESH even when the top verdict pill says STALE/UNKNOWN.
  const sColor = STATE_COLOR[verdict.freshness_state] || '#c98a12';
  const esc = (s) => String(s).replace(/[&<>]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[m]));
  const chips = (arr, cls) => (arr.length ? arr.map((p) => `<span class="chip ${cls}">${esc(p)}</span>`).join('') : '<span class="muted">none</span>');
  const steps = verdict.steps.map((s) => `<tr><td>${esc(s.step)}</td><td class="${s.status === 'PASS' ? 'ok' : 'bad'}">${s.status}</td><td class="muted mono">${esc(s.detail || '')}</td></tr>`).join('');
  const logRows = badge.log.map((e) => `<tr><td class="mono">${e.seq}</td><td>${esc(e.action)}</td><td class="mono muted">${esc((e.entry_hash || '').slice(0, 16))}…</td></tr>`).join('') || '<tr><td colspan="3" class="muted">no log entries</td></tr>';
  const markHtml = MARK_SVG
    ? MARK_SVG.replace('<svg ', '<svg class="mark" ')
    : '<span class="mark-fallback">✓</span>';

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VIA ID — verify ${esc(badge.agent_id)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,wght@0,600;0,700;1,500&family=Instrument+Serif:ital@1&family=Instrument+Sans:wght@400;500;600&family=Martian+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://api.fontshare.com/v2/css?f[]=zodiak@700&display=swap">
<style>
:root{
  --ink:#121016; --accent:#FF2079; --white:#faf9f8;
  --pass:${VERDICT_COLOR.VALID}; --refuse:${VERDICT_COLOR.REVOKED}; --caution:#c98a12;
}
*{box-sizing:border-box}
body{margin:0;background:var(--ink);color:var(--white);font-family:'Instrument Sans',system-ui,sans-serif;}
.wrap{max-width:760px;margin:0 auto;padding:40px 20px 56px}
.mark{width:28px;height:28px;display:block}
.mark-fallback{font-size:24px;color:var(--accent);font-weight:700}
.hdr{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.wordmark{font-family:'Zodiak',serif;font-weight:700;font-size:22px;letter-spacing:.02em}
.hero{font-family:'Fraunces',serif;font-weight:600;font-size:15px;color:#b9b3ba;margin:2px 0 0}
/* neumorphic soft shells for containers — calm, not the verdict */
.card{
  background:#17141b;border-radius:18px;padding:26px;margin-bottom:18px;
  box-shadow: 8px 8px 18px rgba(0,0,0,.45), -6px -6px 16px rgba(255,255,255,.03);
  border:1px solid rgba(255,255,255,.04);
}
/* verdict pill — FLAT, solid, high-contrast, never embossed (the one hard rule) */
.verdict-row{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:8px}
.pill{
  display:inline-flex;align-items:center;gap:8px;font-weight:700;font-size:15px;
  padding:9px 16px;border-radius:10px;background:${vColor};color:#0a0f0c;letter-spacing:.01em;
}
.pill.state{background:${sColor}}
.tier-chip{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#b9b3ba;border:1px solid rgba(255,255,255,.14);padding:6px 10px;border-radius:999px}
.agent-id{font-family:'Martian Mono',ui-monospace,monospace;font-size:13px;color:#b9b3ba;word-break:break-all}
.k{font-size:12px;color:#8f8894;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;font-weight:500}
.mono{font-family:'Martian Mono',ui-monospace,monospace}
.muted{color:#8f8894}
.ok{color:var(--pass);font-weight:600}
.bad{color:var(--refuse);font-weight:600}
.chip{display:inline-block;font-size:12px;padding:5px 10px;border-radius:999px;margin:3px 4px 0 0;font-family:'Martian Mono',ui-monospace,monospace}
.chip.green{background:rgba(47,191,107,.15);color:var(--pass);border:1px solid rgba(47,191,107,.35)}
.chip.notapproved{background:rgba(255,59,92,.12);color:#ff8fa8;border:1px solid rgba(255,59,92,.3)}
table{width:100%;border-collapse:collapse;font-size:13px}
td{padding:8px 6px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top}
.note{font-size:13px;color:#b9b3ba;border-left:3px solid var(--caution);padding:8px 14px;background:rgba(201,138,18,.08);border-radius:0 8px 8px 0;font-style:italic;font-family:'Instrument Serif',serif}
.section-title{font-family:'Fraunces',serif;font-weight:600;font-size:15px;margin:0 0 10px;color:var(--white)}
.footer{font-size:12px;color:#8f8894;text-align:center;font-family:'Instrument Serif',serif;font-style:italic}
</style></head><body><div class="wrap">

<div class="hdr">${markHtml}<div><div class="wordmark">VIA ID</div><div class="hero">Security desk for AI agents — verify</div></div></div>

<div class="card">
  <div class="verdict-row">
    <span class="pill">${esc(verdict.verdict)}</span>
    <span class="pill state">${esc(verdict.freshness_state)}</span>
    <span class="tier-chip">tier: ${esc(verdict.assurance_tier)}</span>
  </div>
  <div class="agent-id">${esc(badge.agent_id)}</div>
</div>

<div class="card">
  <div class="section-title">Coverage</div>
  <div>${esc(verdict.coverage)}</div>
  <div style="margin-top:16px"><div class="k">Confirmed roles / capabilities (GraphSmith-evaluated evidence — never self-declared)</div>${chips(verdict.confirmed_profiles, 'green')}</div>
  <div style="margin-top:14px"><div class="k">Explicitly NOT approved for (evaluated and failed — shown here, never green)</div>${chips(verdict.downgraded_profiles, 'notapproved')}</div>
  <div class="note" style="margin-top:16px">${esc(verdict.scope_note)}</div>
</div>

<div class="card">
  <div class="section-title">Verification steps</div>
  <table><tbody>${steps}</tbody></table>
</div>

<div class="card">
  <div class="section-title">Tamper-evident log (hash-chained)</div>
  <table><tbody>${logRows}</tbody></table>
</div>

<div class="footer">A badge is evidence, not a safety or compliance guarantee. Tamper-evident: if it's changed, it shows.</div>
</div></body></html>`;
}
