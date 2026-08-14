#!/usr/bin/env python3
"""Deterministic verdict for adversarial-review.

Computes PASS / FAIL / BLOCKED purely from recorded artifacts and writes verdict.json.
No model — including the one operating this pipeline — can emit a verdict; only this
script can, which is the point.

Exit codes: 0 PASS, 1 FAIL, 2 BLOCKED.

  PASS    all tier-required gates recorded & passing; panel complete & independent;
          every high/critical finding validated with a compliant record.
  FAIL    a recorded gate failed, or a confirmed-unfixed / unresolved /
          improperly-accepted high/critical finding exists.
  BLOCKED required verification is missing: absent gates or gate plan, incomplete or
          non-independent panel, unvalidated findings, missing concurrence, expired
          suppressions, missing rebuttal at CRITICAL, unauthorized degraded mode.
"""
import argparse
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import family_of, now_iso, read_json, resolve_run, write_json

HIGH = ("critical", "high")


def load_reports(run, plan):
    reports = {}
    for role in plan.get("roles", {}):
        p = run / "panel" / f"{role}.json"
        if p.exists():
            reports[role] = read_json(p)
    return reports


def check_gates(run, tier, fail, blocked, notes):
    req_path = run / "gates" / "_required.json"
    if not req_path.exists():
        blocked.append("gate plan missing — run `gate.py plan` after detecting the stack")
        return {}
    gplan = read_json(req_path)
    for w in gplan.get("waived", []):
        if not w.get("authorized_by"):
            blocked.append(f"gate '{w['name']}' waived without an authorizer")
        else:
            notes.append(f"gate '{w['name']}' waived by {w['authorized_by']}")
    results = {}
    for name in gplan.get("required", []):
        p = run / "gates" / f"{name}.json"
        if not p.exists():
            blocked.append(f"required gate '{name}' has no recorded result")
            continue
        rec = read_json(p)
        results[name] = rec
        # Tri-state: BLOCKED means the check could not be run/verified — unknown, not
        # pass and not fail. Absent status falls back to the exit code (older records).
        status = rec.get("status")
        if status == "BLOCKED":
            blocked.append(f"gate '{name}' blocked: {rec.get('summary', 'could not verify')}")
        elif rec.get("exit_code") is None:
            blocked.append(f"gate '{name}' recorded without an exit code")
        elif status == "FAIL" or rec["exit_code"] != 0:
            fail.append(f"gate '{name}' failed (exit {rec['exit_code']}): {rec.get('summary', '')}")
    return results


def check_panel(run, meta, plan, reports, blocked, notes):
    roles = list(plan.get("roles", {}))
    if not roles:
        blocked.append("panel plan missing or empty — run `panel.py assign`")
        return
    dev = set(meta.get("dev_providers", []))
    fams = [plan["roles"][r]["family"] for r in roles]
    if len(set(fams)) != len(fams):
        blocked.append("provider-family collision in panel plan — independence violated")
    leaked = [f for f in fams if f in dev]
    if leaked:
        blocked.append(f"development family present in panel: {', '.join(leaked)}")
    missing = [r for r in roles if r not in reports]
    if missing:
        blocked.append(f"reviewer reports missing for: {', '.join(missing)}")
    deg = plan.get("degraded")
    if deg and not deg.get("authorized_by"):
        blocked.append("degraded panel without recorded authorization")
    elif deg and not deg.get("below_tier_ack"):
        # 'degraded' only exists when actual < requested for THIS tier (see
        # panel.py cmd_assign) -- authorized_by covers "a smaller panel is OK",
        # this additionally requires the operator to confirm they understand this
        # specific tier is getting less scrutiny than it normally requires. A
        # plan.json from before this field existed, or hand-edited, fails closed.
        blocked.append(
            f"panel degraded to {deg.get('actual')}/{deg.get('requested')} roles "
            f"for {meta['risk']} tier (authorized by {deg.get('authorized_by')}) "
            "without an explicit below-tier-minimum acknowledgment -- re-run "
            "`panel.py assign` with --below-tier-ack to accept this explicitly")
    elif deg:
        notes.append(
            f"panel degraded to {deg.get('actual')}/{deg.get('requested')} roles "
            f"for {meta['risk']} tier, authorized by {deg.get('authorized_by')} "
            "with explicit below-tier-minimum acknowledgment")


REBUTTAL_SCOPE = {
    "critical": {"CRITICAL"},
    "contention": {"SENSITIVE", "CRITICAL"},
    "any": {"NORMAL", "SENSITIVE", "CRITICAL"},
}


def _high_critical_by_role(reports):
    """finding_id -> author role, for every high/critical finding in any report."""
    return {f["id"]: role for role, rep in reports.items()
            for f in rep.get("findings", []) if f["severity"] in HIGH}


def check_rebuttal(run, meta, plan, reports, blocked, notes):
    """Rebuttal is required when the tier is in the policy's scope AND there is
    something to contest (high/critical findings). Cost scales with contention.

    A rebuttal file existing is not enough: REBUTTAL_SCHEMA allows an empty
    responses list with no minimum, so a model can satisfy the file-exists check
    with no real cross-examination. This additionally requires every finding a
    role owes a response to (every high/critical finding some OTHER role
    authored) to actually appear in that role's responses -- an empty list only
    passes when there was genuinely nothing for that role to contest."""
    policy = meta.get("rebuttal_policy", "contention")
    scope = REBUTTAL_SCOPE.get(policy, REBUTTAL_SCOPE["contention"])
    by_role = _high_critical_by_role(reports)
    if meta["risk"] not in scope or not by_role:
        if by_role:
            notes.append(f"rebuttal not required at {meta['risk']} under policy '{policy}'")
        return
    for role in plan.get("roles", {}):
        rpath = run / "rebuttal" / f"{role}.json"
        if not rpath.exists():
            blocked.append(f"rebuttal round required (policy '{policy}', risk {meta['risk']}, "
                           f"high/critical findings present); missing for: {role}")
            continue
        owed = {fid for fid, author in by_role.items() if author != role}
        if not owed:
            continue  # this role authored every high/critical finding itself
        rec = read_json(rpath)
        addressed = {r.get("finding_id") for r in rec.get("responses", [])}
        unaddressed = sorted(owed - addressed)
        if unaddressed:
            blocked.append(
                f"rebuttal for '{role}' does not address: {', '.join(unaddressed)} "
                "(file exists but has no response for these finding ids)")


def author_families(finding_ids, plan):
    fams = set()
    for fid in finding_ids:
        role = fid.rsplit("-", 1)[0]
        info = plan.get("roles", {}).get(role)
        if info:
            fams.add(info["family"])
    return fams


def check_findings(run, meta, plan, reports, fail, blocked, counts):
    findings = {}
    for role, rep in reports.items():
        for f in rep.get("findings", []):
            findings[f["id"]] = f
            if f["severity"] in HIGH:
                counts["findings_high_critical"] += 1
            else:
                counts["findings_medium_low"] += 1

    records = []
    vdir = run / "validation"
    if vdir.is_dir():
        for p in sorted(vdir.glob("*.json")):
            if p.name.startswith("concur-request"):
                continue
            records.append((p.name, read_json(p)))

    suppressions = {}
    spath = run / "suppressions.json"
    if spath.exists():
        for s in read_json(spath):
            suppressions[s.get("finding_id", "")] = s

    covered = set()
    dev = set(meta.get("dev_providers", []))
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for name, rec in records:
        ids = rec.get("finding_ids", [])
        cls = rec.get("classification")
        sev = rec.get("severity") or min(
            (findings[i]["severity"] for i in ids if i in findings),
            key=lambda s: sev_rank.get(s, 9), default="low")
        covered.update(ids)
        if cls not in ("confirmed", "false_positive", "unresolved", "accepted_risk"):
            blocked.append(f"validation/{name}: invalid classification '{cls}'")
            continue
        is_high = sev in HIGH or any(findings.get(i, {}).get("severity") in HIGH for i in ids)
        if cls == "unresolved" and is_high:
            fail.append(f"validation/{name}: high/critical finding unresolved ({', '.join(ids)})")
            counts["unresolved"] += 1
        elif cls == "confirmed":
            counts["confirmed"] += 1
            res = rec.get("resolution") or {}
            if not (res.get("fixed") is True and res.get("gates_rerun")):
                fail.append(f"validation/{name}: confirmed finding not fixed with gates rerun")
        elif cls == "false_positive" and is_high:
            conc = rec.get("concurrence") or {}
            if not rec.get("evidence"):
                blocked.append(f"validation/{name}: false_positive without evidence")
            if conc.get("agrees_false_positive") is not True:
                blocked.append(f"validation/{name}: false_positive on high/critical "
                               "without an agreeing concurrence from an uninvolved model")
            else:
                cfam = family_of(conc.get("model_id", "unknown/unknown"))
                bad = author_families(ids, plan) | dev
                if cfam in bad:
                    blocked.append(f"validation/{name}: concurrence model family "
                                   f"'{cfam}' is not independent of the finding/dev")
        elif cls == "accepted_risk":
            today = date.today().isoformat()
            for fid in ids:
                s = suppressions.get(fid)
                if not s:
                    fail.append(f"validation/{name}: accepted_risk '{fid}' has no suppression entry")
                elif not all(s.get(k) for k in ("evidence", "owner", "expires")):
                    fail.append(f"suppression for '{fid}' incomplete (needs evidence, owner, expires)")
                elif s["expires"] < today:
                    fail.append(f"suppression for '{fid}' expired {s['expires']}")

    uncovered = [i for i, f in findings.items()
                 if f["severity"] in HIGH and i not in covered]
    if uncovered:
        blocked.append("high/critical findings with no validation record: "
                       + ", ".join(sorted(uncovered)))
    # A reviewer explicitly flagged these as release-blocking; severity alone does not
    # exempt them from triage. Untriaged = verification incomplete = BLOCKED.
    flagged = [i for i, f in findings.items()
               if f["severity"] not in HIGH and f.get("release_blocking")
               and i not in covered]
    if flagged:
        blocked.append("reviewer-flagged release-blocking findings without triage: "
                       + ", ".join(sorted(flagged)))
    untriaged = [i for i, f in findings.items()
                 if f["severity"] not in HIGH and i not in covered]
    if untriaged:
        counts["medium_low_untriaged"] = len(untriaged)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run")
    args = ap.parse_args()
    run = resolve_run(args.run)
    meta = read_json(run / "run.json")

    fail, blocked, notes = [], [], []
    counts = {"gates": 0, "reviewers": 0, "findings_high_critical": 0,
              "findings_medium_low": 0, "confirmed": 0, "unresolved": 0}

    gates = check_gates(run, meta["risk"], fail, blocked, notes)
    counts["gates"] = len(gates)

    plan_path = run / "panel" / "plan.json"
    plan = read_json(plan_path) if plan_path.exists() else {}
    reports = load_reports(run, plan)
    counts["reviewers"] = len(reports)
    check_panel(run, meta, plan, reports, blocked, notes)
    check_rebuttal(run, meta, plan, reports, blocked, notes)
    check_findings(run, meta, plan, reports, fail, blocked, counts)

    verdict = "FAIL" if fail else ("BLOCKED" if blocked else "PASS")
    out = {"verdict": verdict, "reasons": fail + blocked, "notes": notes,
           "counts": counts, "risk": meta["risk"], "run_id": meta["run_id"],
           "computed_at": now_iso()}
    write_json(run / "verdict.json", out)

    md = [f"# Release verdict: {verdict}", "",
          f"Run `{meta['run_id']}`, risk {meta['risk']}, computed {out['computed_at']}.", ""]
    md += [f"- FAIL: {r}" for r in fail]
    md += [f"- BLOCKED: {r}" for r in blocked]
    md += [f"- note: {n}" for n in notes]
    md += ["", "Counts: " + ", ".join(f"{k}={v}" for k, v in counts.items())]
    (run / "verdict.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"VERDICT: {verdict}  (risk={meta['risk']}, run={meta['run_id']})")
    for r in fail:
        print(f"  FAIL    - {r}")
    for r in blocked:
        print(f"  BLOCKED - {r}")
    for n in notes:
        print(f"  note    - {n}")
    print(f"written: {run / 'verdict.json'} and verdict.md")
    sys.exit({"PASS": 0, "FAIL": 1, "BLOCKED": 2}[verdict])


if __name__ == "__main__":
    main()
