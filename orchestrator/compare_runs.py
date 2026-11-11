#!/usr/bin/env python3
"""
Comparaison de DEUX scans (evolution dans le temps / avant-apres).

Usage : python3 orchestrator/compare_runs.py <scan_A> <scan_B> [sortie.json]
   ex : python3 orchestrator/compare_runs.py results/20261111-181922 results/20261111-154335

Categories par outil :
  NOUVEAUX    = presents dans B, absents de A  (regressions potentielles)
  RESOLUS     = presents dans A, absents de B  (corrections / scans incomplets)
  INCHANGES   = presents dans les deux
Fingerprint : (tool, rule_id, target, file|endpoint) — stable entre runs.
"""
import json, os, sys
from collections import Counter

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def load_findings(scan_dir):
    fp = os.path.join(scan_dir, "normalized", "findings.json")
    if not os.path.exists(fp):
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import normalize
        normalize.main(scan_dir)
    return json.load(open(fp))["findings"]

def fingerprint(f):
    loc = f.get("file") or f.get("endpoint") or ""
    return (f.get("tool"), f.get("rule_id"), f.get("target"), loc, f.get("line"))

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    a_dir, b_dir = sys.argv[1].rstrip("/"), sys.argv[2].rstrip("/")
    out_fp = sys.argv[3] if len(sys.argv) > 3 else os.path.join(b_dir, "comparison.json")

    A, B = load_findings(a_dir), load_findings(b_dir)
    fa = {fingerprint(f): f for f in A}
    fb = {fingerprint(f): f for f in B}
    only_a, only_b = set(fa) - set(fb), set(fb) - set(fa)
    common = set(fa) & set(fb)
    ta = sorted({f["tool"] for f in A}); tb = sorted({f["tool"] for f in B})

    print("=" * 92)
    print("COMPARAISON DE SCAN (A = avant, B = apres)")
    print(f"  A : {a_dir}  -> {len(A)} findings, outils: {', '.join(ta)}")
    print(f"  B : {b_dir}  -> {len(B)} findings, outils: {', '.join(tb)}")
    print("=" * 92)
    if ta != tb:
        print(f"  [AVERTISSEMENT] outils absents dun des scans : {sorted(set(ta) ^ set(tb))}")
    print()
    print(f"{'Outil':16s} {'A':>6s} {'B':>6s} {'Nouveaux':>9s} {'Resolus':>8s} {'Inchanges':>10s}")
    print("-" * 60)
    per_tool = {}
    for t in sorted(set(ta) | set(tb)):
        ka = [k for k in only_a if k[0] == t]
        kb = [k for k in only_b if k[0] == t]
        kc = [k for k in common if k[0] == t]
        na = sum(1 for f in A if f["tool"] == t)
        nb = sum(1 for f in B if f["tool"] == t)
        per_tool[t] = {"in_a": na, "in_b": nb, "new": len(kb),
                       "resolved": len(ka), "unchanged": len(kc)}
        print(f"{t:16s} {na:6d} {nb:6d} {len(kb):9d} {len(ka):8d} {len(kc):10d}")
    print()
    new_items = [fb[k] for k in only_b]
    res_items = [fa[k] for k in only_a]
    sev_new = Counter(f["severity"] for f in new_items)
    sev_res = Counter(f["severity"] for f in res_items)
    print("NOUVEAUX (B) par severite :", dict(sorted(sev_new.items(), key=lambda kv: -SEV_ORDER.get(kv[0], 0))) or "aucun")
    print("RESOLUS (A sans B) par severite :", dict(sorted(sev_res.items(), key=lambda kv: -SEV_ORDER.get(kv[0], 0))) or "aucun")
    print("\nExemples de NOUVEAUX :")
    for f in sorted(new_items, key=lambda x: -SEV_ORDER.get(x["severity"], 0))[:6]:
        loc = f.get("file") or f.get("endpoint") or "-"
        print(f"  [+] {f['tool']:14s} {f['severity']:8s} {str(f['title'])[:66]}  ({loc})")
    print("Exemples de RESOLUS :")
    for f in sorted(res_items, key=lambda x: -SEV_ORDER.get(x["severity"], 0))[:6]:
        loc = f.get("file") or f.get("endpoint") or "-"
        print(f"  [-] {f['tool']:14s} {f['severity']:8s} {str(f['title'])[:66]}  ({loc})")

    report = {
        "scan_a": a_dir, "scan_b": b_dir,
        "totals": {"a": len(A), "b": len(B), "new": len(only_b),
                   "resolved": len(only_a), "unchanged": len(common)},
        "tools_a": ta, "tools_b": tb, "per_tool": per_tool,
        "new_findings": [{k: f.get(k) for k in ("tool","title","severity","rule_id","target","file","endpoint")} for f in new_items],
        "resolved_findings": [{k: f.get(k) for k in ("tool","title","severity","rule_id","target","file","endpoint")} for f in res_items],
    }
    os.makedirs(os.path.dirname(out_fp) or ".", exist_ok=True)
    json.dump(report, open(out_fp, "w"), indent=1, ensure_ascii=False)
    print(f"\n[compare] -> {out_fp}")

if __name__ == "__main__":
    main()
