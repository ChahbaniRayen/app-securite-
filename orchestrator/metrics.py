#!/usr/bin/env python3
"""
Metriques d evaluation vs ground truth.

Pour chaque vulnerabilite "confirmed"/"pending" du ground truth :
  - TP (vrais positifs)  : outil qui l a signalee (via ses matchers)
  - FN (faux negatifs)   : outil qui NE l a pas signalee
Pour chaque finding outil non rattache a une vuln du GT :
  - "non classifie" (GT non exhaustif) -> considere comme FP indicatif

Sortie : results/<scan>/normalized/metrics.json + rapport texte
Usage : ./orchestrator/metrics.py <results-dir>
"""
import json, sys, os, re, glob
from collections import defaultdict

TOOLS = ["semgrep", "custom", "authz_checker", "sonarqube", "zap", "trivy", "npm_audit"]

def norm_tool(t):
    return "custom" if t == "semgrep_custom" else t

def main(root):
    gt = json.load(open("ground-truth/vulnerabilities.json"))
    fp = os.path.join(root, "normalized", "findings.json")
    if not os.path.exists(fp):
        print(f"[metrics] introuvable : {fp} — lancer d abord normalize.py"); sys.exit(1)
    findings = json.load(open(fp))["findings"]

    # index findings par outil
    by_tool = defaultdict(list)
    for f in findings:
        by_tool[f["tool"]].append(f)

    def matches(finding, rx):
        if not rx: return False
        hay = " ".join(str(finding.get(k) or "") for k in
                       ("title", "rule_id", "file", "endpoint", "description"))
        return re.search(rx, hay, re.I) is not None

    report = {"ground_truth": {}, "tools": {}, "unmatched_findings": {}}
    gt_vulns = [v for v in gt["vulnerabilities"] if v["status"] in ("confirmed", "pending")]

    print("=" * 90)
    print("DETECTION DU GROUND TRUTH PAR OUTIL")
    print("=" * 90)
    header = f"{'ID':7s} {'Grav':10s} {'Statut':9s}" + "".join(f"{t:11s}" for t in TOOLS)
    print(header); print("-" * len(header))

    tool_stats = {t: {"tp": 0, "fn": 0, "matched_findings": set()} for t in TOOLS}
    gt_rows = []
    for v in gt_vulns:
        row = {"id": v["id"], "title": v["title"], "severity": v["severity"],
               "status": v["status"], "detected_by": [], "missed_by": []}
        cells = []
        for t in TOOLS:
            rx = (v.get("matchers") or {}).get(t)
            found = None
            if rx:
                for f in by_tool.get(t, []):
                    if matches(f, rx):
                        found = f; break
            # custom peut aussi matcher via outil semgrep des regles custom
            if found:
                row["detected_by"].append(t)
                tool_stats[t]["tp"] += 1
                tool_stats[t]["matched_findings"].add(
                    (f.get("source_file"), f.get("rule_id"), f.get("title")))
                cells.append("  DETECTEE ")
            else:
                if t in (v.get("matchers") or {}) and v["matchers"][t]:
                    row["missed_by"].append(t)
                    tool_stats[t]["fn"] += 1
                    cells.append("  ratee    ")
                else:
                    cells.append("  n/a      ")
        report["ground_truth"][v["id"]] = row
        gt_rows.append((v, cells))
        print(f"{v['id']:7s} {v['severity']:10s} {v['status']:9s}" + "".join(f"{c:11s}" for c in cells))

    print()
    print("=" * 90)
    print("METRIQUES PAR OUTIL (GT = vulnerabilites confirmed + pending)")
    print("=" * 90)
    print(f"{'Outil':12s} {'TP':>4s} {'FN':>4s} {'Recall':>8s} {'Findings':>9s} {'Rattaches':>10s} {'Precision*':>11s}")
    for t in TOOLS:
        st = tool_stats[t]
        total = st["tp"] + st["fn"]
        recall = (st["tp"] / total * 100) if total else None
        n_find = len(by_tool.get(t, []))
        n_att = len(st["matched_findings"])
        prec = (n_att / n_find * 100) if n_find else None
        report["tools"][t] = {"tp": st["tp"], "fn": st["fn"],
                              "recall_pct": round(recall, 1) if recall is not None else None,
                              "findings": n_find, "matched_findings": n_att,
                              "precision_pct": round(prec, 1) if prec is not None else None}
        print(f"{t:12s} {st['tp']:4d} {st['fn']:4d} "
              f"{(f'{recall:.1f}%' if recall is not None else 'n/a'):>8s} {n_find:9d} {n_att:10d} "
              f"{(f'{prec:.1f}%' if prec is not None else 'n/a'):>11s}")
    print("\n* Precision indicative : le GT n est pas exhaustif — les findings non")
    print("  rattaches sont des 'non classes' (candidats FP a revue manuelle).")

    out = os.path.join(root, "normalized", "metrics.json")
    json.dump(report, open(out, "w"), indent=1, ensure_ascii=False)
    print(f"\n[metrics] -> {out}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    main(sys.argv[1])
