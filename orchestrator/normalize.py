#!/usr/bin/env python3
"""
Normalisation des sorties brutes de TOUS les outils vers un schema unique.

Sortie : results/<scan>/normalized/findings.json
Schema : [{tool, type, target, title, severity, cwe[], owasp, rule_id,
           file, line, endpoint, description, source_file}, ...]

Usage : ./orchestrator/normalize.py <results-dir>
   ex : ./orchestrator/normalize.py results/20261111-145759
"""
import json, sys, glob, os, re

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ---------- mappings de severite ----------
SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "MEDIUM": "medium",
               "LOW": "low", "INFO": "info"}
SONAR_SEV   = {"BLOCKER": "critical", "CRITICAL": "high", "MAJOR": "medium",
               "MINOR": "low", "INFO": "info"}
TRIVY_SEV   = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
               "LOW": "low", "UNKNOWN": "info"}
NPM_SEV     = {"critical": "critical", "high": "high", "moderate": "medium",
               "low": "low", "info": "info"}

def zap_sev(alert):
    rc = str(alert.get("riskcode", "0"))
    return {"3": "high", "2": "medium", "1": "low", "0": "info"}.get(rc, "info")

def target_of(path):
    """Determine la cible depuis le chemin de fichier / nom de fichier."""
    p = path.replace("\\", "/")
    for t in ("juice-shop", "crapI", "crapi", "roundcube", "roundcubemail"):
        if t.lower() in p.lower():
            return "crapI" if t.lower() in ("crapI", "crapi") else (
                   "roundcube" if t.lower() in ("roundcube", "roundcubemail") else "juice-shop")
    return None

def as_list(v):
    if v is None: return []
    if isinstance(v, list): return [str(x) for x in v]
    return [str(v)]

def load(fp):
    try:
        with open(fp) as f: return json.load(f)
    except Exception as e:
        print(f"  [WARN] illisible: {fp}: {e}")
        return None

# ---------- convertisseurs ----------
def conv_semgrep(d, fp, out, target_hint=None):
    tool = "custom" if "custom" in os.path.basename(fp) else "semgrep"
    for r in d.get("results", []):
        md = r.get("extra", {}).get("metadata", {})
        out.append({
            "tool": tool, "type": "SAST",
            "target": target_hint or target_of(r.get("path", "")) or target_of(fp),
            "title": (r.get("extra", {}).get("message", "") or r.get("check_id", "")).strip().split("\n")[0][:200],
            "severity": SEMGREP_SEV.get(r.get("extra", {}).get("severity", "INFO"), "info"),
            "cwe": as_list(md.get("cwe")),
            "owasp": as_list(md.get("owasp")),
            "rule_id": r.get("check_id"),
            "file": r.get("path"), "line": r.get("start", {}).get("line"),
            "endpoint": None,
            "description": r.get("extra", {}).get("lines", "").strip()[:300],
            "source_file": os.path.basename(fp),
        })

def conv_sonar(d, fp, out, target_hint=None):
    for i in d.get("issues", []):
        comp = i.get("component", "")           # ex: "juice-shop:data/datacache.ts"
        fname = comp.split(":", 1)[1] if ":" in comp else comp
        tgt = target_hint or (comp.split(":", 1)[0] if ":" in comp else target_of(fp))
        if tgt == "crapi": tgt = "crapI"
        out.append({
            "tool": "sonarqube", "type": "SAST",
            "target": tgt,
            "title": i.get("message", "")[:200],
            "severity": SONAR_SEV.get(i.get("severity", "INFO"), "info"),
            "cwe": [], "owasp": [],
            "rule_id": i.get("rule"),
            "file": fname, "line": i.get("line"),
            "endpoint": None,
            "description": f"{i.get('type','')} | {i.get('severity','')}",
            "source_file": os.path.basename(fp),
        })

def conv_zap(d, fp, out, target_hint=None):
    tgt = target_hint or target_of(fp)
    for site in d.get("site", []):
        surl = site.get("@name", "")
        for a in site.get("alerts", []):
            urls = [inst.get("requestURI", "") for inst in a.get("instances", [])]
            out.append({
                "tool": "zap", "type": "DAST",
                "target": tgt,
                "title": a.get("name", a.get("alert", ""))[:200],
                "severity": zap_sev(a),
                "cwe": [f"CWE-{a['cweid']}"] if str(a.get("cweid", "0")).isdigit() and a.get("cweid") != "0" else [],
                "owasp": [], "rule_id": a.get("alertRef"),
                "file": None, "line": None,
                "endpoint": urls[0] if urls else surl,
                "description": (a.get("riskdesc", "") + " | " + a.get("desc", ""))[:300].replace("\n", " "),
                "source_file": os.path.basename(fp),
            })

def conv_trivy(d, fp, out, target_hint=None):
    tgt = target_hint or target_of(fp)
    for res in d.get("Results", []) or []:
        target_path = res.get("Target", "")
        for v in (res.get("Vulnerabilities") or []):
            out.append({
                "tool": "trivy", "type": "SCA",
                "target": tgt,
                "title": f"{v.get('VulnerabilityID')} {v.get('Title','')[:150]}".strip(),
                "severity": TRIVY_SEV.get(v.get("Severity", "UNKNOWN"), "info"),
                "cwe": as_list(v.get("CweIDs")),
                "owasp": ["A06:2025"] if v.get("VulnerabilityID", "").startswith("CVE") else [],
                "rule_id": v.get("VulnerabilityID"),
                "file": target_path, "line": None, "endpoint": None,
                "description": (v.get("Description") or "")[:300],
                "source_file": os.path.basename(fp),
            })
        for s in (res.get("Secrets") or []):
            out.append({
                "tool": "trivy", "type": "SECRET",
                "target": tgt,
                "title": s.get("RuleID", "secret") + " " + (s.get("Title") or "")[:120],
                "severity": TRIVY_SEV.get((s.get("Severity") or "HIGH").upper(), "high"),
                "cwe": ["CWE-798"], "owasp": [], "rule_id": s.get("RuleID"),
                "file": target_path, "line": s.get("StartLine"), "endpoint": None,
                "description": (s.get("Match") or "")[:200],
                "source_file": os.path.basename(fp),
            })

def conv_npm(d, fp, out, target_hint=None):
    tgt = target_hint or target_of(fp) or "juice-shop"
    for name, v in (d.get("vulnerabilities") or {}).items():
        if v.get("isDirect") is None and not v: continue
        sev = NPM_SEV.get(v.get("severity", "info"), "info")
        cves = [x for x in (v.get("via") or []) if isinstance(x, dict)]
        out.append({
            "tool": "npm_audit", "type": "SCA",
            "target": tgt,
            "title": f"{name} — {v.get('severity')} (npm)",
            "severity": sev,
            "cwe": as_list((cves[0] if cves else {}).get("cwe")),
            "owasp": ["A06:2025"],
            "rule_id": name,
            "file": v.get("range"), "line": None, "endpoint": None,
            "description": (cves[0].get("title") if cves else v.get("title", "")) or "",
            "source_file": os.path.basename(fp),
        })

def conv_authz(d, fp, out, target_hint=None):
    """authz-findings.json est deja au schema normalise."""
    for f in d.get("findings", []):
        f.setdefault("source_file", os.path.basename(fp))
        out.append(f)

CONV = [
    ("semgrep-custom-", conv_semgrep), ("semgrep-", conv_semgrep),
    ("sonar-", conv_sonar),
    ("zap-baseline-", conv_zap), ("zap-full-", conv_zap),
    ("trivy-fs-", conv_trivy), ("trivy-image-", conv_trivy),
    ("npm-audit-", conv_npm),
    ("authz-", conv_authz),
]

def guess_target(fp):
    b = os.path.basename(fp)
    for t in ("juice-shop", "crapI", "roundcube"):
        if t.lower() in b.lower(): return t
    return None

def main(root):
    out_dir = os.path.join(root, "normalized")
    os.makedirs(out_dir, exist_ok=True)
    findings = []
    files = []
    for pat in ("sast/*.json", "sast-custom/*.json", "dast/*.json", "sca/*.json", "custom/*.json"):
        files += glob.glob(os.path.join(root, pat))
    print(f"[normalize] {len(files)} fichiers bruts dans {root}")
    for fp in sorted(files):
        b = os.path.basename(fp)
        if b.startswith("semgrep-") and "custom" not in fp and False: continue
        d = load(fp)
        if d is None: continue
        tgt = guess_target(fp)
        for prefix, fn in CONV:
            if b.startswith(prefix):
                n0 = len(fn(d, fp, [], None) or [])  # dry not needed; call properly below
                break
        else:
            continue
        # rappel propre
        tmp = []
        for prefix, fn in CONV:
            if b.startswith(prefix):
                fn(d, fp, tmp, tgt)
                break
        if tmp:
            print(f"  {b:42s} -> {len(tmp):4d} findings ({tmp[0]['tool']})")
        findings += tmp
    # tri par severite
    findings.sort(key=lambda f: (-SEV_ORDER.get(f["severity"], 0), f["tool"], f["title"]))
    out_fp = os.path.join(out_dir, "findings.json")
    with open(out_fp, "w") as f:
        json.dump({"count": len(findings), "findings": findings}, f, indent=1, ensure_ascii=False)
    # synthese
    from collections import Counter
    by_tool = Counter(x["tool"] for x in findings)
    by_sev = Counter(x["severity"] for x in findings)
    print(f"[normalize] TOTAL {len(findings)} findings -> {out_fp}")
    print("  par outil  :", dict(by_tool))
    print("  par sev    :", dict(sorted(by_sev.items(), key=lambda kv: -SEV_ORDER[kv[0]])))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(1)
    main(sys.argv[1])
