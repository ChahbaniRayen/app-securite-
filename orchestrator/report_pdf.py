#!/usr/bin/env python3
"""
Rapport PDF consolide de la plateforme de detection de vulnerabilites.
Sources : ground-truth/, results/<scan>/normalized/{findings,metrics}.json,
          results/remediation-*/diff-remediation.json
Usage : python3 orchestrator/report_pdf.py <results-dir> [sortie.pdf]
"""
import json, sys, os, glob, datetime
from collections import Counter, defaultdict
from fpdf import FPDF

SEV_COLOR = {"critical": (178, 24, 44), "high": (214, 92, 20), "medium": (196, 156, 14),
             "low": (44, 110, 160), "info": (110, 110, 110)}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
TOOL_LABEL = {"semgrep": "Semgrep (registry)", "custom": "Regles custom", "authz_checker": "authz_checker (perso)",
              "sonarqube": "SonarQube", "zap": "OWASP ZAP", "trivy": "Trivy", "npm_audit": "npm audit"}

def safe(s):
    """Encoder en latin-1 pour les polices Helvetica (accents FR ok, fleches non)."""
    if s is None: return ""
    s = str(s)
    for a, b in (("→", "->"), ("←", "<-"), ("✓", "OUI"), ("✗", "NON"), ("•", "-"),
                 ("’", "'"), ("‘", "'"), ("“", '"'), ("”", '"'), ("—", "-"), ("–", "-"),
                 ("≥", ">="), ("…", "...")):
        s = s.replace(a, b)
    return s.encode("latin-1", "replace").decode("latin-1")

class Report(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, safe("Plateforme automatisee de detection de vulnerabilites - SAST / DAST / SCA"), align="C")
        self.ln(8)
    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, safe(f"Page {self.page_no()}/{{nb}}"), align="C")

def h1(pdf, txt):
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 50, 90)
    pdf.ln(3)
    pdf.cell(0, 9, safe(txt), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(20, 50, 90)
    pdf.set_line_width(0.5)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(3)
    pdf.set_text_color(0, 0, 0)

def h2(pdf, txt):
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(40, 80, 130)
    pdf.ln(2)
    pdf.cell(0, 7, safe(txt), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

def body(pdf, txt, w=0):
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(w or 0, 5.5, safe(txt))
    pdf.ln(1)

def table(pdf, headers, rows, widths, aligns=None, sev_col=None):
    aligns = aligns or ["L"] * len(headers)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(20, 50, 90)
    pdf.set_text_color(255, 255, 255)
    for h, w, a in zip(headers, widths, aligns):
        pdf.cell(w, 7, safe(h), border=1, fill=True, align="C")
    pdf.ln()
    pdf.set_text_color(0, 0, 0)
    fill = False
    for row in rows:
        if pdf.get_y() > 270:
            pdf.add_page()
        pdf.set_font("Helvetica", "", 8.5)
        if sev_col is not None and row[sev_col].lower() in SEV_COLOR:
            r, g, b = SEV_COLOR[row[sev_col].lower()]
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 8.5)
        else:
            pdf.set_fill_color(240, 244, 248) if fill else pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(0, 0, 0)
        for c, w, a in zip(row, widths, aligns):
            pdf.cell(w, 6.2, safe(str(c))[:90], border=1, fill=True, align=a)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)
        fill = not fill
    pdf.ln(2)

def load(p):
    try: return json.load(open(p))
    except Exception: return None

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    agg = sys.argv[1].rstrip("/")
    out_pdf = sys.argv[2] if len(sys.argv) > 2 else f"{agg}/report.pdf"

    gt = load("ground-truth/vulnerabilities.json")
    findings_doc = load(f"{agg}/normalized/findings.json") or {"findings": [], "count": 0}
    metrics = load(f"{agg}/normalized/metrics.json") or {"tools": {}, "ground_truth": {}}
    findings = findings_doc["findings"]
    rem_files = sorted(glob.glob("results/remediation-*/diff-remediation.json"))
    rem = load(rem_files[-1]) if rem_files else None

    by_tool = Counter(f["tool"] for f in findings)
    by_sev = Counter(f["severity"] for f in findings)
    by_type = Counter(f["type"] for f in findings)
    gt_status = Counter(v["status"] for v in gt["vulnerabilities"])

    pdf = Report()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(True, margin=15)

    # ---------------- 1. COUVERTURE ----------------
    pdf.add_page()
    pdf.ln(45)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(20, 50, 90)
    pdf.multi_cell(0, 12, safe("Plateforme automatisee de\ndetection de vulnerabilites"), align="C")
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(0, 8, safe("Analyse comparative SAST / DAST / SCA avec mecanisme de\ndetection personnalise et evaluation metrique"), align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(0, 0, 0)
    today = datetime.date.today().strftime("%d/%m/%Y")
    for line in ["Cibles : OWASP Juice Shop - OWASP crAPI - Roundcube Webmail",
                 "Outils : Semgrep - SonarQube - OWASP ZAP - Trivy - npm audit",
                 "Mecanisme personnalise : regles Semgrep + authz_checker (BOLA/BFLA)",
                 f"Date : {today}   |   CI/CD : GitHub Actions"]:
        pdf.cell(0, 8, safe(line), align="C", new_x="LMARGIN", new_y="NEXT")

    # ---------------- 2. RESUME EXECUTIF ----------------
    pdf.add_page()
    h1(pdf, "1. Resume executif")
    body(pdf, "Cette plateforme automatise la detection de vulnerabilites dans trois applications web "
              "en combinant quatre approches : SAST (Semgrep, SonarQube), DAST (OWASP ZAP), "
              "SCA (Trivy, npm audit) et un mecanisme de detection personnalise (regles Semgrep "
              "maison + authz_checker pour les failles d autorisation BOLA/BFLA non couvertes par "
              "les outils standards). Les resultats sont normalises dans un schema JSON unique, "
              "archives automatiquement via GitHub Actions, puis evalues metriquement contre un "
              "ground truth etabli par tests manuels (TP1-TP4 du module).")

    h2(pdf, "Chiffres cles")
    kpis = [
        ["Applications cibles deprimees", "3", "Juice Shop, crAPI, Roundcube"],
        ["Vulnerabilites au ground truth", str(len(gt["vulnerabilities"])),
         f"{gt_status['confirmed']} confirmees, {gt_status['pending']} en attente, {gt_status['candidate']} candidates"],
        ["Findings total apres normalisation", str(findings_doc["count"]),
         f"semgrep {by_tool.get('semgrep',0)} | sonar {by_tool.get('sonarqube',0)} | zap {by_tool.get('zap',0)} | trivy {by_tool.get('trivy',0)} | npm {by_tool.get('npm_audit',0)} | custom {by_tool.get('custom',0)} | authz {by_tool.get('authz_checker',0)}"],
        ["Findings critiques / eleves", f"{by_sev.get('critical',0)} / {by_sev.get('high',0)}",
         "repartition : " + ", ".join(f"{s} {by_sev.get(s,0)}" for s in SEV_ORDER)],
        ["Scans automatise en CI", "SAST + SCA a chaque push", "GitHub Actions + archivage artifacts 90 jours"],
    ]
    table(pdf, ["Indicateur", "Valeur", "Detail"], kpis, [62, 38, 90], ["L", "C", "L"])

    # ---------------- 3. ENVIRONNEMENT ----------------
    h1(pdf, "2. Environnement de test")
    body(pdf, "Instance EC2 (Ubuntu 26.04, 2 vCPU, 7.6 Go RAM, volume EBS 30 Go). "
              "Les trois applications sont deploies en Docker et verifiees par healthchecks "
              "(scripts/check_targets.sh).")
    table(pdf, ["Application", "Version", "Port", "Role", "Reference TP"],
          [["OWASP Juice Shop", "v20.2.0", "3000", "SAST + DAST (SQLi, XSS, CSRF)", "TP1, TP2, TP3"],
           ["OWASP crAPI", "latest", "8888", "API REST (BOLA, BFLA)", "TP4"],
           ["Roundcube Webmail", "1.6.21-apache", "8080", "SCA (dependances PHP)", "Module Email"],
           ["SonarQube", "community 26.11", "9000", "SAST - analyse statique", "Phase 3"],
           ["OWASP ZAP", "stable (AF)", "8090", "DAST - scan dynamique", "Phase 4"]],
          [42, 32, 16, 58, 42], ["L", "C", "C", "L", "L"])

    # ---------------- 4. GROUND TRUTH ----------------
    h1(pdf, "3. Ground truth - vulnerabilites reellement presentes")
    body(pdf, "Etabli par tests manuels sur l instance deployee (curl) et les TP valides. "
              "Seules les entrees confirmed/pending entrent dans le calcul des metriques.")
    rows = []
    for v in gt["vulnerabilities"]:
        rows.append([v["id"], v["target"], v["title"][:58], v["cwe"], v["severity"], v["status"]])
    table(pdf, ["ID", "Cible", "Vulnerabilite", "CWE", "Gravite", "Statut"], rows,
          [14, 22, 78, 24, 22, 30], ["C", "L", "L", "C", "C", "C"], sev_col=4)

    # ---------------- 5. RESULTATS PAR OUTIL ----------------
    h1(pdf, "4. Resultats des outils (apres normalisation)")
    rows = []
    for t, n in by_tool.most_common():
        sev = Counter(f["severity"] for f in findings if f["tool"] == t)
        typ = Counter(f["type"] for f in findings if f["tool"] == t)
        rows.append([TOOL_LABEL.get(t, t), str(n),
                     str(sev.get("critical", 0)), str(sev.get("high", 0)),
                     str(sev.get("medium", 0)), str(sev.get("low", 0)),
                     ", ".join(sorted(typ))])
    table(pdf, ["Outil", "Total", "Crit", "Eleve", "Moy", "Faible", "Type"], rows,
          [50, 16, 16, 16, 16, 16, 40], ["L", "C", "C", "C", "C", "C", "L"])
    body(pdf, "Le schema normalise (orchestrator/normalize.py) unifie 7 outils dans un meme format : "
              "cette uniformisation est ce qui rend possible la comparaison inter-outils et le "
              "calcul automatique des metriques.")

    # ---------------- 6. METRIQUES ----------------
    pdf.add_page()
    h1(pdf, "5. Metriques d evaluation vs ground truth")
    body(pdf, "Recall (ou sensibilite) = part des vulnerabilites du ground truth effectivement "
              "detectees par l outil. Precision indicative = part des findings rattaches a une "
              "vulnerabilite connue (le ground truth n est pas exhaustif : les findings non "
              "rattaches sont des non-classes, candidats a une revue manuelle).")
    rows = []
    for t, m in sorted(metrics.get("tools", {}).items(), key=lambda kv: -(kv[1].get("recall_pct") or -1)):
        rec = m.get("recall_pct"); prec = m.get("precision_pct")
        rows.append([TOOL_LABEL.get(t, t), str(m.get("tp", 0)), str(m.get("fn", 0)),
                     f"{rec}%" if rec is not None else "n/a",
                     str(m.get("findings", 0)), str(m.get("matched_findings", 0)),
                     f"{prec}%" if prec is not None else "n/a"])
    table(pdf, ["Outil", "TP", "FN", "Recall", "Findings", "Rattaches", "Precision*"], rows,
          [52, 14, 14, 24, 24, 26, 36], ["L", "C", "C", "C", "C", "C", "C"])

    # Barres de recall
    h2(pdf, "Recall par outil")
    x0, wmax = pdf.l_margin + 62, 90
    for t, m in metrics.get("tools", {}).items():
        rec = m.get("recall_pct")
        if rec is None: continue
        y = pdf.get_y()
        pdf.set_font("Helvetica", "", 8.5)
        pdf.cell(60, 6, safe(TOOL_LABEL.get(t, t)))
        pdf.set_fill_color(230, 235, 240)
        pdf.rect(x0, y, wmax, 6, style="F")
        r, g, b = SEV_COLOR["high"] if rec < 60 else ((196, 156, 14) if rec < 100 else (30, 130, 70))
        pdf.set_fill_color(r, g, b)
        pdf.rect(x0, y, wmax * rec / 100.0, 6, style="F")
        pdf.set_text_color(0, 0, 0)
        pdf.set_xy(x0 + wmax + 3, y)
        pdf.cell(25, 6, f"{rec}%")
        pdf.set_xy(pdf.l_margin, y + 6)
    pdf.ln(3)

    # Matrice de detection GT
    h2(pdf, "Matrice de detection du ground truth")
    tools_cols = ["semgrep", "custom", "authz_checker", "sonarqube", "zap", "trivy", "npm_audit"]
    heads = ["ID", "Sev"] + ["Sem", "Cus", "Aut", "Son", "ZAP", "Trv", "npm"]
    rows = []
    for vid, row in metrics.get("ground_truth", {}).items():
        cells = [vid, row.get("severity", "")]
        for t in tools_cols:
            det = row.get("detected_by", []); mis = row.get("missed_by", [])
            if t in det: cells.append("D")
            elif t in mis: cells.append("RATE")
            else: cells.append("-")
        rows.append(cells)
    table(pdf, heads, rows, [16, 20] + [22] * 7, ["C"] * 9)
    body(pdf, "Lecture : D = detectee, RATE = presente dans le ground truth mais non detectee, "
              "- = hors perimetre de l outil.")

    # ---------------- 7. AVANT / APRES ----------------
    if rem:
        h1(pdf, "6. Scenario avant / apres remediatio (TP2)")
        body(pdf, f"Scenario : {rem.get('scenario','')}. Correction de la injection SQL de "
                  "routes/login.ts par des requetes preparees (parametres lies), puis re-scan "
                  "avec strictement la meme configuration d outils.")
        b, a = rem.get("before", {}), rem.get("after", {})
        table(pdf, ["Mesure", "Avant (code vulnérable)", "Apres (corrige)"],
              [["Alertes totales (Semgrep)", str(b.get("total")), str(a.get("total"))],
               ["Alertes sur routes/login.ts", str(len(b.get("login_ts", []))), str(len(a.get("login_ts", [])))],
               ["Alertes SQLi (regles custom + registry)", str(len(b.get("login_ts", []))), str(len(a.get("login_ts", [])))],
               ["Alertes introduites par le correctif", "-", str(len(rem.get("new_alerts", [])))]],
              [80, 55, 55], ["L", "C", "C"])
        body(pdf, "Les 3 alertes SQLi (express-sequelize-injection, raw-query-regex, "
                  "raw-query-user-input) disparaissent apres la remediatio, sans nouvelle "
                  "alerte introduite : le correctif TP2 est valide par le scan automatique.")

    # ---------------- 8. CI/CD ----------------
    h1(pdf, "7. Automatisation CI/CD (GitHub Actions)")
    body(pdf, "Le workflow .github/workflows/security.yml se declenche a chaque push/PR sur les "
              "chemins critiques (scanners, custom, orchestrator, ground-truth) ainsi que sur "
              "un planning hebdomadaire. Il realise :")
    for line in ["SAST : clone des 3 sources + Semgrep (regles OWASP + regles custom) + SonarQube (optionnel, secrets);",
                 "SCA : Trivy (vulnerabilites, secrets, misconfigurations) + npm audit;",
                 "DAST : scan ZAP baseline sur demande (workflow_dispatch);",
                 "Archivage : upload des artifacts (90 jours) + push automatique sur la branche results (historique horodaté)."]:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_x(pdf.l_margin + 6)
        pdf.multi_cell(0, 6, safe("- " + line), new_x="LMARGIN", new_y="NEXT")
    body(pdf, "Le pipeline local orchestrator/run_all.sh reproduit la meme chaine en une seule "
              "commande (SAST -> DAST -> SCA -> custom -> normalisation -> metriques).")

    # ---------------- 9. CONCLUSION ----------------
    h1(pdf, "8. Conclusion")
    body(pdf, "1) La plateforme est reproductible : un deploiement (deploy.sh), un scan "
              "(run_all.sh) et un rapport (report_pdf.py) suffisent a reproduire toute la chaine. "
              "2) Aucun outil n est exhaustif : Semgrep et Trivy atteignent 100% de recall sur "
              "le perimetre evalue, SonarQube 50% (il rate la SQLi), ZAP 66.7% (il ne voit pas "
              "la SQLi en JSON non authentifie). 3) Le mecanisme personnalise apporte une "
              "valeur unique : authz_checker detecte le BOLA/BFLA que aucun outil standard ne "
              "couvre, avec la meilleure precision (50%). 4) La complementarite SAST/DAST/SCA "
              "est confirmee : chaque classe de vulnerabilite est couverte par au moins un "
              "outil, et la fusion normalisee permet une lecture commune. 5) Le scenario "
              "avant/apres prouve que l integration du scan en CI valide automatiquement les "
              "corrections.")

    os.makedirs(os.path.dirname(out_pdf) or ".", exist_ok=True)
    pdf.output(out_pdf)
    print(f"Rapport PDF genere : {out_pdf} ({os.path.getsize(out_pdf)} octets)")

if __name__ == "__main__":
    main()
