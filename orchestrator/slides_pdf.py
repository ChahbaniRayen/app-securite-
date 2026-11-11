#!/usr/bin/env python3
"""
Presentation du projet (slides PDF paysage).
Usage : python3 orchestrator/slides_pdf.py [sortie.pdf]
Donnees : ground-truth/, results/AGGREGATE-*/normalized/metrics.json
"""
import json, sys, os, glob, datetime
from fpdf import FPDF

def safe(s):
    s = str(s)
    for a, b in (("→","->"),("✓","OUI"),("✗","NON"),("•","-"),("’","'"),("—","-"),("–","-"),("…","...")):
        s = s.replace(a, b)
    return s.encode("latin-1","replace").decode("latin-1")

NAVY = (20, 50, 90)
BLUE = (40, 80, 130)
GREY = (90, 90, 90)
RED  = (178, 24, 44)
GREEN= (30, 130, 70)

class Deck(FPDF):
    def __init__(self):
        super().__init__(orientation="L", unit="mm", format="A4")
        self.set_auto_page_break(False)
    def slide(self, num, title, subtitle=None):
        self.add_page()
        self.set_fill_color(*NAVY)
        self.rect(0, 0, self.w, 22, style="F")
        self.set_xy(12, 4)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 14, safe(title))
        if subtitle:
            self.set_xy(12, 26)
            self.set_font("Helvetica", "I", 11)
            self.set_text_color(*GREY)
            self.cell(0, 7, safe(subtitle))
        # numero de slide
        self.set_xy(self.w - 30, self.h - 10)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(150, 150, 150)
        self.cell(20, 6, str(num), align="R")
        self.set_xy(12, 38)
        self.set_text_color(0, 0, 0)
    def bullets(self, items, size=13, gap=9, x=16):
        self.set_x(x)
        for it in items:
            self.set_font("Helvetica", "", size)
            self.set_text_color(*NAVY)
            self.cell(6, gap, "-")
            self.set_text_color(0, 0, 0)
            self.multi_cell(self.w - x - 20, gap, safe(it))
            self.ln(1.5)
            self.set_x(x)
    def kv_table(self, headers, rows, widths, size=10):
        self.set_font("Helvetica", "B", size)
        self.set_fill_color(*NAVY); self.set_text_color(255,255,255)
        for h, w in zip(headers, widths):
            self.cell(w, 8, safe(h), border=1, fill=True, align="C")
        self.ln()
        fill = False
        for row in rows:
            self.set_font("Helvetica", "", size)
            self.set_text_color(0,0,0)
            self.set_fill_color(238, 242, 247) if fill else self.set_fill_color(255,255,255)
            for c, w in zip(row, widths):
                self.cell(w, 7.5, safe(c)[:70], border=1, fill=True, align="C" if w < 40 else "L")
            self.ln()
            fill = not fill
        self.ln(3)

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "presentation.pdf"
    gt = json.load(open("ground-truth/vulnerabilities.json"))
    agg = sorted(glob.glob("results/AGGREGATE-*/normalized/metrics.json"))
    metrics = json.load(open(agg[-1])) if agg else {"tools": {}}
    rem_files = sorted(glob.glob("results/remediation-*/diff-remediation.json"))
    rem = json.load(open(rem_files[-1])) if rem_files else {}
    today = datetime.date.today().strftime("%d/%m/%Y")

    d = Deck()

    # --- 1. Titre ---
    d.add_page()
    d.set_fill_color(*NAVY); d.rect(0, 0, d.w, d.h, style="F")
    d.set_xy(0, 55); d.set_font("Helvetica", "B", 30); d.set_text_color(255,255,255)
    d.cell(d.w, 16, safe("Plateforme automatisee de detection"), align="C", new_x="LMARGIN", new_y="NEXT")
    d.cell(d.w, 16, safe("de vulnerabilites web"), align="C", new_x="LMARGIN", new_y="NEXT")
    d.ln(8)
    d.set_font("Helvetica", "", 15); d.set_text_color(190, 210, 235)
    d.cell(d.w, 9, safe("SAST - DAST - SCA + mecanisme personnalise + metriques + CI/CD"), align="C", new_x="LMARGIN", new_y="NEXT")
    d.ln(16)
    d.set_font("Helvetica", "", 13); d.set_text_color(255,255,255)
    for line in ["Abderrahmen ABDELJALIL", "Ecole Polytechnique Sousse - Securite des Applications Web & Email", f"Juin/Novembre {today.split('/')[2]}"]:
        d.cell(d.w, 9, safe(line), align="C", new_x="LMARGIN", new_y="NEXT")

    # --- 2. Contexte & objectifs ---
    d.slide(2, "Contexte & objectifs", "Concevoir une solution reproductible qui automatise la detection et l evaluation des vulnerabilites")
    d.bullets([
        "Objectif : combiner SAST (code statique), DAST (exécution) et SCA (dependances) dans une meme plateforme",
        "Evaluer la capacite reelle de chaque outil a detecter les vulnerabilites PRESENTES (ground truth issue des TP1-TP4)",
        "Centraliser les resultats dans un format unique, automatiser via CI/CD (GitHub Actions) et produire des rapports exploitables",
        "Apport personnel : un mecanisme de detection complementaire (regles Semgrep + authz_checker BOLA/BFLA)",
    ], size=14, gap=10)

    # --- 3. Architecture ---
    d.slide(3, "Architecture de la plateforme", "Un depot Git unique, un deploiement, un scan, un rapport")
    d.bullets([
        "Cibles (Docker) : Juice Shop v20.2.0 (:3000) - crAPI (:8888) - Roundcube 1.6.21 (:8080) + SonarQube (:9000)",
        "Scanners : Semgrep (regles OWASP + regles custom) - SonarQube - OWASP ZAP (Automation Framework) - Trivy - npm audit",
        "Orchestration Python/Bash : run_sast / run_dast / run_sca / run_all -> results/<date>/ (archives horodatees)",
        "Normalisation : normalize.py convertit 7 outils dans un schema JSON unique -> comparaison possible",
        "Evaluation : metrics.py confronte les findings au ground truth -> TP / FN / Recall / Precision",
        "CI/CD : GitHub Actions a chaque push -> SAST + SCA + artefacts (90 j) + branche results",
    ], size=13, gap=9)

    # --- 4. Ground truth ---
    d.slide(4, "Ground truth : le referentiel d evaluation", f"{len(gt['vulnerabilities'])} vulnerabilites - methodologie : tests manuels sur l instance deployee + TP valides")
    rows = []
    for v in gt["vulnerabilities"]:
        rows.append([v["id"], v["target"], v["title"][:52], v["severity"], v["status"]])
    d.kv_table(["ID", "Cible", "Vulnerabilite", "Gravite", "Statut"], rows,
               [16, 30, 130, 35, 40], size=9)
    d.set_font("Helvetica", "I", 11); d.set_text_color(*GREY)
    d.set_x(16)
    d.multi_cell(0, 6, safe("Ex. JS-001 : injection SQL sur /rest/user/login confirmee par notre test "
                            "(payload \" OR 1=1-- -> JWT admin@juice-sh.op obtenu sans mot de passe)."))

    # --- 5. SAST ---
    d.slide(5, "SAST : Semgrep + SonarQube + regles custom", "Analyse statique sur les 3 sources clonées")
    d.bullets([
        "Semgrep (profils p/owasp-top-ten) : 241 alertes sur les 3 cibles - rapide, oriente vulnerabilites",
        "SonarQube (conteneur, API d export) : 667 issues - oriente qualite, mais RATE la SQLi (recall 50%)",
        "Regles custom (personnelles, taint mode) : SQLi template-literal (TP2), command injection (mini-lab), XSS DOM (TP3), secrets hardcodes (CR-004)",
        "Validation sur fixtures : 4 alertes sur le fichier vulnerable, 0 sur le fichier corrige (non-regression)",
        "Preuve : la regle custom detecte JS-001 sur routes/login.ts:34 la ou SonarQube ne voit rien",
    ], size=13, gap=9.5)

    # --- 6. DAST ---
    d.slide(6, "DAST : OWASP ZAP (Automation Framework)", "Scan dynamique contre les applications en fonctionnement")
    d.bullets([
        "Baseline (spider passif) sur les 3 cibles puis scan actif complet (spider + activeScan, budgets de temps)",
        "Rapports HTML + JSON (templates risk-confidence-html / traditional-json) archives par date",
        "Resultats : en-têtes de sécurité manquants, divulgation de versions (Server / X-Powered-By), cookies sans SameSite",
        "Limite observee : ZAP ne detecte PAS la SQLi en JSON sur le login non authentifie (recall 66.7% sur le GT)",
        "ZAP ne couvre pas les failles d autorisation (BOLA/BFLA) -> complement oblige (voir slide 9)",
    ], size=13, gap=9.5)

    # --- 7. SCA ---
    d.slide(7, "SCA : Trivy + npm audit", "Dependances applicatives et configuration")
    d.bullets([
        "Trivy image : 70 CVE (Juice Shop) / 149 (postgres crAPI) / 194 (Roundcube) en HIGH+CRITICAL",
        "Trivy fs : sources + secrets + misconfigurations -> 591 findings au total (dont 9 secrets, 153 misconfigs)",
        "npm audit (Juice Shop) : 55 paquets vulnerables (7 critical, 22 high) - lockfile regenere automatiquement",
        "Detection des secrets hardcodes de crAPI (JWT_SECRET=crapi, mots de passe base) -> corrobore CR-004",
    ], size=13, gap=10)

    # --- 8. Mecanisme personnalise ---
    d.slide(8, "Mecanisme complementaire personnalise", "La valeur ajoutee du projet : detecter ce que les outils standards ratent")
    d.bullets([
        "1) Regles Semgrep maison (scanners/semgrep/rules/) : 4 regles, mode taint, metadata CWE/OWASP/GT",
        "2) authz_checker.py (Python) : reproduction automatisee de la methodologie du TP4 -",
        "     2 comptes (foulen/foulana) + vehicules seedes + requetes croisees token/ressource",
        "BOLA : GET /vehicle/<uuid victime>/location avec le jeton attaquant -> HTTP 200 + PII du proprietaire",
        "BFLA : GET /workshop/api/management/users/all + DELETE /admin/videos/<id> avec un jeton USER -> pas de 401/403",
        "Aucun outil standard (ZAP/Semgrep/SonarQube) ne detecte ces failles : complementarite prouvee",
    ], size=13, gap=9)

    # --- 9. Resultats / metriques ---
    d.slide(9, "Resultats : metriques vs ground truth", "Recall = vulnerabilites du GT detectees ; Precision* = findings rattaches (GT non exhaustif)")
    rows = []
    labels = {"semgrep":"Semgrep","custom":"Regles custom","authz_checker":"authz_checker","sonarqube":"SonarQube","zap":"OWASP ZAP","trivy":"Trivy","npm_audit":"npm audit"}
    for t, m in sorted(metrics.get("tools", {}).items(), key=lambda kv: -(kv[1].get("recall_pct") or -1)):
        rec = m.get("recall_pct"); prec = m.get("precision_pct")
        rows.append([labels.get(t, t), str(m.get("tp",0)), str(m.get("fn",0)),
                     f"{rec}%" if rec is not None else "n/a",
                     str(m.get("findings",0)),
                     f"{prec}%" if prec is not None else "n/a"])
    d.kv_table(["Outil", "TP", "FN", "Recall", "Findings", "Precision*"], rows,
               [70, 25, 25, 40, 45, 50], size=11)
    d.set_font("Helvetica", "B", 12); d.set_text_color(*NAVY); d.set_x(16)
    d.multi_cell(0, 7, safe("Conclusion : aucun outil n est exhaustif -> la fusion normalisee des 7 sources "
                            "couvre l integralite du ground truth."))
    d.set_font("Helvetica", "", 11); d.set_text_color(*GREY); d.set_x(16)
    d.multi_cell(0, 7, safe("* Precision indicative a relecture manuelle : le GT ne reference pas toutes les "
                            "vulnerabilites reelles (findings non classes)."))

    # --- 10. Avant / apres ---
    if rem:
        d.slide(10, "Exploitation : scenario avant / apres", safe(rem.get("scenario", "")))
        b, a = rem.get("before", {}), rem.get("after", {})
        d.kv_table(["Mesure", "Avant (vulnerable)", "Apres (corrige)"],
                   [["Alertes totales (Semgrep)", str(b.get("total")), str(a.get("total"))],
                    ["Alertes sur routes/login.ts", str(len(b.get("login_ts", []))), str(len(a.get("login_ts", [])))],
                    ["Alertes introduites par le fix", "-", str(len(rem.get("new_alerts", [])))]],
                   [110, 65, 65], size=12)
        d.bullets([
            "Correctif TP2 : requetes preparees (parametres lies) au lieu du template literal",
            "Les 3 alertes SQLi (express-sequelize-injection + 2 regles custom) disparaissent, 0 regression",
            "Usage CI : chaque push re-verifie automatiquement que la vulnerabilite reste corrigee",
        ], size=13, gap=10)

    # --- 11. CI/CD ---
    d.slide(11, "Automatisation CI/CD - GitHub Actions", "github.com/ChahbaniRayen/app-securite-")
    d.bullets([
        "Declencheurs : push/PR sur les chemins critiques (scanners, custom, orchestrator, ground-truth) + planning hebdo + manuel",
        "Jobs : SAST (clone des 3 sources + Semgrep + SonarQube optionnel) | SCA (Trivy + npm audit) | DAST (ZAP baseline a la demande)",
        "Archivage : artifacts 90 jours + push automatique sur la branche results (historique horodaté des scans)",
        "Pipeline local equivalent : ./orchestrator/run_all.sh (meme chaine en une commande)",
        "Statut : SAST vert en CI ; SCA corrige (tag d action) ; rapports PDF regenerables a tout moment",
    ], size=13, gap=10)

    # --- 12. Conclusion ---
    d.slide(12, "Conclusion & perspectives")
    d.bullets([
        "Solution reproductible : deploy.sh + run_all.sh + report_pdf.py = toute la chaine en 3 commandes",
        "Evaluation objective : ground truth fonde sur les TP, metriques TP/FN/Recall/Precision par outil",
        "Complementarite prouvee : Semgrep/Trivy 100% recall | SonarQube 50% | ZAP 66.7% | authz_checker seul sur BOLA/BFLA",
        "Exploitation : scénario avant/apres qui prouve la validation automatique des corrections",
        "Perspectives : connecter crAPI a ZAP via OpenAPI, enrichir le GT (CR-003), dashboard HTML, seuils de qualite en CI",
    ], size=14, gap=11)

    d.output(out)
    print(f"Presentation generee : {out} ({os.path.getsize(out)} octets, {len(d.pages)} slides)")

if __name__ == "__main__":
    main()
