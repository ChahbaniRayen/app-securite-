#!/usr/bin/env python3
"""
Presentation PowerPoint (.pptx) avec captures d ecran et notes de speech.
Images attendues dans shots/ : juice.png, crapi.png, roundcube.png,
  gh-actions.png, zap-report.png, metrics-terminal.png, authz-terminal.png
Usage : python3 orchestrator/slides_pptx.py [sortie.pptx]
"""
import json, sys, os, glob, datetime
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

NAVY = RGBColor(20, 50, 90)
BLUE = RGBColor(40, 80, 130)
GREY = RGBColor(90, 90, 90)
WHITE = RGBColor(255, 255, 255)
RED = RGBColor(178, 24, 44)
GREEN = RGBColor(30, 130, 70)
LIGHT = RGBColor(238, 242, 247)

def add_slide(prs, layout_idx, title, subtitle=None):
    layout = prs.slide_layouts[layout_idx]  # 5 = title only
    s = prs.slides.add_slide(layout)
    # bandeau
    band = s.shapes.add_shape(1, Inches(0), Inches(0), prs.slide_width, Inches(0.95))
    band.fill.solid(); band.fill.fore_color.rgb = NAVY
    band.line.fill.background(); band.shadow.inherit = False
    tf = band.text_frame; tf.margin_left = Inches(0.35); tf.margin_top = Inches(0.1)
    p = tf.paragraphs[0]; p.text = title
    p.font.size = Pt(26); p.font.bold = True; p.font.color.rgb = WHITE
    if subtitle:
        tb = s.shapes.add_textbox(Inches(0.4), Inches(1.0), prs.slide_width - Inches(0.8), Inches(0.45))
        pp = tb.text_frame.paragraphs[0]; pp.text = subtitle
        pp.font.size = Pt(13); pp.font.italic = True; pp.font.color.rgb = GREY
    return s

def bullets(s, items, top=1.55, size=15, left=0.5, width=12.3, height=5.5, color=None):
    tb = s.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = tb.text_frame; tf.word_wrap = True
    for i, it in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = "• " + it
        p.font.size = Pt(size); p.font.color.rgb = color or RGBColor(0, 0, 0)
        p.space_after = Pt(8)
    return tb

def img(s, path, left, top, width=None, height=None):
    if not os.path.exists(path):
        return None
    kw = {}
    if width: kw["width"] = Inches(width)
    if height: kw["height"] = Inches(height)
    return s.shapes.add_picture(path, Inches(left), Inches(top), **kw)

def table(s, headers, rows, left, top, width, height, size=11):
    shp = s.shapes.add_table(len(rows) + 1, len(headers), Inches(left), Inches(top),
                             Inches(width), Inches(height))
    t = shp.table
    for j, h in enumerate(headers):
        c = t.cell(0, j); c.text = h
        c.fill.solid(); c.fill.fore_color.rgb = NAVY
        for p in c.text_frame.paragraphs:
            p.font.size = Pt(size); p.font.bold = True; p.font.color.rgb = WHITE
            p.alignment = PP_ALIGN.CENTER
    for i, row in enumerate(rows, start=1):
        for j, v in enumerate(row):
            c = t.cell(i, j); c.text = str(v)
            c.fill.solid()
            c.fill.fore_color.rgb = LIGHT if i % 2 else WHITE
            for p in c.text_frame.paragraphs:
                p.font.size = Pt(size - 1)
                p.alignment = PP_ALIGN.CENTER if j else PP_ALIGN.LEFT
    return t

def notes(s, text):
    s.notes_slide.notes_text_frame.text = text

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "presentation.pptx"
    SHOT = "shots"
    gt = json.load(open("ground-truth/vulnerabilities.json"))
    agg = sorted(glob.glob("results/AGGREGATE-*/normalized/metrics.json"))
    metrics = json.load(open(agg[-1])) if agg else {"tools": {}}
    rem_files = sorted(glob.glob("results/remediation-*/diff-remediation.json"))
    rem = json.load(open(rem_files[-1])) if rem_files else {}
    today = datetime.date.today().strftime("%d/%m/%Y")

    prs = Presentation()
    prs.slide_width = Inches(13.333); prs.slide_height = Inches(7.5)

    # ---------- 1. TITRE ----------
    s = prs.slides.add_slide(prs.slide_layouts[6])  # blank
    bg = s.shapes.add_shape(1, 0, 0, prs.slide_width, prs.slide_height)
    bg.fill.solid(); bg.fill.fore_color.rgb = NAVY; bg.line.fill.background()
    tb = s.shapes.add_textbox(Inches(0.8), Inches(2.2), Inches(11.8), Inches(2.2))
    tf = tb.text_frame; tf.word_wrap = True
    p = tf.paragraphs[0]; p.text = "Plateforme automatisee de detection de vulnerabilites web"
    p.font.size = Pt(40); p.font.bold = True; p.font.color.rgb = WHITE; p.alignment = PP_ALIGN.CENTER
    p2 = tf.add_paragraph(); p2.text = "SAST - DAST - SCA + mecanisme personnalise + metriques + CI/CD"
    p2.font.size = Pt(20); p2.font.color.rgb = RGBColor(190, 210, 235); p2.alignment = PP_ALIGN.CENTER
    tb2 = s.shapes.add_textbox(Inches(0.8), Inches(4.9), Inches(11.8), Inches(1.6))
    tf2 = tb2.text_frame; tf2.word_wrap = True
    for i, line in enumerate(["Abderrahmen ABDELJALIL",
                              "Ecole Polytechnique Sousse - Securite des Applications Web & Email",
                              f"Soutenance - {today}"]):
        p = tf2.paragraphs[0] if i == 0 else tf2.add_paragraph()
        p.text = line; p.font.size = Pt(18); p.font.color.rgb = WHITE; p.alignment = PP_ALIGN.CENTER
    notes(s, "BONJOUR ET BIENVENUE. Je vais vous presenter notre projet : une plateforme automatisee "
             "de detection de vulnerabilites d applications web. L idee centrale est simple : aucun outil "
             "de securite n est complet, alors nous en avons combine quatre - SAST, DAST, SCA et un "
             "mecanisme personnalise - puis nous les avons evalues metriquement contre un referentiel de "
             "verite. Tout est automatise et reproduit via GitHub Actions. Duree estimee : 12 a 15 minutes.")

    # ---------- 2. CONTEXTE ----------
    s = add_slide(prs, 5, "Contexte & objectifs",
                  "Concevoir une solution reproductible qui automatise la detection ET l evaluation")
    bullets(s, [
        "Combiner SAST (code statique), DAST (execution) et SCA (dependances) dans une meme plateforme",
        "Evaluer la capacite REELLE de chaque outil a detecter les vulnerabilites presentes (ground truth issue des TP1-TP4)",
        "Centraliser les resultats dans un format unique, automatiser via CI/CD et produire des rapports exploitables",
        "Apport personnel : un mecanisme de detection complementaire (regles Semgrep + authz_checker BOLA/BFLA)",
        "Livrables : environnement deploie, pipeline automatise, metriques, rapport et presentation",
    ], size=16, height=5.2)
    notes(s, "NOTRE PROBLEME : les outils de securite existent, mais personne ne sait ce qu ils detectent "
             "vraiment. Nous repondons a trois questions : 1) qu elles vulnérabilites sont reellement "
             "presentes dans l application ? 2) quels outils les trouvent, lesquels les ratent ? 3) comment "
             "automatiser tout cela dans une pipeline reproductible ? Le ground truth - le referentiel de "
             "verite - est construit A PARTIR DES TP du module : c est ce qui rend l evaluation objective. "
             "Prenez note du mot cle : EVALUER, pas juste scanner.")

    # ---------- 3. ARCHITECTURE ----------
    s = add_slide(prs, 5, "Architecture de la plateforme", "Un depot Git, un deploiement, un scan, un rapport")
    bullets(s, [
        "Cibles Docker : Juice Shop (:3000) - crAPI (:8888) - Roundcube (:8080) + SonarQube (:9000)",
        "Scanners : Semgrep (OWASP + regles custom) - SonarQube - OWASP ZAP (Automation Framework) - Trivy - npm audit",
        "Orchestration : run_sast / run_dast / run_sca / run_all -> results/<date>/ archives horodatees",
        "Normalisation : normalize.py convertit 7 outils dans un schema JSON unique",
        "Evaluation : metrics.py confronte les findings au ground truth -> TP / FN / Recall / Precision",
        "CI/CD : GitHub Actions a chaque push -> SAST + SCA + artefacts + branche results",
    ], size=15, height=5.2)
    notes(s, "ARCHITECTURE EN COUCHES. En bas, les trois applications cibles en Docker, verifiees par des "
             "healthchecks. Au milieu, les sept sources de donnees - cinq outils standards plus nos deux "
             "contributions. En haut, la couche d orchestration : un script par type de scan, puis "
             "NORMALISATION dans un schema commun - c est la brique cle qui rend la comparaison possible - "
             "puis METRIQUES contre le ground truth. Tout est versionne dans Git, tout est horodate : "
             "c est ca la reproductibilite.")

    # ---------- 4. ENVIRONNEMENT / CIBLES (captures) ----------
    s = add_slide(prs, 5, "Environnement de test : les 3 cibles",
                  "Instance EC2 - Docker - sante verifiee par check_targets.sh")
    y = 1.65
    img(s, f"{SHOT}/juice.png", 0.4, y, width=4.1)
    img(s, f"{SHOT}/crapi.png", 4.65, y, width=4.1)
    img(s, f"{SHOT}/roundcube.png", 8.9, y, width=4.1)
    tb = s.shapes.add_textbox(Inches(0.4), Inches(5.9), Inches(12.6), Inches(1.2))
    tf = tb.text_frame; tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = ("Juice Shop v20.2.0 (TP1-3 : SQLi, XSS, CSRF) | crAPI (TP4 : API REST, BOLA/BFLA) | "
              "Roundcube 1.6.21 (module Email : SCA)")
    p.font.size = Pt(14); p.font.color.rgb = NAVY; p.font.bold = True
    notes(s, "VOICI LES TROIS APPLICATIONS en fonctionnement sur notre instance EC2. Juice Shop est la "
             "cible principale des TP1 a TP3 - c est la que se trouve notre injection SQL confirmee. "
             "crAPI porte le TP4 sur les failles d autorisation d API. Roundcube apporte la dimension "
             "messagerie et un cas concret d analyse de dependances PHP. Chaque application est verifiee "
             "automatiquement : si l une d elles ne repond pas en HTTP 200, le pipeline s arrete. "
             "(Montrez les URLs dans le navigateur si possible.)")

    # ---------- 5. GROUND TRUTH ----------
    s = add_slide(prs, 5, "Ground truth : le referentiel d evaluation",
                  f"{len(gt['vulnerabilities'])} vulnerabilites - tests manuels + TP valides")
    rows = [[v["id"], v["target"], v["title"][:56], v["severity"], v["status"]]
            for v in gt["vulnerabilities"]]
    table(s, ["ID", "Cible", "Vulnerabilite", "Gravite", "Statut"], rows,
          left=0.5, top=1.6, width=12.3, height=4.9, size=11)
    notes(s, "LE GROUND TRUTH, c est le coeur de l evaluation. On ne peut pas mesurer la qualite d un "
             "outil sans savoir la verite. Nous avons liste 11 vulnerabilites : 6 CONFIRMEES par nos "
             "propres tests sur l instance deployee - par exemple JS-001 : avec le payload d injection "
             "SQL du TP2, nous obtenons le JWT de l administrateur sans mot de passe. 3 sont en attente "
             "de verification automatique, 2 sont des hypotheses non prouvees et sont EXCLUES des "
             "metriques pour rester honnetes. Chaque entree precise aussi quels outils devraient la "
             "detecter : c est la regle du jeu du calcul de recall.")

    # ---------- 6. SAST ----------
    s = add_slide(prs, 5, "SAST : Semgrep + SonarQube + regles custom", "Analyse statique sur les 3 sources")
    bullets(s, [
        "Semgrep (profils OWASP) : 241 alertes - rapide, oriente vulnerabilites, CWE/OWASP en metadata",
        "SonarQube : 667 issues - oriente qualite... mais RATE la SQLi (recall 50%)",
        "Regles custom (personnelles, mode taint) : SQLi TP2, command injection, XSS DOM, secrets hardcodes",
        "Validation sur fixtures : 4 alertes sur le fichier vulnerable, 0 sur le corrige",
        "Preuve : notre regle detecte JS-001 sur routes/login.ts:34 ou SonarQube ne voit RIEN",
    ], size=15, height=3.6, width=7.6)
    img(s, f"{SHOT}/semgrep-terminal.png", 8.3, 1.6, width=4.6)
    notes(s, "EN SAST, deux outils tres differents. Semgrep est un moteur de regles de SECURITE : mode "
             "taint, sources et sinks - exactement le schema Source vers Sink du TP2. SonarQube est un "
             "moteur de QUALITE : 667 issues, mais il ne reconnait pas notre injection SQL. Notre "
             "contribution : quatre regles custom ecrites a la main, testees sur des fixtures - quatre "
             "alertes sur le code vulnerable, ZERO sur le code corrige. Et voyez cette capture : notre "
             "regle signale routes/login.ts ligne 34, la ligne exacte du TP2, la ou SonarQube reste muet. "
             "C est la premiere preuve de la complementarite.")

    # ---------- 7. DAST ----------
    s = add_slide(prs, 5, "DAST : OWASP ZAP (Automation Framework)", "Scan dynamique contre l application en fonctionnement")
    bullets(s, [
        "Baseline (spider passif) puis scan actif complet (spider + activeScan, budgets de temps)",
        "Rapports HTML + JSON generees par les templates ZAP, archives par date",
        "Detecte : en-tetes de securite manquants, divulgation de versions, cookies sans SameSite",
        "Limite : ZAP rate la SQLi en JSON sur login non authentifie (recall 66.7%)",
        "ZAP ne couvre pas BOLA/BFLA -> complement oblige",
    ], size=15, height=3.6, width=7.6)
    img(s, f"{SHOT}/zap-report.png", 8.3, 1.6, width=4.6)
    notes(s, "EN DAST, OWASP ZAP tourne sans interface via l AUTOMATION FRAMEWORK : un fichier YAML qui "
             "enchaaine spider, scan actif et generation de rapports. Resultat : 5, 8 et 13 alertes selon "
             "les cibles. Sur cette capture : le rapport HTML genere. IMPORTANT - les limites : ZAP n a "
             "pas detecte notre injection SQL, car le login est en JSON dans une SPA sans formulaire "
             "classique a fuzzler, et ZAP ignore totalement les failles d autorisation. Ce n est pas un "
             "echec de l outil, c est la demonstration que SAST et DAST sont COMPLEMENTAIRES.")

    # ---------- 8. SCA ----------
    s = add_slide(prs, 5, "SCA : Trivy + npm audit", "Dependances, secrets et configuration")
    bullets(s, [
        "Trivy image : 70 CVE (Juice Shop) / 149 (postgres crAPI) / 194 (Roundcube) en HIGH+CRITICAL",
        "Trivy fs : sources + secrets + misconfigurations -> 591 findings (dont 9 secrets, 153 misconfigs)",
        "npm audit : 55 paquets vulnerables (7 critical, 22 high) - lockfile regenere automatiquement",
        "Secrets hardcodes de crAPI identifies : JWT_SECRET=crapi, mots de passe de base en clair (CR-004)",
        "Dimension A06:2025 - securite de la chaine d approvisionnement",
    ], size=15, height=5.2)
    notes(s, "EN SCA, on ne regarde plus le code de l application mais CE QU IL UTILISE. Trivy analyse "
             "les images Docker et les sources : pres de 415 CVE HIGH ou CRITICAL sur les images "
             "seules. npm audit revele 55 paquets vulnerables dans Juice Shop, dont 7 critiques. Et un "
             "resultat concret : la detection de secrets - le JWT_SECRET de crAPI vaut litteralement "
             "'crapi' dans son docker-compose. Attention cependant : un CVE n est pas forcement "
             "exploitable, c est pour ca qu on confronte au ground truth plutot que d additionner les "
             "alertes.")

    # ---------- 9. MECANISME PERSONNALISE ----------
    s = add_slide(prs, 5, "Mecanisme complementaire personnalise",
                  "authz_checker : detecter ce que les outils standards ratent")
    bullets(s, [
        "authz_checker.py (Python) : reproduction automatisee de la methodologie du TP4",
        "2 comptes (foulen/foulana) + vehicules seedes + requetes croisees jeton/ressource",
        "BOLA : GET /vehicle/<uuid victime>/location avec le jeton attaquant -> 200 + PII du proprietaire",
        "BFLA : endpoints admin avec un jeton USER -> pas de 401/403 (CWE-285)",
        "Aucun outil standard ne detecte ces failles : complementarite prouvee",
    ], size=15, height=3.6, width=7.6)
    img(s, f"{SHOT}/authz-terminal.png", 8.3, 1.6, width=4.6)
    notes(s, "VOUS ETES MAINTENANT SUR NOTRE PART PERSONNELLE. Le BOLA et le BFLA - les failles du TP4 - "
             "ne sont detectes par AUCUN des outils standards : ZAP, Semgrep et SonarQube sont tous a "
             "zero. Alors nous avons ecrit authz_checker en Python : il cree ou connecte deux comptes, "
             "revendique les vehicules libres, puis rejoue les requetes en CROISANT le jeton d un "
             "utilisateur et la ressource de l autre. Resultat en capture : le BOLA repond HTTP 200 avec "
             "la localisation ET les donnees personnelles du proprietaire - preuve d un controle d objet "
             "absent. Le BFLA : l endpoint admin repond avec un simple jeton utilisateur. C est notre "
             "outil qui a la MEILLEURE precision du projet : 50 pourcent.")

    # ---------- 10. METRIQUES ----------
    s = add_slide(prs, 5, "Resultats : metriques vs ground truth",
                  "Recall = vulnerabilites detectees ; Precision* = findings rattaches (GT non exhaustif)")
    labels = {"semgrep": "Semgrep", "custom": "Regles custom", "authz_checker": "authz_checker",
              "sonarqube": "SonarQube", "zap": "OWASP ZAP", "trivy": "Trivy", "npm_audit": "npm audit"}
    rows = []
    for t, m in sorted(metrics.get("tools", {}).items(),
                        key=lambda kv: -(kv[1].get("recall_pct") or -1)):
        rec = m.get("recall_pct"); prec = m.get("precision_pct")
        rows.append([labels.get(t, t), m.get("tp", 0), m.get("fn", 0),
                     f"{rec}%" if rec is not None else "n/a",
                     m.get("findings", 0),
                     f"{prec}%" if prec is not None else "n/a"])
    table(s, ["Outil", "TP", "FN", "Recall", "Findings", "Precision*"], rows,
          left=0.5, top=1.65, width=12.3, height=3.6, size=13)
    tb = s.shapes.add_textbox(Inches(0.5), Inches(5.6), Inches(12.3), Inches(1.4))
    tf = tb.text_frame; tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = ("Aucun outil n est exhaustif : Semgrep/Trivy/custom = 100% recall | SonarQube = 50% | "
              "ZAP = 66,7% | La fusion des 7 sources couvre 100% du ground truth.")
    p.font.size = Pt(15); p.font.bold = True; p.font.color.rgb = NAVY
    p2 = tf.add_paragraph()
    p2.text = ("* Precision indicative : le GT n est pas exhaustif - les findings non rattaches sont des "
               "non-classes, a revue manuelle.")
    p2.font.size = Pt(11); p2.font.italic = True; p2.font.color.rgb = GREY
    notes(s, "VOICI LE TABLEAU PRINCIPAL de notre evaluation. Recall : la part des vraies failles "
             "trouvees. Semgrep, Trivy et nos regles customs atteignent 100 pourcent sur ce "
             "perimetre. SonarQube plafonne a 50 : il rate notre SQLi. ZAP a 66,7. Notre "
             "authz_checker : 66,7 avec la meilleure precision. Sur la colonne Precision, soyez prudents "
             "dans vos questions : le ground truth n est pas exhaustif, donc les findings non rattaches "
             "sont des NON-CLASSES pas des faux positifs - c est une nuance methodologique importante. "
             "La conclusion : la somme des outils couvre la totalite du referentiel.")

    # ---------- 11. AVANT / APRES ----------
    if rem:
        s = add_slide(prs, 5, "Exploitation : scenario avant / apres remediatio",
                      "Correction de la SQLi du TP2 (requetes preparees) puis re-scan")
        b, a = rem.get("before", {}), rem.get("after", {})
        table(s, ["Mesure", "Avant (vulnerable)", "Apres (corrige)"],
              [["Alertes totales (Semgrep)", b.get("total"), a.get("total")],
               ["Alertes sur routes/login.ts", len(b.get("login_ts", [])), len(a.get("login_ts", []))],
               ["Alertes introduites par le fix", "-", len(rem.get("new_alerts", []))]],
              left=1.5, top=1.8, width=10.3, height=2.2, size=14)
        bullets(s, [
            "Correctif TP2 : parametres lies (replacements) au lieu du template literal",
            "Les 3 alertes SQLi disparaissent : express-sequelize-injection + 2 regles custom",
            "0 alerte introduite par le correctif : pas de regression",
            "En CI : chaque push re-verifie automatiquement que la vulnerabilite reste corrigee",
        ], top=4.4, size=15)
        notes(s, "L EXPLOITATION DES RESULTATS, enfin. Nous avons applique le correctif du TP2 - requetes "
                 "preparees - sur une copie de Juice Shop, puis nous avons relance STRICTEMENT le meme "
                 "scan. Resultat : 3 alertes sur routes/login.ts avant, ZERO apres, et aucune nouvelle "
                 "alerte introduite. C est ce que l on appelle valider une correction par le scan : dans "
                 "notre pipeline CI, ce test devient automatique - si quelqu un reintroduit la faille, "
                 "le build echoue. C est le concret du 'shift left'.")

    # ---------- 12. CI/CD ----------
    s = add_slide(prs, 5, "Automatisation CI/CD - GitHub Actions",
                  "github.com/ChahbaniRayen/app-securite-")
    bullets(s, [
        "Declencheurs : push/PR sur les chemins critiques + planning hebdomadaire + manuel (workflow_dispatch)",
        "Jobs : SAST (clone + Semgrep + SonarQube optionnel) | SCA (Trivy + npm audit) | DAST a la demande",
        "Archivage : artefacts 90 jours + push automatique sur la branche results (historique horodate)",
        "Pipeline local equivalent : ./orchestrator/run_all.sh - toute la chaine en une commande",
    ], size=15, height=3.4, width=7.6)
    img(s, f"{SHOT}/gh-actions.png", 8.3, 1.6, width=4.6)
    notes(s, "L AUTOMATION. A chaque push sur les chemins critiques du depot, GitHub Actions declenche "
             "deux jobs paralleles : SAST et SCA. Les resultats sont archives en artefacts pendant 90 "
             "jours, puis compenses sur une branche results qui constitue l historique horodate des "
             "scans - visible sur cette capture. Sur le chemin, nous avons resolu trois problemes reels : "
             "un YAML casse par un heredoc imbrique, remplacer par un template base64 ; un tag d action "
             "invalide ; et le DAST, trop long pour chaque push, garde en declenchement manuel. "
             "Localement, run_all.sh reproduit la meme chaine.")

    # ---------- 13. CONCLUSION ----------
    s = add_slide(prs, 5, "Conclusion & perspectives")
    bullets(s, [
        "Solution reproductible : deploy.sh + run_all.sh + report_pdf.py = la chaine en 3 commandes",
        "Evaluation objective : ground truth fonde sur les TP, metriques TP/FN/Recall/Precision",
        "Complementarite prouvee : aucun outil seul ne suffit, la fusion couvre 100% du referentiel",
        "Apport original : authz_checker, seul a detecter BOLA/BFLA (precision 50%)",
        "Exploitation : scenario avant/apres qui valide automatiquement les corrections",
        "Perspectives : scan connecte sur ZAP, specs OpenAPI crAPI, dashboard, seuils de qualite en CI",
    ], size=16, height=5.4)
    notes(s, "POUR CONCLURE. Trois messages. Un : la plateforme est REPRODUCTIBLE - trois commandes "
             "suffisent a tout reproduire. Deux : l evaluation est OBJECTIVE - ground truth fonde sur "
             "vos TP, metriques calculees automatiquement, et une honnetetet methodologique sur les "
             "limites (precision indicative, candidats exclus). Trois : la complementarite est "
             "DEMONBREE chiffres a l appui - et notre mecanisme personnalise comble un trou reel que "
             "aucun outil standard ne couvre. Perspectives : authentifier ZAP pour scanner connecte, "
             "importer les specs OpenAPI de crAPI, et ajouter des seuils de qualite qui feraient echouer "
             "le build sous un recall cible. Je vous remercie - je suis a votre disposition pour vos "
             "questions.")

    prs.save(out)
    print(f"Presentation generee : {out} ({os.path.getsize(out)} octets, {len(prs.slides)} slides)")

if __name__ == "__main__":
    main()
