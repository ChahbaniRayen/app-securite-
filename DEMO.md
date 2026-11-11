# Script de démonstration (15 min)

> Instance : `ubuntu@54.162.183.99` — projet : `~/secscan-platform`
> Pré-requis : `./deploy.sh` déjà exécuté (3 cibles en ligne).

## Étape 1 — Déploiement de l'environnement (2 min)

```bash
cd ~/secscan-platform
./deploy.sh                  # (re)déploie les 3 cibles
./scripts/check_targets.sh   # vérifie la santé
```
**À montrer** : les 3 URLs répondent HTTP 200
- http://54.162.183.99:3000 (Juice Shop) — http://54.162.183.99:8080 (Roundcube) — http://54.162.183.99:8888 (crAPI)

## Étape 2 — Ground truth (1 min)

```bash
python3 -m json.tool ground-truth/vulnerabilities.json | head -40
```
**À dire** : 11 vulnérabilités référencées, issues des TP1-TP4, **6 confirmées par nos propres tests** (ex. SQLi → JWT admin obtenu avec `' OR 1=1--`).

## Étape 3 — Exécution automatisée des scans (5 min)

```bash
# Pipeline complet en une commande (SAST -> DAST -> SCA -> custom -> metrics)
./orchestrator/run_all.sh --skip-dast     # (~3 min ; sans DAST pour la démo)
# ou individuellement :
./orchestrator/run_sast.sh                # Semgrep + SonarQube
./orchestrator/run_dast.sh full           # ZAP spider + active scan
./orchestrator/run_sca.sh                 # Trivy + npm audit
```
**À montrer** : les compteurs d'alertes par outil qui s'affichent.

## Étape 4 — Mécanisme de détection personnalisé (3 min)

```bash
# 4a. Règles Semgrep custom (SQLi, CMDi, XSS, secrets) sur fixtures
docker run --rm -v $PWD/custom/semgrep-rules/testdata:/src:ro \
  -v $PWD/scanners/semgrep/rules:/rules:ro semgrep/semgrep:latest \
  semgrep scan --config /rules /src
# 4b. authz_checker : BOLA/BFLA automatisés (2 comptes, véhicules, requêtes croisées)
python3 custom/authz/authz_checker.py
```
**À dire** : 4 alertes sur le fichier vulnérable, **0 sur le corrigé** ; authz_checker détecte
le BOLA (accès au véhicule d'autrui → HTTP 200 + PII) et le BFLA (endpoint admin avec un
jeton USER) — **que aucun outil standard ne détecte**.

## Étape 5 — Collecte, normalisation, métriques (2 min)

```bash
AGG=results/AGGREGATE-$(date +%Y%m%d-%H%M%S)
# (l'agrégation des sorties de tous les outils est faite par normalize.py)
python3 orchestrator/normalize.py results/AGGREGATE-20261111-154335
python3 orchestrator/metrics.py   results/AGGREGATE-20261111-154335
```
**À montrer** : la matrice de détection GT (D / RATE / -) et le tableau
TP / FN / Recall / Precision par outil.

## Étape 6 — Exploitation : avant / après remédiation (2 min)

```bash
cat results/remediation-*/diff-remediation.json
```
**À dire** : correction SQLi (requêtes préparées, TP2 Phase 5) → re-scan avec la même
configuration → **3 alertes SQLi sur login.ts avant, 0 après, 0 régression**.

## Étape 7 — CI/CD (1 min)

```bash
git log --oneline -5            # historique des commits
```
**À montrer** : https://github.com/ChahbaniRayen/app-securite-/actions
→ push automatique → jobs SAST/SCA verts → artefacts archivés (90 j) + branche `results`.

## Étape 8 — Rapports (1 min)

```bash
python3 orchestrator/report_pdf.py results/AGGREGATE-20261111-154335
```
**À montrer** : `report.pdf` (synthèse, tableaux, métriques, scénario avant/après).
