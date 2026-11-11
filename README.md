# Plateforme automatisée de détection de vulnérabilités

Plateforme combinant **SAST** (Semgrep, SonarQube), **DAST** (OWASP ZAP) et
**SCA** (Trivy, npm audit) pour détecter et comparer les vulnérabilités de
3 applications web cibles, avec CI/CD GitHub Actions et métriques d'évaluation.

## Cibles déployées

| Application | Port | Rôle | Référence TP |
|---|---|---|---|
| OWASP Juice Shop `v20.2.0` | 3000 | SAST + DAST (SQLi, XSS, CSRF) | TP1, TP2, TP3 |
| OWASP crAPI | 8888 | API REST (BOLA, BFLA) | TP4 |
| Roundcube Webmail `1.6.21` | 8080 | SCA (dépendances PHP) | Module Email |

## Démarrage rapide — **TOUT EN UNE COMMANDE**

```bash
./launch.sh                 # deploiement + sante + SAST/DAST(baseline)/SCA
                            # + custom + metriques + rapport PDF + presentation PPTX
```

Options :
```bash
./launch.sh --full          # + scan actif ZAP complet (~1h en plus)
./launch.sh --quick         # sans DAST (~5 min)
./launch.sh --skip-deploy   # ne redéploie pas les cibles
./launch.sh --skip-sonar    # sans SonarQube (gain ~3 min)
```

### Commandes individuelles
```bash
./deploy.sh                 # déploie les 3 cibles + vérifie la santé
./scripts/check_targets.sh  # re-vérifie (420 s de timeout max)
./orchestrator/run_all.sh   # pipeline de scans seul (SAST/DAST/SCA/custom/metrics)
python3 orchestrator/report_pdf.py results/<scan>   # rapport PDF
python3 orchestrator/slides_pptx.py sortie.pptx results/<scan>  # presentation
docker compose down         # arrête Juice Shop + Roundcube
docker ps                   # état de tous les conteneurs
```

## Structure

```
secscan-platform/
├── docker-compose.yml      # Juice Shop + Roundcube
├── deploy.sh               # déploiement complet (3 cibles)
├── scripts/                # scripts utilitaires (santé, ...)
├── ground-truth/           # référentiel des vulnérabilités attendues
├── scanners/               # configs Semgrep, SonarQube, ZAP, SCA
├── custom/                 # mécanisme de détection personnalisé
├── orchestrator/           # pipeline d'exécution Python
├── results/                # résultats bruts archivés par date
├── reports/                # rapports consolidés (JSON/HTML)
├── remediation/            # scénario avant/après correction
└── third_party/            # dépôts clonés (crAPI) — git ignoré
```

## Comptes de test

| Application | Compte |
|---|---|
| crAPI | `foulen@poly.lab` / `foulana@poly.lab` (création via l'UI) |
| Juice Shop | `labtest@poly.tn` (création via l'UI) |
