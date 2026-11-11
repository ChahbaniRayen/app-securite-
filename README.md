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

## Démarrage rapide

```bash
./deploy.sh                 # déploie les 3 cibles + vérifie la santé
./scripts/check_targets.sh  # re-vérifie (420 s de timeout max)
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
