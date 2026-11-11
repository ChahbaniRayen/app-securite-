#!/usr/bin/env bash
# =============================================================
# Pipeline complet : SAST -> DAST -> SCA -> custom -> normalize -> metrics
# Tous les outils partagent la meme date de scan (results/<SCAN_DATE>/)
# Usage : ./orchestrator/run_all.sh [--skip-dast] [--skip-sonar]
# =============================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# Charger les secrets (SONAR_TOKEN) si presents
if [ -f .env ]; then set -a; . ./.env; set +a; fi
export SCAN_DATE="${SCAN_DATE:-$(date +%Y%m%d-%H%M%S)}"
SKIP_DAST=0; SKIP_SONAR=0; DAST_MODE="full"
for a in "$@"; do
  case "$a" in
    --skip-dast) SKIP_DAST=1;;
    --skip-sonar) SKIP_SONAR=1;;
    --dast-baseline) DAST_MODE="baseline";;
  esac
done

echo "########## SCAN_DATE=$SCAN_DATE ##########"
echo "[1/6] SAST (Semgrep + SonarQube)"
if [ "$SKIP_SONAR" = "1" ]; then SKIP_SONAR=1 ./orchestrator/run_sast.sh; else ./orchestrator/run_sast.sh; fi

echo "[2/6] DAST (ZAP : $DAST_MODE)"
if [ "$SKIP_DAST" = "1" ]; then echo "  (skip)"; else ./orchestrator/run_dast.sh "$DAST_MODE"; fi

echo "[3/6] SCA (Trivy + npm audit)"
./orchestrator/run_sca.sh

echo "[4/6] Detection custom (regles Semgrep maison)"
for pair in "juice-shop:third_party/juice-shop" "crapI:third_party/crAPI" "roundcube:third_party/roundcubemail"; do
  t="${pair%%:*}"; src="${pair##*:}"
  [ -d "$src" ] || continue
  docker run --rm -v "$ROOT/$src":/src:ro -v "$ROOT/scanners/semgrep/rules":/rules:ro \
    -v "$ROOT/results/$SCAN_DATE/sast-custom":/out \
    semgrep/semgrep:latest semgrep scan --json --config /rules --metrics=off --quiet \
    -o "/out/semgrep-custom-$t.json" /src >/dev/null 2>&1
done

echo "[5/6] Detection custom (authz_checker BOLA/BFLA sur crAPI)"
python3 custom/authz/authz_checker.py --out "results/$SCAN_DATE/custom" || echo "  (authz_checker: avertissement)"

echo "[6/6] Normalisation + Metriques"
AGG="results/$SCAN_DATE"
python3 orchestrator/normalize.py "$AGG"
python3 orchestrator/metrics.py "$AGG"

echo "########## TERMINE : results/$SCAN_DATE ##########"
