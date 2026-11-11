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
echo "[1/7] SAST (Semgrep + SonarQube)"
if [ "$SKIP_SONAR" = "1" ]; then SKIP_SONAR=1 ./orchestrator/run_sast.sh; else ./orchestrator/run_sast.sh; fi

echo "[2/7] DAST (ZAP : $DAST_MODE)"
if [ "$SKIP_DAST" = "1" ]; then echo "  (skip)"; else ./orchestrator/run_dast.sh "$DAST_MODE"; fi

echo "[3/7] SCA (Trivy + npm audit)"
./orchestrator/run_sca.sh

echo "[4/7] Detection custom (regles Semgrep maison)"
for pair in "juice-shop:third_party/juice-shop" "crapI:third_party/crAPI" "roundcube:third_party/roundcubemail"; do
  t="${pair%%:*}"; src="${pair##*:}"
  [ -d "$src" ] || continue
  docker run --rm -v "$ROOT/$src":/src:ro -v "$ROOT/scanners/semgrep/rules":/rules:ro \
    -v "$ROOT/results/$SCAN_DATE/sast-custom":/out \
    semgrep/semgrep:latest semgrep scan --json --config /rules --metrics=off --quiet \
    -o "/out/semgrep-custom-$t.json" /src >/dev/null 2>&1
done

echo "[5/7] Detection custom (authz_checker BOLA/BFLA sur crAPI)"
python3 custom/authz/authz_checker.py --out "results/$SCAN_DATE/custom" || echo "  (authz_checker: avertissement)"

echo "[6/7] Normalisation + Metriques"
AGG="results/$SCAN_DATE"
python3 orchestrator/normalize.py "$AGG"
python3 orchestrator/metrics.py "$AGG"

echo "[7/7] Generation des rapports (PDF + PPTX)"
python3 orchestrator/report_pdf.py "$AGG" \
  && echo "  -> $AGG/report.pdf" \
  || echo "  [ECHEC] report_pdf.py"
python3 orchestrator/slides_pptx.py "$AGG/presentation.pptx" "$AGG" \
  && echo "  -> $AGG/presentation.pptx" \
  || echo "  [ECHEC] slides_pptx.py"

echo "########## TERMINE : results/$SCAN_DATE ##########"
echo "  Rapport PDF       : $AGG/report.pdf"
echo "  Presentation PPTX : $AGG/presentation.pptx"
