#!/usr/bin/env bash
# =============================================================
#  launch.sh — TOUT LE PROJET EN UNE SEULE COMMANDE
#  Deploiement -> Sante -> SAST -> DAST -> SCA -> Custom ->
#  Normalisation -> Metriques -> Rapport PDF -> Presentation
#
#  Usages :
#    ./launch.sh                 # complet (DAST baseline, ~8-12 min)
#    ./launch.sh --full          # + scan actif ZAP (~1h de plus)
#    ./launch.sh --quick         # sans DAST (~5 min)
#    ./launch.sh --skip-deploy   # ne redéploie pas les cibles
#    ./launch.sh --skip-sonar    # sans SonarQube (gain ~3 min)
# =============================================================
set -uo pipefail
cd "$(dirname "$0")"

ARGS=""
DO_DEPLOY=1
for a in "$@"; do
  case "$a" in
    --full)        ARGS="$ARGS" ;;                     # DAST full = défaut de run_all
    --quick)       ARGS="$ARGS --skip-dast" ;;
    --skip-deploy) DO_DEPLOY=0 ;;
    --skip-sonar)  ARGS="$ARGS --skip-sonar" ;;
    --dast-baseline) ARGS="$ARGS --dast-baseline" ;;
    *) echo "Option inconnue: $a (aide: voir en-tete du script)"; exit 1;;
  esac
done
# Par defaut : DAST baseline (rapide). --full => scan actif complet.
echo "$ARGS" | grep -q "skip-dast" || ARGS="$ARGS --dast-baseline"
[ "$1" = "--full" ] 2>/dev/null && ARGS=$(echo "$ARGS" | sed "s/ --dast-baseline//")

T0=$(date +%s)
echo "############################################################"
echo "#  LANCEMENT COMPLET — $(date '+%d/%m/%Y %H:%M:%S')"
echo "############################################################"

# [1] Deploiement des 3 cibles
if [ "$DO_DEPLOY" = "1" ]; then
  echo; echo "===== [1/8] DEPLOIEMENT (docker compose + crAPI) ====="
  ./deploy.sh || echo "[WARN] deploy.sh : erreur (les cibles existent peut-etre deja)"
else
  echo; echo "===== [1/8] DEPLOIEMENT : skip (--skip-deploy) ====="
fi

# [2] Sante
echo; echo "===== [2/8] SANTE DES CIBLES ====="
./scripts/check_targets.sh 90 || echo "[WARN] une ou plusieurs cibles ne repondent pas"

# [3-7] Pipeline de scans + normalisation + metriques
echo; echo "===== [3/8] PIPELINE DE SCANS (SAST/DAST/SCA/custom -> normalize -> metrics) ====="
# shellcheck disable=SC2086
./orchestrator/run_all.sh $ARGS

# Recuperer la date du scan effectue
SCAN_DIR=$(ls -td results/2* | head -1)
echo "Resultats : $SCAN_DIR"

# [8] Livrables
echo; echo "===== [8/8] RAPPORTS ====="
python3 orchestrator/report_pdf.py "$SCAN_DIR" && echo "  -> $SCAN_DIR/report.pdf"
python3 orchestrator/slides_pptx.py "$SCAN_DIR/presentation.pptx" "$SCAN_DIR" && echo "  -> $SCAN_DIR/presentation.pptx"

# Resume
T1=$(date +%s)
echo
echo "############################################################"
echo "#  TERMINE en $(( (T1-T0)/60 )) min $(( (T1-T0)%60 )) s"
echo "############################################################"
python3 - "$SCAN_DIR" <<'PYEOF'
import json, sys, os
d = sys.argv[1]
try:
    f = json.load(open(f"{d}/normalized/findings.json"))
    m = json.load(open(f"{d}/normalized/metrics.json"))
    print(f"  Findings normalises : {f['count']}")
    print("  Recall par outil     :", {k: (str(v['recall_pct'])+'%') if v.get('recall_pct') is not None else 'n/a'
                                       for k, v in m['tools'].items()})
    print(f"  Rapport PDF          : {d}/report.pdf")
    print(f"  Presentation PPTX    : {d}/presentation.pptx")
except Exception as e:
    print("  (resume partiel :", e, ")")
PYEOF
echo "  Cibles : http://$(curl -s -m3 https://api.ipify.org 2>/dev/null || echo IP_VM):3000 | :8080 | :8888"
