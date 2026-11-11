#!/usr/bin/env bash
# =============================================================
# DAST : OWASP ZAP - Automation Framework (-autorun)
#   baseline : spider uniquement (passif)
#   full     : spider + activeScan (injections, XSS, CSRF, ...)
# Usage : ./orchestrator/run_dast.sh [baseline|full] [cible...]
# Sortie : results/<date>/dast/zap-<mode>-<cible>.{html,json}
# =============================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-baseline}"; shift || true
DATE="${SCAN_DATE:-$(date +%Y%m%d-%H%M%S)}"
OUT="$ROOT/results/$DATE/dast"
IMAGE="ghcr.io/zaproxy/zaproxy:stable"
mkdir -p "$OUT"

TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(juice-shop crapI roundcube)

url_of() {
  case "$1" in
    juice-shop) echo "http://127.0.0.1:3000" ;;
    crapI)      echo "http://127.0.0.1:8888" ;;
    roundcube)  echo "http://127.0.0.1:8080" ;;
  esac
}

gen_yaml() {  # $1=cible $2=url $3=mode
  local t="$1" url="$2" m="$3"
  local ascan=""
  if [ "$m" = "full" ]; then
    ascan="
  - type: activeScan
    name: activeScan
    parameters:
      context: secscan
      url: $url
      maxRuleDurationInMins: 5
      maxScanDurationInMins: 25
      maxThreads: 2"
  fi
  cat > "$OUT/zap-$m-$t.yaml" <<YAMLEOF
---
env:
  contexts:
    - name: secscan
      urls:
        - $url
      includePaths:
        - $url.*
  parameters:
    failOnError: false
    failOnWarning: false
jobs:
  - type: spider
    name: spider
    parameters:
      context: secscan
      url: $url
      maxDuration: 8
$ascan
  - type: report
    name: report-html
    parameters:
      template: risk-confidence-html
      reportDir: /out
      reportFile: zap-$m-$t
      reportTitle: "ZAP $m scan - $t"
      displayReport: false
  - type: report
    name: report-json
    parameters:
      template: traditional-json
      reportDir: /out
      reportFile: zap-$m-$t
      reportTitle: "ZAP $m scan - $t"
      displayReport: false
YAMLEOF
}

echo "### [DAST:$MODE] sortie : $OUT"
for t in "${TARGETS[@]}"; do
  URL="$(url_of "$t")"
  [ -z "$URL" ] && { echo "[SKIP] $t"; continue; }
  echo "### [DAST:$MODE] $t -> $URL"
  gen_yaml "$t" "$URL" "$MODE"
  docker run --rm --network host \
    -v "$OUT":/out \
    --memory=3g \
    "$IMAGE" zap.sh -cmd -port 8090 -notel -autorun "/out/zap-$MODE-$t.yaml" \
    > "$OUT/zap-$MODE-$t.log" 2>&1
  RC=$?   # 0=ok, 2=warnings (non fatal, cf doc ZAP)
  if [ -f "$OUT/zap-$MODE-$t.json" ]; then
    python3 -c "
import json
d = json.load(open('$OUT/zap-$MODE-$t.json'))
sites = d.get('site', [])
alerts = sum(len(s.get('alerts', [])) for s in sites)
print('    -> zap-$MODE-$t.json :', alerts, 'alertes')"
  else
    echo "    [ECHEC rc=$RC] dernières lignes du log :"
    grep -iE "error|exception|failed|invalid" "$OUT/zap-$MODE-$t.log" | tail -4
  fi
done
echo "### [DAST:$MODE] TERMINE"
