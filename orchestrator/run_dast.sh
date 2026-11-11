#!/usr/bin/env bash
# =============================================================
# DAST : OWASP ZAP (Docker)
#   Mode "baseline" : scan passif rapide (en-tetes, cookies, URLs)
#   Mode "full"     : spider + active scan (injections, XSS, ...)
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

echo "### [DAST:$MODE] sortie : $OUT"
for t in "${TARGETS[@]}"; do
  URL="$(url_of "$t")"
  [ -z "$URL" ] && { echo "[SKIP] $t"; continue; }
  echo "### [DAST:$MODE] $t -> $URL"
  if [ "$MODE" = "baseline" ]; then
    docker run --rm --network host -v "$OUT":/out -v "$ROOT/scanners/zap":/zapcfg:ro \
      -e ZAP_PORT=8090 \
      "$IMAGE" zap.sh -cmd -silent \
        -quickurl "$URL" \
        -quickout "/out/zap-baseline-$t.html" \
        -quickjson "/out/zap-baseline-$t.json" \
        -quickprogress "/out/zap-baseline-$t.progress" \
      > "$OUT/zap-baseline-$t.log" 2>&1
  else
    docker run --rm --network host -v "$OUT":/out -v "$ROOT/scanners/zap":/zapcfg:ro \
      --memory=3g \
      "$IMAGE" zap.sh -cmd \
        -fullurl "$URL" \
        -fullout "/out/zap-full-$t.html" \
        -fulljson "/out/zap-full-$t.json" \
        -fullprogress "/out/zap-full-$t.progress" \
      > "$OUT/zap-full-$t.log" 2>&1
  fi
  RC=$?
  if [ $RC -eq 0 ] && [ -f "$OUT/zap-$MODE-$t.json" ]; then
    python3 -c "
import json
d = json.load(open('$OUT/zap-$MODE-$t.json'))
sites = d.get('site', [])
alerts = sum(len(s.get('alerts', [])) for s in sites)
print('    -> zap-$MODE-$t.json :', alerts, 'alertes')"
  else
    echo "    [ECHEC rc=$RC] voir zap-$MODE-$t.log"; tail -3 "$OUT/zap-$MODE-$t.log" 2>/dev/null
  fi
done
echo "### [DAST:$MODE] TERMINE"
