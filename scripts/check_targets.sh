#!/usr/bin/env bash
# Verification de sante des 3 cibles
#   $1 = timeout optionnel en secondes (defaut 420)
set -uo pipefail
TIMEOUT="${1:-420}"
DEADLINE=$(( $(date +%s) + TIMEOUT ))

check() {  # $1=nom $2=url $3=codes acceptes (regex)
  local name="$1" url="$2" ok_codes="$3"
  while true; do
    code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$url" 2>/dev/null || echo 000)
    if echo "$code" | grep -qE "$ok_codes"; then
      printf '  [OK]   %-12s %-45s HTTP %s\n' "$name" "$url" "$code"; return 0
    fi
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
      printf '  [FAIL] %-12s %-45s HTTP %s\n' "$name" "$url" "$code"; return 1
    fi
    sleep 5
  done
}

echo "Attente de sante des cibles (timeout ${TIMEOUT}s)..."
FAIL=0
check "juice-shop"  "http://127.0.0.1:3000/"       "200" || FAIL=1
check "roundcube"   "http://127.0.0.1:8080/"       "200|302" || FAIL=1
check "crAPI"       "http://127.0.0.1:8888/"       "200|302" || FAIL=1
exit $FAIL
