#!/usr/bin/env bash
# =============================================================
# SCA : Trivy (fs + images) + npm audit + composer audit
# Sortie : results/<date>/sca/*
# Usage : ./orchestrator/run_sca.sh [cible...]
# =============================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATE="${SCAN_DATE:-$(date +%Y%m%d-%H%M%S)}"
OUT="$ROOT/results/$DATE/sca"
mkdir -p "$OUT"

TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(juice-shop crapI roundcube)

echo "### [SCA] sortie : $OUT"

# ---------- 1. TRIVY sur les images des cibles ----------
declare -A IMAGES=(
  [juice-shop]="bkimminich/juice-shop:v20.2.0"
  [roundcube]="roundcube/roundcubemail:1.6.21-apache"
  [crapI]="postgres:14"   # representatif : image crAPI la plus critique (les autres = latest)
)
for t in "${TARGETS[@]}"; do
  img="${IMAGES[$t]:-}"
  [ -z "$img" ] && continue
  echo "### [trivy image] $t ($img)"
  trivy image --severity HIGH,CRITICAL --format json -o "$OUT/trivy-image-$t.json" "$img" >/dev/null 2>&1 \
    && python3 -c "
import json
d=json.load(open('$OUT/trivy-image-$t.json'))
n=sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results') or [])
print('    -> trivy-image-$t.json :', n, 'CVE HIGH/CRITICAL')" \
    || echo "    [ECHEC] trivy image $t"
done

# ---------- 2. TRIVY fs sur les sources ----------
declare -A SRCS=(
  [juice-shop]="third_party/juice-shop"
  [crapI]="third_party/crAPI"
  [roundcube]="third_party/roundcubemail"
)
for t in "${TARGETS[@]}"; do
  src="${SRCS[$t]:-}"
  [ -z "$src" ] || [ ! -d "$ROOT/$src" ] && continue
  echo "### [trivy fs] $t ($src)"
  trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL \
    --format json -o "$OUT/trivy-fs-$t.json" "$ROOT/$src" >/dev/null 2>&1 \
    && python3 -c "
import json
d=json.load(open('$OUT/trivy-fs-$t.json'))
n=sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results') or [])
s=sum(len(r.get('Secrets') or []) for r in d.get('Results') or [])
m=sum(len(r.get('Misconfigurations') or []) for r in d.get('Results') or [])
print('    -> trivy-fs-$t.json :', n, 'CVE |', s, 'secrets |', m, 'misconfigs')" \
    || echo "    [ECHEC] trivy fs $t"
done

# ---------- 3. npm audit (Juice Shop / sources Node) ----------
if [ -f "$ROOT/third_party/juice-shop/package.json" ]; then
  echo "### [npm audit] juice-shop"
  (cd "$ROOT/third_party/juice-shop" && npm audit --json > "$OUT/npm-audit-juice-shop.json" 2>/dev/null)
  python3 -c "
import json
try:
    d=json.load(open('$OUT/npm-audit-juice-shop.json'))
    m=d.get('metadata',{}).get('vulnerabilities',{})
    print('    -> npm-audit-juice-shop.json :', dict(m))
except Exception as e: print('    [ECHEC]', e)"
fi

# ---------- 4. composer audit (Roundcube) ----------
if [ -f "$ROOT/third_party/roundcubemail/composer.json" ]; then
  echo "### [composer audit] roundcube"
  if command -v composer >/dev/null 2>&1; then
    (cd "$ROOT/third_party/roundcubemail" && composer audit --format=json > "$OUT/composer-audit-roundcube.json" 2>/dev/null)
    echo "    -> composer-audit-roundcube.json"
  else
    echo "    [SKIP] composer absent (a installer) — trivy fs couvre vendor/ via lockfile"
  fi
fi

echo "### [SCA] TERMINE"
