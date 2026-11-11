#!/usr/bin/env bash
# =============================================================
# SAST : Semgrep (Docker) + SonarQube (sonar-scanner-cli Docker)
# Sortie : results/<date>/sast/{semgrep-<target>.json, sonar-<target>.json}
# Usage : ./orchestrator/run_sast.sh [cible...]   # defaut: les 3
# =============================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATE="${SCAN_DATE:-$(date +%Y%m%d-%H%M%S)}"
OUT="$ROOT/results/$DATE/sast"
SONAR_HOST="${SONAR_HOST_URL:-http://127.0.0.1:9000}"
SONAR_TOKEN="${SONAR_TOKEN:-}"
mkdir -p "$OUT"

TARGETS=("$@")
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(juice-shop crapI roundcube)

src_of() {
  case "$1" in
    juice-shop) echo "$ROOT/third_party/juice-shop" ;;
    crapI)      echo "$ROOT/third_party/crAPI" ;;
    roundcube)  echo "$ROOT/third_party/roundcubemail" ;;
    *) echo "" ;;
  esac
}
key_of() { case "$1" in juice-shop) echo juice-shop;; crapI) echo crapi;; roundcube) echo roundcube;; esac; }

echo "### [SAST] Sortie : $OUT"
SKIP_SEMGREP="${SKIP_SEMGREP:-0}"
SKIP_SONAR="${SKIP_SONAR:-0}"

# ---------- 1. SEMGREP ----------
if [ "$SKIP_SEMGREP" != "1" ]; then
# configs semgrep : par defaut p/owasp-top-ten (+ regles locales si presentes)
# SURCHARGE : SEMGREP_CONFIGS="--config ... --config ..." (separateur espace)
read -ra SEMGREP_CONFIGS <<< "${SEMGREP_CONFIGS:---config p/owasp-top-ten}"; 
if [ -d "$ROOT/scanners/semgrep/rules" ] && [ -n "$(ls -A "$ROOT/scanners/semgrep/rules" 2>/dev/null)" ]; then
  SEMGREP_CONFIGS+=("--config" "/rules")   # chemin DANS le conteneur (monte ci-dessous)
fi

for t in "${TARGETS[@]}"; do
  SRC="$(src_of "$t")"
  [ -z "$SRC" ] || [ ! -d "$SRC" ] && { echo "[SKIP] $t : source introuvable ($SRC)"; continue; }
  echo "### [semgrep] $t ..."
  docker run --rm -v "$SRC":/src:ro -v "$OUT":/out -v "$ROOT/scanners/semgrep/rules":/rules:ro \
    semgrep/semgrep:latest semgrep scan --json --timeout 120 \
    "${SEMGREP_CONFIGS[@]}" --metrics=off --quiet -o "/out/semgrep-$t.json" /src \
    && echo "    -> semgrep-$t.json ($(python3 -c "import json;d=json.load(open('$OUT/semgrep-$t.json'));print(len(d.get('results',[])),'alertes')" 2>/dev/null || echo '?'))" \
    || echo "    [ECHEC] semgrep $t"
done

fi

# ---------- 2. SONARQUBE ----------
if [ "$SKIP_SONAR" != "1" ]; then
if [ -n "$SONAR_TOKEN" ]; then
  for t in "${TARGETS[@]}"; do
    SRC="$(src_of "$t")"; KEY="$(key_of "$t")"
    [ -z "$SRC" ] || [ ! -d "$SRC" ] && { echo "[SKIP] $t"; continue; }
    echo "### [sonarqube] $t (key=$KEY) ..."
    docker run --rm --network host \
      -v "$SRC":/usr/src \
      -v "$OUT":/out \
      -e SONAR_HOST_URL="$SONAR_HOST" \
      -e SONAR_TOKEN="$SONAR_TOKEN" \
      -e SONAR_USER_HOME=/out/.sonar \
      sonarsource/sonar-scanner-cli:latest \
      -Dsonar.projectKey="$KEY" -Dsonar.projectName="$KEY" -Dsonar.projectVersion=1.0 \
      -Dsonar.sources=. -Dsonar.exclusions=**/node_modules/**,**/vendor/**,**/*.min.js,**/test/**,**/tests/** \
      -Dsonar.working.directory="/out/.sonar-$KEY" \
      > "$OUT/sonar-$t.log" 2>&1
    if grep -q "EXECUTION SUCCESS" "$OUT/sonar-$t.log"; then
      curl -s -H "Authorization: Bearer $SONAR_TOKEN" "$SONAR_HOST/api/issues/search?componentKeys=$KEY&ps=500" > "$OUT/sonar-$t.json"
      echo "    -> sonar-$t.json ($(python3 -c "import json;d=json.load(open('$OUT/sonar-$t.json'));print(d.get('total','?'),'issues')" 2>/dev/null || echo '?'))"
    else
      echo "    [ECHEC] voir $OUT/sonar-$t.log"; tail -3 "$OUT/sonar-$t.log"
    fi
  done
else
  echo "### [sonarqube] SONAR_TOKEN absent -> analyse SonarQube ignorée (configurer .env)"
fi

fi

echo "### [SAST] TERMINE"
