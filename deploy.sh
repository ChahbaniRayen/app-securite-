#!/usr/bin/env bash
# =============================================================
# Deploiement des 3 applications cibles (Phase 1)
#   - OWASP Juice Shop v20.2.0  -> :3000  (TP1, TP2, TP3)
#   - Roundcube Webmail 1.6.21  -> :8080  (module Email)
#   - OWASP crAPI (compose officiel) -> :8888 (TP4)
# Usage : ./deploy.sh
# =============================================================
set -euo pipefail
cd "$(dirname "$0")"

echo "[1/4] --- Juice Shop + Roundcube : pull + demarrage ---"
docker compose pull
docker compose up -d

echo "[2/4] --- crAPI : clone du depot officiel (si absent) ---"
if [ ! -d third_party/crAPI/.git ]; then
  git clone --depth 1 https://github.com/OWASP/crAPI.git third_party/crAPI
fi

echo "[3/4] --- crAPI : pull + demarrage (LISTEN_IP=0.0.0.0) ---"
cd third_party/crAPI/deploy/docker
docker compose pull
LISTEN_IP="0.0.0.0" docker compose -f docker-compose.yml --compatibility up -d
cd "$(dirname "$0")"

echo "[4/4] --- Verification de sante des 3 cibles ---"
./scripts/check_targets.sh
echo "=== DEPLOIEMENT TERMINE ==="
