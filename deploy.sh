#!/usr/bin/env sh
# Déploie (ou met à jour) bt-url sur ce serveur : ./deploy.sh
set -eu
cd "$(dirname "$0")"

command -v docker >/dev/null 2>&1 || { echo "Docker n'est pas installé : https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Le plugin « docker compose » est requis."; exit 1; }

if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  echo "Fichier .env créé. Renseignez DOMAIN et vos clés API (nano .env), puis relancez ./deploy.sh"
  exit 1
fi

domain=$(sed -n 's/^DOMAIN=\([^ #]*\).*/\1/p' .env | tail -1)
case "$domain" in
  ""|*exemple.com*) echo "Renseignez DOMAIN dans .env (ex. DOMAIN=bt-url.mondomaine.fr) puis relancez."; exit 1;;
esac

keys=$(grep -cE '^(VIRUSTOTAL|GOOGLE_SAFEBROWSING|OTX|ABUSECH|PHISHTANK)_API_KEY=[^ #]+' .env || true)
[ "$keys" -gt 0 ] || echo "Attention : aucune clé API dans .env — aucune base de menaces ne sera interrogée."

docker compose up -d --build
docker compose ps
echo "Déployé : https://$domain  (journaux : docker compose logs -f)"
