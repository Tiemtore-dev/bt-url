# bt-url

Analyse d'URL (phishing / malware) par **Threat Intelligence**, avec une règle de décision simple :
**un verdict MALICIOUS d'une source faisant autorité prime sur tout le reste.**

> **Modèle ML : en cours d'entraînement.** Aucun modèle n'est livré avec ce dépôt ni utilisé pour l'instant.
> Le verdict repose sur les sources de Threat Intelligence et sur des indices lexicaux. Le code d'intégration
> du modèle est présent mais **désactivé par défaut** (voir [Modèle ML](#modèle-ml-en-cours-dentraînement)).

Extrait et durci à partir de la partie URL de [bt-knife](https://github.com/Tiemtore-dev/bt-knife) :
aucun moteur Rust, aucune règle YARA/Sigma/Snort.

## Utilisation locale

```bash
pip install -e ".[dev]"      # Python >= 3.10
cp .env.example .env         # clés API (toutes optionnelles)

bt-url https://exemple.com/login            # sortie lisible
bt-url https://exemple.com --json           # JSON complet
bt-url --file urls.txt                      # lot
```

Code de sortie : `0` CLEAN · `1` SUSPICIOUS · `2` HIGH_RISK / CONFIRMED_MALICIOUS · `3` UNKNOWN.

## Règles de décision (`src/bt_url/scoring.py`)

| # | Règle |
|---|---|
| 1 | **TI autoritaire MALICIOUS** (URLhaus, PhishTank vérifié, Google Safe Browsing, ThreatFox confiance ≥ 50, VirusTotal ≥ 3 moteurs) → `CONFIRMED_MALICIOUS` (0,95 ; 1,0 si ≥ 2 sources). **Rien ne peut l'abaisser** : ni d'autres sources CLEAN, ni un éventuel modèle « bénin ». |
| 2 | Source non autoritaire MALICIOUS (ex. OTX) → au moins `HIGH_RISK` ; tout SUSPICIOUS → au moins `SUSPICIOUS`. |
| 3 | Sans TI positive, les heuristiques lexicales (typosquatting, IP, `@`, punycode…) et, plus tard, le modèle sont combinés (noisy-OR) et **plafonnés à 0,89** : seule la TI peut « confirmer ». |
| 4 | **Un CLEAN ne diminue jamais le score** : une URL de phishing récente est souvent inconnue des bases. |
| 5 | Aucune donnée exploitable → `UNKNOWN`, jamais `CLEAN` par défaut. Les sources en erreur sont ignorées. |

Seuils : `≥ 0,90` MALICIOUS · `≥ 0,60` HIGH_RISK · `≥ 0,35` SUSPICIOUS.

## Sources

| Source | Clé (.env) | Autoritaire |
|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | oui, à partir de `VT_MIN_ENGINES` (3) moteurs |
| Google Safe Browsing | `GOOGLE_SAFEBROWSING_API_KEY` | oui |
| URLhaus / ThreatFox | `ABUSECH_API_KEY` (gratuite) | oui (ThreatFox : confiance ≥ 50) |
| PhishTank | `PHISHTANK_API_KEY` | oui si vérifié et valide |
| OTX AlienVault | `OTX_API_KEY` | non (indicatif ; domaines en liste blanche OTX ignorés) |

**Sans aucune clé, aucune base de menaces n'est interrogée** (les données de la cible sont tout de même collectées) : le verdict est alors `UNKNOWN` (ou `SUSPICIOUS` sur indices lexicaux forts).

## Service web (API + page)

```bash
pip install -e ".[api]"
uvicorn bt_url.api.app:app_factory --factory --port 8000     # puis http://localhost:8000
```

| Route | Rôle |
|---|---|
| `GET /` | Page web : verdict, raisons, sources, **données collectées sur la cible** (âge du domaine, DNS, TLS, RDAP, GeoIP…), certificat TLS, redirections, JSON complet |
| `POST /api/analyze` `{"url": "..."}` | Analyse (JSON). Erreurs : `422` invalide · `429` + `Retry-After` · `503` occupé · `504` délai dépassé |
| `GET /api/status` | Sources actives, statut du modèle (`training`), quota restant (aucun secret) |
| `GET /health` | Sonde de vie |

**Protection des quotas (aucun jeton requis pour les visiteurs)** :

| Variable | Défaut | Effet |
|---|---|---|
| `BT_URL_RATE_PER_MIN` / `_PER_HOUR` | 3 / 20 | Analyses par adresse IP |
| `BT_URL_GLOBAL_PER_MIN` | 4 | Plafond global (= quota gratuit VirusTotal) |
| `BT_URL_DAILY_BUDGET` | 300 | Analyses « réelles » par jour (UTC) |
| `BT_URL_CACHE_TTL` | 3600 s | Cache par URL canonique (60 s si résultat dégradé) |
| `BT_URL_MAX_CONCURRENT` | 4 | Analyses simultanées |
| `BT_URL_TRUST_PROXY` | false | `true` derrière un proxy : IP = dernière entrée de `X-Forwarded-For` |

Un résultat en cache ne consomme aucun quota ; deux demandes identiques simultanées partagent une seule analyse.
**Un seul worker uvicorn** : cache et limites sont en mémoire.

Page : aucun script/style en ligne, CSP stricte (`default-src 'none'`), DOM construit via `textContent`
(les données viennent de tiers).

## Déploiement sur un VPS (Docker)

L'image est construite et publiée automatiquement par la CI sur `ghcr.io/tiemtore-dev/bt-url` (workflow *Publish image*,
linux/amd64 + arm64). Tant que le dépôt est privé, l'image l'est aussi. Le VPS n'a besoin que de **trois fichiers**
(`docker-compose.yml`, `Caddyfile`, `.env`) : pas de code source, pas de build.

Prérequis : Docker + plugin Compose, un nom de domaine pointant vers le VPS, ports 80 et 443 ouverts.

```bash
# 1) une seule fois : autoriser le VPS à tirer l'image privée (PAT GitHub avec le droit read:packages)
echo "$GHCR_TOKEN" | docker login ghcr.io -u Tiemtore-dev --password-stdin

# 2) récupérer les fichiers de déploiement (scp, ou git clone) puis configurer
cp .env.example .env && nano .env          # DOMAIN + clés API

# 3) déployer
docker compose pull && docker compose up -d
docker compose logs -f app
```

Mise à jour : `docker compose pull && docker compose up -d`. Alternative sans registre : `docker compose up -d --build`
depuis un clone du dépôt.

- **Réglages non secrets** (limites de débit, cache, quotas…) : intégrés à l'image avec des valeurs par défaut ;
  surchargeables dans `.env`. **Les clés API ne sont jamais dans l'image** : seul `.env` (sur le VPS) les contient.
- `app` : image minimale, utilisateur non root, système de fichiers en lecture seule, capabilities retirées, 512 Mo max.
  **Aucun port publié** : seul Caddy est exposé.
- `caddy` : TLS Let's Encrypt automatique, corps de requête limité à 8 Ko, transmission de l'IP réelle du client
  (utilisée par la limitation de débit).
- Test local sans domaine : `DOMAIN=http://localhost`, `HTTP_PORT=8080` dans `.env`.
- Derrière votre propre proxy : `docker run -p 8000:8000 --env-file .env ghcr.io/tiemtore-dev/bt-url`. Ne mettez
  `BT_URL_TRUST_PROXY=true` que si un proxy de confiance est **devant** le conteneur, sinon la limitation par IP peut
  être contournée.

## Données collectées (sans modèle)

Indépendamment du modèle, chaque analyse d'un hôte **public** collecte et affiche : DNS (TTL, enregistrements A/AAAA/MX,
IP), TLS (certificat, durée de validité), enregistrement du domaine via RDAP/WHOIS (âge, expiration, serveurs de noms),
réseau (latence TCP, pays de l'IP via un service GeoIP tiers) et forme de l'URL — chacune avec sa signification.
Désactivable : `BT_URL_COLLECT=false`. Les hôtes non publics ne sont jamais contactés.

## Sécurité

- **SSRF** : un hôte non public (loopback, privé, link-local, métadonnées cloud) n'est jamais contacté ; chaque
  redirection est revalidée et le résolveur refuse ces adresses à la connexion.
- **Aucun secret dans le dépôt ni dans l'image** : les clés viennent de `.env` (ignoré par git et par Docker).
- Les erreurs internes ne sont jamais renvoyées au client (journalisées côté serveur uniquement).

## Modèle ML (en cours d'entraînement)

Un classifieur LightGBM est en cours d'entraînement. Il n'est **pas inclus** et **pas actif**. Les premiers essais ont
montré des biais (par exemple, un score très surestimé quand l'hôte commence par `www.`, et une détection faible des
URLs en adresse IP), d'où le choix de ne pas le mettre en production avant de l'avoir retravaillé.

Le code d'intégration est conservé pour les tests : `pip install -e ".[ml]"` puis
`BT_URL_ML_ENABLED=true BT_URL_MODEL_PATH=… BT_URL_MODEL_META=… BT_URL_MODEL_SHA256=…`. Le SHA256 est **obligatoire** :
`joblib` exécute du pickle, le fichier est vérifié avant tout chargement. Il peut aussi être récupéré via
`BT_URL_MODEL_URL` (HTTPS uniquement, vérifié avant installation).

## Tests

```bash
python -m pytest        # 148 tests, hors réseau
```

## Limites connues

- Sans clés API, aucune source n'est interrogée.
- Le typosquatting compare le domaine enregistrable à une courte liste de marques.
- Le suivi des redirections et les sondes TLS ne contactent que des hôtes publics, mais la vérification DNS puis la
  connexion TLS ne sont pas atomiques (DNS-rebinding non couvert pour la sonde TLS).
