# bt-url

Analyse d'URL (phishing / malware) : **Threat Intelligence + modèle ML**, avec une règle
de décision simple : **un verdict MALICIOUS d'une source faisant autorité prime sur tout le reste**.

Extrait et durci à partir de la partie URL de [bt-knife](https://github.com/Tiemtore-dev/bt-knife) :
aucun moteur Rust, aucune règle YARA/Sigma/Snort — uniquement la détection d'URL.

## Installation

```bash
pip install -e ".[dev]"      # Python >= 3.11
cp .env.example .env         # clés API (toutes optionnelles)
```

## Utilisation

```bash
bt-url https://exemple.com/login            # sortie lisible
bt-url https://exemple.com --json           # JSON complet
bt-url --file urls.txt --no-ml              # lot, sans ML
```

Code de sortie : `0` CLEAN · `1` SUSPICIOUS · `2` HIGH_RISK / CONFIRMED_MALICIOUS · `3` UNKNOWN.

```python
import asyncio
from bt_url.analyzer import URLAnalyzer
print(asyncio.run(URLAnalyzer().analyze("https://exemple.com"))["risk"])
```

## Règles de décision (`src/bt_url/scoring.py`)

| # | Règle |
|---|---|
| 1 | **TI autoritaire MALICIOUS** (URLhaus, PhishTank vérifié, Google Safe Browsing, ThreatFox confiance ≥ 50, VirusTotal ≥ 3 moteurs) → `CONFIRMED_MALICIOUS` (score 0,95 ; 1,0 si ≥ 2 sources). **Rien ne peut l'abaisser** : ni un ML « bénin », ni d'autres sources CLEAN. |
| 2 | Source non autoritaire MALICIOUS (ex. OTX) → au moins `HIGH_RISK` ; tout SUSPICIOUS → au moins `SUSPICIOUS`. |
| 3 | Sans TI positive : ML (poids 0,85) + heuristiques lexicales (typosquatting, IP, `@`, punycode…) combinés en noisy-OR, **plafonnés à 0,89** : le ML seul ne « confirme » jamais. |
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
| OTX AlienVault | `OTX_API_KEY` | non (indicatif) |

Sans aucune clé, il ne reste que le ML + heuristiques (verdict limité à HIGH_RISK).

## Service web (API + page)

```bash
pip install -e ".[api]"
uvicorn bt_url.api.app:app_factory --factory --port 8000     # puis http://localhost:8000
```

| Route | Rôle |
|---|---|
| `GET /` | Page web : verdict, preuves, sources, **toutes les données collectées pour le modèle** (âge du domaine, DNS, TLS, RDAP…) avec leur signification, JSON complet |
| `POST /api/analyze` `{"url": "..."}` | Analyse (JSON). Erreurs : `422` URL invalide · `429` + `Retry-After` · `503` occupé · `504` délai dépassé |
| `GET /api/status` | Sources actives, modèle chargé, quota restant (aucun secret) |
| `GET /health` | Sonde de vie |

**Protection des quotas (aucun jeton requis pour les visiteurs)** — variables d'environnement :

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

Page : aucun script/style en ligne, CSP stricte (`default-src 'none'`), DOM construit via `textContent` (les données viennent de tiers).

### Déploiement (Docker / Render)

```bash
docker build -t bt-url .            # le build télécharge le modèle et échoue si le SHA256 diffère
docker run -p 8000:8000 --env-file .env bt-url
```

Sur Render : « New + → Blueprint » sur ce dépôt (`render.yaml`), puis saisir les clés API dans le tableau de bord
(`sync: false` : jamais dans git). Prévoir ≥ 1 Go de RAM. Les clés ne sont jamais dans l'image.

## Sécurité

- **SSRF** : un hôte non public (loopback, privé, link-local, métadonnées cloud) n'est jamais
  contacté ; chaque redirection est revalidée et le résolveur refuse ces adresses à la connexion.
  Les hôtes non publics sont analysés lexicalement + TI uniquement.
- **Modèle ML** : `joblib` exécute du pickle. Le SHA256 du modèle est **vérifié avant tout chargement**
  (hash officiel épinglé), téléchargement HTTPS dans un fichier temporaire, refus en cas d'écart.
  Un modèle custom exige `BT_URL_MODEL_PATH` + `BT_URL_MODEL_SHA256`.
- Le modèle (183 Mo) n'est pas dans le dépôt : téléchargé au premier usage dans `~/.cache/bt-url/`.
  Il a été entraîné avec **scikit-learn 1.8** (version épinglée).

## Tests

```bash
python -m pytest                                  # 139 tests, hors réseau
BT_URL_MODEL_PATH=/chemin/best_model_pipeline.pkl python -m pytest -m network   # vrai modèle
```

## Biais du modèle constaté (et contournement)

Mesuré sur des sites légitimes : le préfixe `www.` fait gonfler le score (wikipedia.org 0,00 → **0,89** avec `www.`,
google.com 0,00 → 0,85), car `count_dots` / `num_subdomains` pèsent lourd. bt-url retire donc un `www.` initial
**avant l'extraction des features** (`lexical.strip_www`) et l'indique dans la page. C'est un correctif de
contournement : le vrai remède est de réentraîner le modèle sur des URLs normalisées.
Le modèle reste faible sur les hôtes en adresse IP (URL listée par URLhaus et VirusTotal : score 0,03) — d'où la
priorité donnée à la Threat Intelligence.

## Limites connues

- Le ML dépend de DNS/TLS/RDAP/GeoIP en direct : un hôte mort donne des features à 0.
- Modèle entraîné sur des données de mars 2026, sans suivi de dérive.
- Le typosquatting compare le domaine enregistrable à une courte liste de marques.
- Dernier saut du DNS-rebinding sur les sondes TLS/ML du modèle (sockets directs) non couvert ;
  les requêtes HTTP (redirections) le sont.
