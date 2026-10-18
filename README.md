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
python -m pytest                                  # 90 tests, hors réseau
BT_URL_MODEL_PATH=/chemin/best_model_pipeline.pkl python -m pytest -m network   # vrai modèle
```

## Limites connues

- Le ML dépend de DNS/TLS/RDAP/GeoIP en direct : un hôte mort donne des features à 0.
- Modèle entraîné sur des données de mars 2026, sans suivi de dérive.
- Le typosquatting compare le domaine enregistrable à une courte liste de marques.
- Dernier saut du DNS-rebinding sur les sondes TLS/ML du modèle (sockets directs) non couvert ;
  les requêtes HTTP (redirections) le sont.
