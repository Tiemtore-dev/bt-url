"""Configuration : variables d'environnement (+ fichiers .env), jamais de secret en dur."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

for _candidate in (Path.cwd() / ".env", Path.home() / ".bt-url.env"):
    if _candidate.exists():
        load_dotenv(_candidate, override=False)

def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    return default if val is None else val.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


@dataclass
class Settings:
    virustotal_key: str = field(default_factory=lambda: _env("VIRUSTOTAL_API_KEY"))
    gsb_key: str = field(default_factory=lambda: _env("GOOGLE_SAFEBROWSING_API_KEY"))
    otx_key: str = field(default_factory=lambda: _env("OTX_API_KEY"))
    abusech_key: str = field(default_factory=lambda: (
        _env("ABUSECH_API_KEY") or _env("URLHAUS_API_KEY") or _env("THREATFOX_API_KEY")))
    phishtank_key: str = field(default_factory=lambda: _env("PHISHTANK_API_KEY"))

    vt_min_engines: int = field(default_factory=lambda: _int("VT_MIN_ENGINES", 3))

    # Collecte des données de la cible (DNS, TLS, RDAP, GeoIP…) affichées dans la page, indépendante du modèle.
    collect_details: bool = field(default_factory=lambda: _bool("BT_URL_COLLECT", True))

    # Le modèle ML est en cours d'entraînement : désactivé par défaut, aucun modèle n'est livré.
    # Pour tester un modèle local : BT_URL_ML_ENABLED=true + chemin + SHA256 (obligatoire).
    ml_enabled: bool = field(default_factory=lambda: _bool("BT_URL_ML_ENABLED", False))
    model_path: str = field(default_factory=lambda: _env("BT_URL_MODEL_PATH"))
    model_meta_path: str = field(default_factory=lambda: _env("BT_URL_MODEL_META"))
    model_url: str = field(default_factory=lambda: _env("BT_URL_MODEL_URL"))
    model_sha256: str = field(default_factory=lambda: _env("BT_URL_MODEL_SHA256"))
    allow_unverified_model: bool = field(
        default_factory=lambda: _bool("BT_URL_ALLOW_UNVERIFIED_MODEL", False))

    source_timeout: int = field(default_factory=lambda: _int("BT_URL_TIMEOUT", 10))


def get_settings() -> Settings:
    return Settings()
