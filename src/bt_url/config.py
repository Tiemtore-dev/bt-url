"""Configuration : variables d'environnement (+ fichiers .env), jamais de secret en dur."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

for _candidate in (Path.cwd() / ".env", Path.home() / ".bt-url.env"):
    if _candidate.exists():
        load_dotenv(_candidate, override=False)

# Modèle officiel v1.0.0 (SHA256 publié par la release GitHub).
DEFAULT_MODEL_URL = (
    "https://github.com/Tiemtore-dev/bt-knife/releases/download/v1.0.0/best_model_pipeline.pkl"
)
DEFAULT_MODEL_SHA256 = "1e902bbe7474fb61414a2c64fb492cb9674c4b911cc9936162b436fab31ed9f9"


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
    abusech_key: str = field(default_factory=lambda: _env("ABUSECH_API_KEY"))
    phishtank_key: str = field(default_factory=lambda: _env("PHISHTANK_API_KEY"))

    vt_min_engines: int = field(default_factory=lambda: _int("VT_MIN_ENGINES", 3))

    ml_enabled: bool = field(default_factory=lambda: _bool("BT_URL_ML_ENABLED", True))
    model_path: str = field(default_factory=lambda: _env(
        "BT_URL_MODEL_PATH", str(Path.home() / ".cache" / "bt-url" / "best_model_pipeline.pkl")))
    model_url: str = field(default_factory=lambda: _env("BT_URL_MODEL_URL", DEFAULT_MODEL_URL))
    model_sha256: str = field(default_factory=lambda: _env("BT_URL_MODEL_SHA256", DEFAULT_MODEL_SHA256))
    allow_unverified_model: bool = field(
        default_factory=lambda: _bool("BT_URL_ALLOW_UNVERIFIED_MODEL", False))

    source_timeout: int = field(default_factory=lambda: _int("BT_URL_TIMEOUT", 10))


def get_settings() -> Settings:
    return Settings()
