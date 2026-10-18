"""Chargement sécurisé du modèle et prédiction."""

import hashlib
import json
import logging
import os
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

from bt_url.config import Settings
from bt_url.models import MLResult

log = logging.getLogger("bt_url.ml")

class ModelIntegrityError(RuntimeError):
    """Le SHA256 du modèle ne correspond pas : il ne doit JAMAIS être chargé."""


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_model(path: str, expected_sha256: str, allow_unverified: bool = False) -> None:
    """
    joblib.load() exécute du pickle : le fichier est vérifié AVANT tout chargement.
    Sans hash attendu, le chargement est refusé sauf opt-in explicite.
    """
    if not expected_sha256:
        if allow_unverified:
            log.warning("Modèle chargé SANS vérification d'intégrité (opt-in explicite)")
            return
        raise ModelIntegrityError(
            "Aucun SHA256 attendu : définir BT_URL_MODEL_SHA256 "
            "(ou BT_URL_ALLOW_UNVERIFIED_MODEL=true, déconseillé)")
    actual = sha256_file(path)
    if actual.lower() != expected_sha256.lower():
        raise ModelIntegrityError(f"SHA256 inattendu : {actual} (attendu {expected_sha256})")


def download_model(url: str, dest: str, expected_sha256: str, allow_unverified: bool = False) -> None:
    """Télécharge dans un fichier temporaire, vérifie, puis déplace atomiquement."""
    if not url.startswith("https://"):
        raise ModelIntegrityError("Le modèle doit être téléchargé en HTTPS")
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest_path.parent, suffix=".part")
    os.close(fd)
    try:
        log.info("Téléchargement du modèle ML depuis %s", url)
        urllib.request.urlretrieve(url, tmp)  # noqa: S310 (https imposé ci-dessus)
        verify_model(tmp, expected_sha256, allow_unverified)
        os.replace(tmp, dest_path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class ModelLoader:
    def __init__(self, model_path: str, meta_path: str):
        self._model_path = model_path
        self._meta = json.loads(Path(meta_path).read_text(encoding="utf-8"))
        self._pipeline = None

    @property
    def meta(self) -> dict:
        return self._meta

    @property
    def threshold(self) -> float:
        return float(self._meta.get("threshold", 0.5))

    def load(self, expected_sha256: str, allow_unverified: bool = False) -> None:
        verify_model(self._model_path, expected_sha256, allow_unverified)
        import joblib  # import tardif : lourd

        self._pipeline = joblib.load(self._model_path)

    def predict(self, raw_features: dict) -> MLResult:
        import pandas as pd

        if self._pipeline is None:
            raise RuntimeError("Modèle non chargé")
        cat = set(self._meta.get("cat_features", []))
        row = {}
        for name in self._meta["feature_names"]:
            val = raw_features.get(name, 0)
            if name in cat:
                val = str(val).strip().lower() if val else "inconnu"
                if val in ("nan", "none", "null", "", "0", "-"):
                    val = "inconnu"
            row[name] = val
        proba = float(self._pipeline.predict_proba(
            pd.DataFrame([row], columns=self._meta["feature_names"]))[0][1])
        thr = self.threshold
        malicious = proba >= thr
        label = "MALICIOUS" if malicious else ("SUSPICIOUS" if proba >= thr * 0.7 else "BENIGN")
        return MLResult(score=round(proba, 4), label=label,
                        confidence=round(proba if malicious else 1 - proba, 4),
                        threshold=round(thr, 4), features=raw_features)


def build_engine(settings: Settings) -> Optional[ModelLoader]:
    """
    Prépare le modèle s'il est activé ET configuré (chemin + métadonnées). None sinon.
    Aucun modèle n'est livré avec le projet ni téléchargé par défaut.
    """
    if not settings.ml_enabled:
        return None
    if not settings.model_path:
        log.warning("BT_URL_ML_ENABLED=true mais BT_URL_MODEL_PATH est vide : ML désactivé")
        return None
    try:
        if not Path(settings.model_path).exists():
            if not settings.model_url:
                raise FileNotFoundError(settings.model_path)
            download_model(settings.model_url, settings.model_path,
                           settings.model_sha256, settings.allow_unverified_model)
        meta = settings.model_meta_path or str(Path(settings.model_path).with_suffix(".meta.json"))
        loader = ModelLoader(settings.model_path, meta)
        loader.load(settings.model_sha256, settings.allow_unverified_model)
        return loader
    except ModelIntegrityError as e:
        log.error("Modèle ML REFUSÉ : %s", e)
    except Exception as e:  # fichier absent/corrompu, incompatibilité de version…
        log.warning("Modèle ML indisponible : %s", e)
    return None
