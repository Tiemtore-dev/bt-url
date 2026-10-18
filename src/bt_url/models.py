"""Types partagés."""

from dataclasses import dataclass, field
from typing import Optional

# Ordre de gravité des verdicts de source (plus grand = plus grave).
VERDICT_SEVERITY = {
    "NOT_SUPPORTED": -2,
    "ERROR": -1,
    "UNKNOWN": 0,
    "CLEAN": 1,
    "SUSPICIOUS": 2,
    "MALICIOUS": 3,
}


@dataclass
class SourceResult:
    """Résultat standardisé d'une source de Threat Intelligence."""

    source_name: str
    verdict: str = "UNKNOWN"  # CLEAN | SUSPICIOUS | MALICIOUS | UNKNOWN | ERROR | NOT_SUPPORTED
    detections: Optional[str] = None
    score: Optional[float] = None
    raw: dict = field(default_factory=dict)
    response_time_ms: int = 0
    error: Optional[str] = None
    # Une source « faisant autorité » (liste vérifiée, consensus multi-moteurs)
    # impose son verdict MALICIOUS : il l'emporte sur tout le reste.
    authoritative: bool = False

    @property
    def usable(self) -> bool:
        """Vrai si la source a réellement répondu (ni erreur, ni non supportée)."""
        return self.verdict not in ("ERROR", "NOT_SUPPORTED")


@dataclass
class MLResult:
    """Résultat d'une prédiction ML."""

    score: float
    label: str  # BENIGN | SUSPICIOUS | MALICIOUS
    confidence: float
    threshold: float
    features: dict = field(default_factory=dict)
