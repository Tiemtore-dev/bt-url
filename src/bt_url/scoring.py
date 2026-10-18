"""
Agrégation du risque — règles de décision (par ordre de priorité) :

1. TI AUTORITAIRE : si une source faisant autorité (URLhaus, PhishTank vérifié, Google Safe
   Browsing, ThreatFox, VirusTotal avec consensus) dit MALICIOUS, le verdict est
   CONFIRMED_MALICIOUS. Rien (ML « bénin », autres sources CLEAN) ne peut l'abaisser.
2. TI non autoritaire MALICIOUS (ex. OTX) → au minimum HIGH_RISK ; tout verdict SUSPICIOUS
   d'une source → au minimum SUSPICIOUS.
3. Sans TI positive, le ML et les heuristiques (noisy-OR) donnent le score, plafonné à
   0,89 : le ML seul ne peut PAS « confirmer » une URL malveillante.
4. L'absence de détection n'est pas une preuve : un CLEAN ne diminue jamais le score
   (les URLs de phishing récentes sont souvent inconnues des bases).
5. Sans aucune donnée exploitable → UNKNOWN, jamais CLEAN par défaut.
"""

from typing import Optional

from bt_url.models import MLResult, SourceResult

LEVEL_MALICIOUS = 0.90
LEVEL_HIGH_RISK = 0.60
LEVEL_SUSPICIOUS = 0.35

ML_WEIGHT = 0.85
NON_TI_CAP = 0.89
NON_AUTH_MALICIOUS_FLOOR = 0.65
SUSPICIOUS_FLOOR = 0.40


def structural_score(url_features: dict, typosquatting: list, embedded_urls: int = 0) -> tuple[float, list[str]]:
    """Heuristiques lexicales, plafonnées à 0,5. Retourne (score, raisons)."""
    pts, reasons = 0.0, []
    if typosquatting:
        pts += 0.25
        reasons.append(f"Typosquatting proche de {typosquatting[0]['legitimate_domain']}")
    if url_features.get("has_ip_in_url"):
        pts += 0.15
        reasons.append("Hôte = adresse IP")
    if url_features.get("has_userinfo"):
        pts += 0.15
        reasons.append("Présence de '@' dans l'URL (masquage de l'hôte)")
    if url_features.get("is_punycode"):
        pts += 0.10
        reasons.append("Domaine punycode (homoglyphes possibles)")
    if len(url_features.get("suspicious_keywords", [])) >= 3:
        pts += 0.10
        reasons.append("Plusieurs mots-clés de phishing dans l'URL")
    if embedded_urls:
        pts += 0.10
        reasons.append("URL encodée en base64 dans l'URL")
    if url_features.get("uses_https") is False:
        pts += 0.05
        reasons.append("HTTP non chiffré")
    return min(pts, 0.5), reasons


def _classify(score: float) -> tuple[str, str]:
    if score >= LEVEL_MALICIOUS:
        return "MALICIOUS", "CONFIRMED_MALICIOUS"
    if score >= LEVEL_HIGH_RISK:
        return "HIGH_RISK", "HIGH_RISK"
    if score >= LEVEL_SUSPICIOUS:
        return "SUSPICIOUS", "SUSPICIOUS"
    return "CLEAN", "CLEAN"


def assess_risk(
    sources: list[SourceResult],
    ml: Optional[MLResult] = None,
    heuristic: float = 0.0,
    heuristic_reasons: Optional[list[str]] = None,
) -> dict:
    reasons: list[str] = []
    usable = [s for s in sources if s.usable]
    auth_hits = [s for s in usable if s.authoritative and s.verdict == "MALICIOUS"]
    other_malicious = [s for s in usable if not s.authoritative and s.verdict == "MALICIOUS"]
    suspicious = [s for s in usable if s.verdict == "SUSPICIOUS"]

    # ── Règle 1 : TI autoritaire ────────────────────────────────────────
    if auth_hits:
        score = 1.0 if len(auth_hits) >= 2 else 0.95
        names = ", ".join(s.source_name for s in auth_hits)
        reasons.append(f"Détecté MALICIOUS par une source faisant autorité : {names}")
        if ml and ml.label == "BENIGN":
            reasons.append("Le modèle ML disait BENIGN — ignoré (la TI prime)")
        return {
            "score": score, "level": "MALICIOUS", "verdict": "CONFIRMED_MALICIOUS",
            "confidence": 0.99 if len(auth_hits) >= 2 else 0.95,
            "decisive_source": auth_hits[0].source_name, "reasons": reasons,
        }

    # ── Règles 2-4 : TI non autoritaire + ML + heuristiques ─────────────
    floor = 0.0
    if other_malicious:
        floor = NON_AUTH_MALICIOUS_FLOOR
        reasons.append("Signalé MALICIOUS (source non autoritaire) : "
                       + ", ".join(s.source_name for s in other_malicious))
    if suspicious:
        floor = max(floor, SUSPICIOUS_FLOOR)
        reasons.append("Signalé SUSPICIOUS : " + ", ".join(s.source_name for s in suspicious))

    ml_component = ML_WEIGHT * ml.score if ml else 0.0
    if ml and ml.label != "BENIGN":
        reasons.append(f"Modèle ML : {ml.label} (score {ml.score:.2f}, seuil {ml.threshold:.2f})")
    if heuristic > 0:
        reasons.extend(heuristic_reasons or [])

    combined = 1 - (1 - ml_component) * (1 - heuristic)
    score = min(max(floor, combined), NON_TI_CAP)

    level, verdict = _classify(score)

    # ── Règle 5 : aucune donnée exploitable ─────────────────────────────
    # Heuristiques seules + niveau CLEAN = on ne sait pas, ce n'est pas « sain ».
    if not usable and ml is None and level == "CLEAN":
        return {
            "score": round(score, 4) if heuristic else None, "level": "UNKNOWN",
            "verdict": "UNKNOWN", "confidence": 0.0, "decisive_source": None,
            "reasons": ["Aucune source TI n'a répondu et le ML est indisponible"] + reasons,
        }

    if not reasons and level == "CLEAN":
        reasons.append("Aucun indicateur malveillant (absence de détection ≠ preuve d'innocuité)")

    coverage = min(len(usable) / 3, 1.0)
    confidence = 0.4 * coverage + 0.6 * (ml.confidence if ml else 0.0)
    return {
        "score": round(score, 4), "level": level, "verdict": verdict,
        "confidence": round(confidence, 4),
        "decisive_source": (other_malicious or suspicious or [None])[0].source_name
        if (other_malicious or suspicious) else None,
        "reasons": reasons,
    }
