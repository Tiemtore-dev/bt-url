"""Orchestrateur d'analyse d'URL."""

import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional

from bt_url import __version__, lexical, netguard
from bt_url.config import Settings, get_settings
from bt_url.models import VERDICT_SEVERITY, MLResult, SourceResult
from bt_url.scoring import assess_risk, structural_score
from bt_url.sources import get_enabled_sources
from bt_url.sources.base import BaseSource


def check_ssl(hostname: str, timeout: float = 5) -> dict:
    """Certificat TLS du serveur (vérification standard de la chaîne)."""
    info = {"valid": False, "issuer": "", "subject": "", "not_after": "", "days_remaining": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as sock:
                cert = sock.getpeercert()
                info["protocol"] = sock.version()
        info["valid"] = True
        info["issuer"] = next((v for rdn in cert.get("issuer", ()) for k, v in rdn
                               if k == "organizationName"), "")
        info["subject"] = next((v for rdn in cert.get("subject", ()) for k, v in rdn
                                if k == "commonName"), "")
        info["not_after"] = cert.get("notAfter", "")
        if info["not_after"]:
            expires = ssl.cert_time_to_seconds(info["not_after"])
            info["days_remaining"] = int((expires - time.time()) // 86400)
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"
    return info


def merge_source_results(batches: list[list[SourceResult]]) -> list[SourceResult]:
    """Une entrée par source : on garde le verdict le plus grave (original vs URL déroulée)."""
    best: dict[str, SourceResult] = {}
    for batch in batches:
        for r in batch:
            cur = best.get(r.source_name)
            if cur is None or VERDICT_SEVERITY.get(r.verdict, 0) > VERDICT_SEVERITY.get(cur.verdict, 0):
                best[r.source_name] = r
    return list(best.values())


class URLAnalyzer:
    def __init__(self, settings: Optional[Settings] = None,
                 sources: Optional[list[BaseSource]] = None, ml_loader=None):
        self.settings = settings or get_settings()
        self.sources = sources if sources is not None else get_enabled_sources(self.settings)
        self._ml = ml_loader
        self._ml_ready = ml_loader is not None

    def _get_ml(self):
        if not self._ml_ready:
            from bt_url.ml.model import build_engine

            self._ml = build_engine(self.settings)
            self._ml_ready = True
        return self._ml

    async def _query_sources(self, url: str) -> list[SourceResult]:
        outs = await asyncio.gather(*(s.check_url(url) for s in self.sources), return_exceptions=True)
        results = []
        for source, out in zip(self.sources, outs):
            if isinstance(out, Exception):
                results.append(SourceResult(source.name, verdict="ERROR", error=str(out)))
            elif out.verdict != "NOT_SUPPORTED":
                results.append(out)
        return results

    def _predict_ml(self, url: str) -> Optional[MLResult]:
        loader = self._get_ml()
        if loader is None:
            return None
        from bt_url.ml.features import collect_all_features

        features = collect_all_features(url)
        return loader.predict(features) if features else None

    async def analyze(self, url: str, use_ml: bool = True, follow_redirects: bool = True) -> dict:
        started = time.time()
        original = lexical.normalize_url(url)
        if not lexical.is_valid_url(original):
            raise ValueError(f"URL invalide (http/https attendu) : {url!r}")

        hostname = lexical.get_hostname(original)
        public = await netguard.host_is_public(hostname)
        result: dict = {
            "meta": {"tool": "bt-url", "version": __version__,
                     "scan_date": datetime.now(timezone.utc).isoformat()},
            "target": {"url": original, "hostname": hostname, "public": public},
        }
        notes: list[str] = []
        analyzed = original
        if not public:
            notes.append("Hôte non public ou non résolvable : aucune connexion sortante "
                         "(ML, TLS, redirections désactivés)")

        # Raccourcisseur : on interroge la TI sur l'URL d'origine ET l'URL finale
        urls_to_check = [original]
        if public and lexical.is_shortened_url(original):
            resolved = await netguard.follow_redirects(original)
            final = resolved["final_url"]
            result["url_shortener"] = {"chain": resolved["chain"], "final_url": final,
                                       "blocked": resolved["blocked"]}
            if final != original:
                urls_to_check.append(final)
                analyzed = final

        analyzed_host = lexical.get_hostname(analyzed)
        features = lexical.extract_url_features(analyzed)
        typo = lexical.check_typosquatting(analyzed_host)
        b64 = lexical.extract_base64_payloads(analyzed)
        embedded_urls = sum(1 for p in b64 if p["decoded"].lower().startswith(("http://", "https://")))
        result["url_features"] = features
        result["typosquatting"] = {"detected": bool(typo), "matches": typo[:5]}
        result["embedded_base64"] = b64

        # TI en parallèle (+ ML dans un thread : il fait des I/O bloquantes)
        ml_task = None
        if use_ml and self.settings.ml_enabled and public and await netguard.host_is_public(analyzed_host):
            ml_task = asyncio.get_running_loop().run_in_executor(None, self._predict_ml, analyzed)
        ssl_task = (asyncio.get_running_loop().run_in_executor(None, check_ssl, analyzed_host)
                    if public and analyzed.startswith("https://") else None)
        redirect_task = (netguard.follow_redirects(analyzed)
                         if follow_redirects and public else None)

        batches = await asyncio.gather(*(self._query_sources(u) for u in urls_to_check))
        sources = merge_source_results(list(batches))
        result["sources"] = [
            {"name": s.source_name, "verdict": s.verdict, "authoritative": s.authoritative,
             "detections": s.detections, "response_time_ms": s.response_time_ms, "error": s.error}
            for s in sources
        ]

        ml: Optional[MLResult] = None
        if ml_task is not None:
            try:
                ml = await ml_task
            except Exception as e:
                notes.append(f"ML en échec : {type(e).__name__}: {e}")
        result["ml"] = ({"enabled": True, "score": ml.score, "label": ml.label,
                         "confidence": ml.confidence, "threshold": ml.threshold}
                        if ml else {"enabled": bool(ml_task is not None), "available": False})
        if ssl_task is not None:
            result["ssl"] = await ssl_task
        if redirect_task is not None:
            result["redirects"] = await redirect_task

        heuristic, heuristic_reasons = structural_score(features, typo, embedded_urls)
        result["risk"] = assess_risk(sources, ml, heuristic, heuristic_reasons)
        if notes:
            result["notes"] = notes
        result["meta"]["scan_duration_ms"] = int((time.time() - started) * 1000)
        return result
