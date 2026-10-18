"""Registre des sources TI : seules celles utilisables (clé présente) sont activées."""

from bt_url.config import Settings
from bt_url.sources.base import BaseSource
from bt_url.sources.safebrowsing import GoogleSafeBrowsingSource
from bt_url.sources.otx import OTXSource
from bt_url.sources.phishtank import PhishTankSource
from bt_url.sources.threatfox import ThreatFoxSource
from bt_url.sources.urlhaus import URLhausSource
from bt_url.sources.virustotal import VirusTotalSource


def get_enabled_sources(s: Settings) -> list[BaseSource]:
    t = s.source_timeout
    sources: list[BaseSource] = []
    if s.phishtank_key:  # PhishTank renvoie 403 sans app_key
        sources.append(PhishTankSource(s.phishtank_key, t))
    if s.virustotal_key:
        sources.append(VirusTotalSource(s.virustotal_key, s.vt_min_engines, t))
    if s.gsb_key:
        sources.append(GoogleSafeBrowsingSource(s.gsb_key, t))
    if s.otx_key:
        sources.append(OTXSource(s.otx_key, t))
    if s.abusech_key:
        sources.append(URLhausSource(s.abusech_key, t))
        sources.append(ThreatFoxSource(s.abusech_key, t))
    return sources
