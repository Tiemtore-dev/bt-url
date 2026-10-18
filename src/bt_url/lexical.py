"""Utilitaires purement lexicaux sur les URLs (aucun accès réseau)."""

import math
import re
from collections import Counter
from urllib.parse import urlparse

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "bl.ink", "lnkd.in", "amzn.to", "rb.gy",
}

LEGITIMATE_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "paypal.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "yahoo.com", "dropbox.com", "github.com", "stackoverflow.com", "reddit.com",
    "whatsapp.com", "telegram.org", "zoom.us", "slack.com", "discord.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "outlook.com", "hotmail.com", "gmail.com", "icloud.com",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "confirm",
    "password", "signin", "banking", "wallet", "suspend", "alert",
    "urgent", "restore", "unlock", "authenticate", "validate",
    "paypal", "ebay", "amazon", "apple", "microsoft",
]

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def normalize_url(url: str) -> str:
    """Ajoute le schéma https si absent et retire le fragment."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"https://{url}"
    return url.split("#", 1)[0]


def is_valid_url(url: str) -> bool:
    """Seules les URLs http(s) avec un hôte sont acceptées."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except ValueError:
        return False


def get_hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_shortened_url(url: str) -> bool:
    return get_hostname(url) in URL_SHORTENERS


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in Counter(data).values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _registered_domain(hostname: str) -> str:
    """Approximation du domaine enregistrable (2 derniers labels)."""
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def check_typosquatting(hostname: str, threshold: int = 2) -> list[dict]:
    """
    Domaines légitimes proches (distance de Levenshtein <= threshold) du domaine
    enregistrable. Un domaine légitime lui-même (distance 0) n'est jamais signalé.
    """
    domain = _registered_domain(hostname.lower().strip())
    if not domain or domain in LEGITIMATE_DOMAINS:
        return []
    matches = []
    for legit in LEGITIMATE_DOMAINS:
        dist = levenshtein(domain, legit)
        if 0 < dist <= threshold:
            matches.append({"legitimate_domain": legit, "distance": dist})
    return sorted(matches, key=lambda m: m["distance"])


def extract_url_features(url: str) -> dict:
    """Caractéristiques structurelles d'une URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    lowered = url.lower()
    return {
        "has_ip_in_url": bool(_IPV4.match(hostname)),
        "url_length": len(url),
        "path_depth": len([p for p in parsed.path.split("/") if p]),
        "param_count": len(parsed.query.split("&")) if parsed.query else 0,
        "entropy": round(shannon_entropy(url), 4),
        "uses_https": parsed.scheme == "https",
        "has_userinfo": "@" in parsed.netloc,
        "is_punycode": "xn--" in hostname,
        "suspicious_keywords": [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered],
    }


def extract_base64_payloads(text: str) -> list[dict]:
    """Détecte les chaînes base64 décodables en texte imprimable (ex: URL cachée)."""
    import base64
    import binascii

    found = []
    for candidate in set(re.findall(r"[A-Za-z0-9+/_-]{20,}={0,2}", text)):
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
            decoded_text = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded_text.isprintable() and len(decoded_text) >= 8:
            found.append({"encoded": candidate[:80], "decoded": decoded_text[:200]})
    return found
