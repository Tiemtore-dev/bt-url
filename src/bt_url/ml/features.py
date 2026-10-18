"""
Extraction des 25 features du classificateur LightGBM d'URLs malveillantes
(DNS, TLS, RDAP/WHOIS, réseau/GeoIP, lexical).
"""

import math
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import logging

log = logging.getLogger("bt_url.ml")

# ── Constantes ───────────────────────────────────────────────────────────────
DNS_TIMEOUT = 5
TLS_TIMEOUT = 5
IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ══════════════════════════════════════════════════════════════════════════════
# Features DNS
# ══════════════════════════════════════════════════════════════════════════════

def collect_dns_features(hostname: str) -> dict:
    """
    Collecte les features DNS : ttl_A, ttl_MX, nb_A_records, nb_ips,
    has_AAAA, has_MX, dns_had_no_ips, nb_nameservers.
    """
    features = {
        "ttl_A": 0, "ttl_MX": 0,
        "nb_A_records": 0, "nb_ips": 0,
        "has_AAAA": 0, "has_MX": 0,
        "dns_had_no_ips": 1,
        "nb_nameservers": 0,
    }

    if not hostname:
        return features

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        resolver.timeout = DNS_TIMEOUT
    except ImportError:
        log.debug("dnspython non installé — fallback résolution basique")
        try:
            ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
            features["nb_A_records"] = len(set(r[4][0] for r in ips))
            features["nb_ips"] = features["nb_A_records"]
            features["dns_had_no_ips"] = 0 if features["nb_ips"] > 0 else 1
        except Exception:
            pass
        return features

    # A records
    try:
        ans_a = resolver.resolve(hostname, "A")
        a_ips = [r.address for r in ans_a]
        features["nb_A_records"] = len(a_ips)
        features["nb_ips"] = len(set(a_ips))
        features["ttl_A"] = int(ans_a.rrset.ttl) if ans_a.rrset else 0
        features["dns_had_no_ips"] = 0
    except Exception:
        pass

    # AAAA records
    try:
        ans_aaaa = resolver.resolve(hostname, "AAAA")
        if ans_aaaa:
            features["has_AAAA"] = 1
            features["dns_had_no_ips"] = 0
            features["nb_ips"] += len(set(r.address for r in ans_aaaa))
    except Exception:
        pass

    # MX records
    try:
        ans_mx = resolver.resolve(hostname, "MX")
        if ans_mx:
            features["has_MX"] = 1
            features["ttl_MX"] = int(ans_mx.rrset.ttl) if ans_mx.rrset else 0
    except Exception:
        pass

    # NS records
    try:
        ans_ns = resolver.resolve(hostname, "NS")
        features["nb_nameservers"] = len(list(ans_ns))
    except Exception:
        pass

    return features


# ══════════════════════════════════════════════════════════════════════════════
# Features TLS
# ══════════════════════════════════════════════════════════════════════════════

def collect_tls_features(hostname: str) -> dict:
    """Collecte tls_cert_count, cert_valid_len_days, is_alive."""
    features = {
        "tls_cert_count": 0,
        "cert_valid_len_days": 0,
        "is_alive": 0,
    }

    if not hostname:
        return features

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
            sock.settimeout(TLS_TIMEOUT)
            sock.connect((hostname, 443))
            cert = sock.getpeercert()

            if cert:
                features["tls_cert_count"] = 1
                features["is_alive"] = 1

                not_before_str = cert.get("notBefore", "")
                not_after_str = cert.get("notAfter", "")
                if not_before_str and not_after_str:
                    try:
                        fmt = "%b %d %H:%M:%S %Y %Z"
                        not_before = datetime.strptime(not_before_str, fmt)
                        not_after = datetime.strptime(not_after_str, fmt)
                        features["cert_valid_len_days"] = max(0, (not_after - not_before).days)
                    except ValueError:
                        pass
    except Exception:
        try:
            import requests as req
            resp = req.head(f"http://{hostname}", timeout=TLS_TIMEOUT, allow_redirects=True)
            features["is_alive"] = 1 if resp.status_code < 500 else 0
        except Exception:
            pass

    return features


# ══════════════════════════════════════════════════════════════════════════════
# Features WHOIS / RDAP
# ══════════════════════════════════════════════════════════════════════════════

def collect_whois_features(hostname: str) -> dict:
    """Collecte domain_age_days, domain_remaining_days, nb_rdap_status, nb_nameservers via RDAP/WHOIS."""
    features = {
        "domain_age_days": 0,
        "domain_remaining_days": 0,
        "nb_rdap_status": 0,
        "nb_nameservers": 0,
    }

    if not hostname or IP_PATTERN.match(hostname):
        return features

    parts = hostname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    now = datetime.now()
    rdap_success = False

    # Méthode 1 : RDAP API (HTTPS 443)
    try:
        import requests as req
        from dateutil import parser as dateutil_parser

        resp = req.get(
            f"https://rdap.org/domain/{domain}",
            timeout=8, allow_redirects=True,
            headers={"Accept": "application/rdap+json, application/json"},
        )

        if resp.status_code == 200:
            data = resp.json()
            for event in data.get("events", []):
                action = event.get("eventAction", "").lower()
                date_str = event.get("eventDate", "")
                if not date_str:
                    continue
                try:
                    d = dateutil_parser.parse(date_str).replace(tzinfo=None)
                    if action == "registration":
                        features["domain_age_days"] = max(0, (now - d).days)
                    elif action == "expiration":
                        features["domain_remaining_days"] = max(0, (d - now).days)
                except Exception:
                    pass

            statuses = data.get("status", [])
            if statuses:
                features["nb_rdap_status"] = len(statuses)

            ns_entries = data.get("nameservers", [])
            if ns_entries:
                features["nb_nameservers"] = len(ns_entries)

            rdap_success = True
    except Exception as e:
        log.debug("RDAP échoué pour %s : %s", domain, e)

    # Méthode 2 : Fallback commande système whois
    if not rdap_success:
        try:
            import subprocess
            result = subprocess.run(
                ["whois", domain], capture_output=True, text=True, timeout=5
            )
            output = result.stdout

            def _extract_date(pattern, text):
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    try:
                        from dateutil import parser as dateutil_parser
                        d = dateutil_parser.parse(match.group(1).strip())
                        return d.replace(tzinfo=None)
                    except Exception:
                        pass
                return None

            creation = _extract_date(
                r"(?:Creation Date|Created|Registration Time):\s*(.+)", output
            )
            if creation:
                features["domain_age_days"] = max(0, (now - creation).days)

            expiration = _extract_date(
                r"(?:Registry Expiry Date|Expiration Date|Expiry|Expiration Time):\s*(.+)", output
            )
            if expiration:
                features["domain_remaining_days"] = max(0, (expiration - now).days)

            statuses = re.findall(r"Domain Status:\s*(.+)", output, re.IGNORECASE)
            if statuses:
                features["nb_rdap_status"] = len(set(s.split()[0] for s in statuses))
        except Exception as e:
            log.debug("WHOIS système échoué pour %s : %s", domain, e)

    return features


# ══════════════════════════════════════════════════════════════════════════════
# Features réseau / GeoIP
# ══════════════════════════════════════════════════════════════════════════════

def collect_network_features(hostname: str) -> dict:
    """Collecte average_rtt, primary_prefix_len, primary_country_code."""
    features = {
        "average_rtt": 0.0,
        "primary_prefix_len": 24,
        "primary_country_code": "inconnu",
    }

    if not hostname:
        return features

    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return features

    # RTT via TCP connect
    try:
        rtt_samples = []
        for _ in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            start = time.time()
            try:
                sock.connect((ip, 80))
                rtt_ms = (time.time() - start) * 1000
                rtt_samples.append(rtt_ms)
            except Exception:
                pass
            finally:
                sock.close()
        if rtt_samples:
            features["average_rtt"] = round(sum(rtt_samples) / len(rtt_samples), 2)
    except Exception:
        pass

    # GeoIP country code
    try:
        import requests as req
        resp = req.get(f"https://freeipapi.com/api/json/{ip}", timeout=3)
        if resp.status_code == 200:
            cc = resp.json().get("countryCode", "")
            if cc:
                features["primary_country_code"] = cc.lower()
    except Exception:
        pass

    return features


# ══════════════════════════════════════════════════════════════════════════════
# Features URL lexicales
# ══════════════════════════════════════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    """Entropie de Shannon en bits."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def collect_url_features(url: str, hostname: str) -> dict:
    """Collecte les features lexicales de l'URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hn = parsed.hostname or hostname or ""

    parts = hn.split(".")
    tld = parts[-1] if len(parts) >= 2 else "inconnu"

    if IP_PATTERN.match(hn):
        num_subdomains = 0
    else:
        num_subdomains = max(0, len(parts) - 2)

    return {
        "url_length": len(url),
        "domain_length": len(hn),
        "count_unique_chars": len(set(url.lower())),
        "url_entropy": round(_shannon_entropy(url), 6),
        "count_dots": url.count("."),
        "count_slashes": url.count("/"),
        "num_subdomains": num_subdomains,
        "tld": tld.lower(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Collecteur principal — toutes les features en parallèle
# ══════════════════════════════════════════════════════════════════════════════

def _normalize_url(url: str) -> str:
    """Supprime le préfixe http:// ou https:// pour l'extraction de features."""
    if not isinstance(url, str) or not url.strip():
        return ""
    return re.sub(r"^https?://", "", url.strip(), flags=re.IGNORECASE)


def collect_all_features(url: str) -> dict:
    """
    Collecte les 25 features nécessaires au modèle, en parallèle.
    Le préfixe http/https est retiré pour correspondre à l'entraînement.
    """
    url_normalized = _normalize_url(url)
    parsed = urlparse("http://" + url_normalized if "://" not in url_normalized else url_normalized)
    hostname = parsed.hostname or ""

    log.info("Collecte des features pour %s", hostname)

    results = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(collect_dns_features, hostname): "dns",
            executor.submit(collect_tls_features, hostname): "tls",
            executor.submit(collect_whois_features, hostname): "whois",
            executor.submit(collect_network_features, hostname): "network",
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
                log.debug("%s features collectées", name.upper())
            except Exception as e:
                results[name] = {}
                log.warning("%s : %s", name.upper(), e)

    # Features URL lexicales (instantané)
    url_feats = collect_url_features(url_normalized, hostname)

    # Fusion
    all_features = {}
    all_features.update(results.get("dns", {}))
    all_features.update(results.get("tls", {}))

    whois_data = results.get("whois", {})
    rdap_ns = whois_data.pop("nb_nameservers", 0)
    all_features.update(whois_data)
    if all_features.get("nb_nameservers", 0) == 0 and rdap_ns > 0:
        all_features["nb_nameservers"] = rdap_ns

    all_features.update(results.get("network", {}))
    all_features.update(url_feats)

    return all_features
