"""
Protection SSRF : l'analyse d'une URL ne doit jamais atteindre le réseau interne.

- `host_is_public` refuse tout hôte dont une adresse résolue n'est pas globale
  (loopback, privée, link-local, métadonnées cloud 169.254.169.254, etc.).
- `PublicOnlyResolver` rejoue cette vérification au moment de la connexion
  (protection contre le DNS rebinding pour les requêtes aiohttp).
- `follow_redirects` suit une chaîne de redirections en revalidant chaque saut.
"""

import asyncio
import ipaddress
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp.abc import AbstractResolver

MAX_REDIRECTS = 8
REDIRECT_CODES = (301, 302, 303, 307, 308)


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_global
    except ValueError:
        return False


def _resolve_sync(hostname: str) -> list[str]:
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def host_is_public_sync(hostname: str) -> bool:
    """Vrai si l'hôte se résout et que TOUTES ses adresses sont publiques."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return is_public_ip(hostname.strip("[]"))
    except ValueError:
        pass
    try:
        addrs = _resolve_sync(hostname)
    except OSError:
        return False
    return bool(addrs) and all(is_public_ip(a) for a in addrs)


async def host_is_public(hostname: str) -> bool:
    return await asyncio.get_running_loop().run_in_executor(None, host_is_public_sync, hostname)


class PublicOnlyResolver(AbstractResolver):
    """Résolveur aiohttp qui refuse les adresses non publiques à la connexion."""

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
        out = []
        for fam, _, proto, _, sockaddr in infos:
            ip = sockaddr[0]
            if not is_public_ip(ip):
                raise OSError(f"Adresse non publique refusée : {host} -> {ip}")
            out.append({"hostname": host, "host": ip, "port": port,
                        "family": fam, "proto": proto, "flags": socket.AI_NUMERICHOST})
        return out

    async def close(self) -> None:
        return None


def safe_session(timeout: float = 5) -> aiohttp.ClientSession:
    return aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout),
        connector=aiohttp.TCPConnector(resolver=PublicOnlyResolver()),
    )


async def follow_redirects(url: str, max_redirects: int = MAX_REDIRECTS,
                           timeout: float = 5) -> dict:
    """
    Suit les redirections HTTP sans jamais contacter un hôte non public.

    Returns: {"chain": [...], "final_url": str, "blocked": Optional[str], "error": Optional[str]}
    """
    chain = [url]
    current = url
    blocked: Optional[str] = None
    error: Optional[str] = None

    async with safe_session(timeout) as session:
        for _ in range(max_redirects):
            host = urlparse(current).hostname or ""
            if not await host_is_public(host):
                blocked = current
                break
            try:
                async with session.get(current, allow_redirects=False) as resp:
                    location = resp.headers.get("Location", "")
                    if resp.status not in REDIRECT_CODES or not location:
                        break
                    nxt = urljoin(current, location)
                    if urlparse(nxt).scheme not in ("http", "https"):
                        break
                    if nxt == current or nxt in chain:  # boucle
                        break
                    chain.append(nxt)
                    current = nxt
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                error = f"{type(e).__name__}: {e}"
                break
    return {"chain": chain, "final_url": chain[-1], "blocked": blocked, "error": error}
