"""Shared HTTP plumbing: one client factory, DNS-over-HTTPS, and an SSRF-safe fetch.

Footprint fetches pages on hosts that a visitor typed in (the target's homepage, the
homepages of lookalike domains). Without a guard, a visitor could aim the server at
``169.254.169.254`` (cloud metadata) or ``localhost``. ``safe_fetch`` resolves every hop
of a redirect chain and refuses anything that is not a public address.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0 Safari/537.36"
)
MAX_BODY = 400_000  # bytes; enough for titles and fingerprints, small enough to be cheap


def make_client(timeout: float = 12.0, concurrency: int = 60) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=6.0),
        headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"},
        limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=20),
        follow_redirects=False,
    )


# ---------------------------------------------------------------- DNS over HTTPS

DOH_ENDPOINTS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


async def doh(client: httpx.AsyncClient, name: str, rtype: str = "A") -> dict:
    """Query DNS over HTTPS. Returns ``{"status": int, "answers": [str]}``.

    Status follows RFC 1035: 0 = NOERROR (the name exists), 3 = NXDOMAIN (it does not).
    Falls back to Cloudflare when Google fails; -1 means neither answered.
    """
    for endpoint in DOH_ENDPOINTS:
        try:
            r = await client.get(
                endpoint,
                params={"name": name, "type": rtype},
                headers={"Accept": "application/dns-json"},
                timeout=6.0,
            )
            if r.status_code != 200:
                continue
            j = r.json()
            want = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5, "CAA": 257}.get(rtype)
            answers = [
                a.get("data", "").strip('"') if rtype != "TXT" else _join_txt(a.get("data", ""))
                for a in j.get("Answer", []) or []
                if want is None or a.get("type") == want
            ]
            return {"status": j.get("Status", -1), "answers": answers}
        except (httpx.HTTPError, ValueError):
            continue
    return {"status": -1, "answers": []}


def _join_txt(data: str) -> str:
    # Long TXT records arrive as several quoted chunks: "v=spf1 ..." "include:..."
    parts = [p for p in data.split('"') if p.strip()]
    return "".join(parts) if parts else data


# ---------------------------------------------------------------- SSRF-safe fetch


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


async def host_is_public(host: str) -> bool:
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    ips = {info[4][0] for info in infos}
    return bool(ips) and all(_is_public(ip) for ip in ips)


@dataclass
class Page:
    url: str
    status: int
    headers: httpx.Headers
    text: str
    chain: list[str]


async def safe_fetch(client: httpx.AsyncClient, url: str, max_hops: int = 5, timeout: float = 10.0) -> Page | None:
    """GET ``url`` following redirects by hand, refusing any non-public hop."""
    chain: list[str] = []
    for _ in range(max_hops + 1):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        if not await host_is_public(parts.hostname):
            return None
        chain.append(url)
        try:
            async with client.stream("GET", url, timeout=timeout) as r:
                if r.is_redirect and "location" in r.headers:
                    url = urljoin(url, r.headers["location"])
                    continue
                body = b""
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
                text = body.decode(r.encoding or "utf-8", errors="replace")
                return Page(url=str(r.url), status=r.status_code, headers=r.headers, text=text, chain=chain)
        except (httpx.HTTPError, UnicodeError):
            return None
    return None
