"""Attack-surface recon: what does a domain expose to anyone who looks?

Every source here is passive and keyless: DNS over HTTPS, RDAP, certificate-transparency
logs, Shodan InternetDB, ip-api, the Wayback Machine. The only thing we touch directly is
the target's own homepage, as any browser would.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

import httpx

from .net import doh, safe_fetch

INTERESTING_SUBS = re.compile(
    r"(^|[.-])(dev|develop|staging|stage|stg|test|qa|uat|beta|demo|sandbox|internal|intranet|admin|"
    r"vpn|remote|jenkins|gitlab|git|jira|grafana|kibana|old|legacy|backup|bak|db|sql|mail|webmail|"
    r"owa|portal|sso|auth|ftp|api)([.-]|\d|$)"
)

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MS SQL", 2375: "Docker API", 3306: "MySQL",
    3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 5601: "Kibana", 8080: "Alt HTTP", 8443: "Alt HTTPS",
}

SECURITY_HEADERS = {
    "strict-transport-security": "Forces HTTPS so traffic can't be downgraded",
    "content-security-policy": "Limits which scripts may run, the main defence against XSS",
    "x-frame-options": "Stops the site being framed for clickjacking",
    "x-content-type-options": "Stops browsers guessing file types",
    "referrer-policy": "Controls what leaks in the Referer header",
    "permissions-policy": "Restricts camera, mic and location access",
}

JUICY_PATHS = re.compile(
    r"(\.env|\.git/|\.sql|\.bak|\.backup|\.old|\.zip|\.tar|\.gz|\.log|\.config|config\.php|wp-config|"
    r"phpinfo|/admin|/administrator|wp-admin|/debug|/swagger|/api-docs|\.json$|\.xml$|/backup|/dump)",
    re.I,
)


# ---------------------------------------------------------------- DNS


async def dns_records(client: httpx.AsyncClient, domain: str) -> dict:
    kinds = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
    answers = await asyncio.gather(*(doh(client, domain, k) for k in kinds), doh(client, f"_dmarc.{domain}", "TXT"))
    rec = {k: a["answers"] for k, a in zip(kinds, answers)}
    dmarc = next((t for t in answers[-1]["answers"] if t.lower().startswith("v=dmarc1")), None)
    spf = next((t for t in rec["TXT"] if t.lower().startswith("v=spf1")), None)
    rec["SPF"] = spf
    rec["DMARC"] = dmarc
    rec["exists"] = answers[0]["status"] == 0 or any(rec[k] for k in kinds)
    return rec


def dns_findings(rec: dict) -> list[dict]:
    f = []
    if rec["MX"] or rec["SPF"]:
        if not rec["SPF"]:
            f.append(_f("high", "email", "No SPF record", "Anyone can send email that claims to come from this domain."))
        elif rec["SPF"].rstrip().endswith("+all"):
            f.append(_f("high", "email", "SPF allows every server (+all)", "The SPF record approves the whole internet as a sender."))
        elif rec["SPF"].rstrip().endswith("?all"):
            f.append(_f("medium", "email", "SPF is neutral (?all)", "Receivers are told not to act on spoofed mail."))
    if not rec["DMARC"]:
        f.append(_f("high", "email", "No DMARC policy", "Spoofed emails from this domain won't be blocked, which makes phishing easy."))
    elif re.search(r"\bp=none\b", rec["DMARC"], re.I):
        f.append(_f("medium", "email", "DMARC is monitor-only (p=none)", "Spoofed mail is reported but still delivered."))
    if not rec["CAA"]:
        f.append(_f("low", "dns", "No CAA record", "Any certificate authority may issue certificates for this domain."))
    return f


# ---------------------------------------------------------------- RDAP / WHOIS


_bootstrap: dict[str, str] = {}
_rdap_sem = asyncio.Semaphore(6)


async def _rdap_base(client: httpx.AsyncClient, tld: str) -> str:
    """Ask the registry directly (IANA's RDAP directory); rdap.org throttles bursts."""
    if not _bootstrap:
        try:
            r = await client.get("https://data.iana.org/rdap/dns.json", timeout=10.0)
            for tlds, urls in r.json()["services"]:
                for t in tlds:
                    _bootstrap[t] = urls[0].rstrip("/") + "/"
        except (httpx.HTTPError, ValueError, KeyError):
            pass
    return _bootstrap.get(tld, "https://rdap.org/")


async def rdap(client: httpx.AsyncClient, domain: str) -> dict | None:
    try:
        base = await _rdap_base(client, domain.rsplit(".", 1)[-1])
        async with _rdap_sem:
            r = await client.get(f"{base}domain/{domain}", follow_redirects=True, timeout=12.0)
        if r.status_code != 200:
            return None
        j = r.json()
    except (httpx.HTTPError, ValueError):
        return None
    events = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    registrar = None
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    return {
        "registrar": registrar,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed"),
        "nameservers": [n.get("ldhName", "").lower() for n in j.get("nameservers", [])],
        "status": j.get("status", []),
    }


def age_days(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def whois_findings(w: dict | None) -> list[dict]:
    if not w:
        return []
    f = []
    left = age_days(w.get("expires"))
    if left is not None and -left < 45:
        f.append(_f("high", "dns", "Domain expires soon", f"Registration lapses in {-left} days. A lapsed domain can be bought by anyone."))
    if not any("transfer" in s.lower() and "prohibited" in s.lower() for s in w.get("status", [])):
        f.append(_f("low", "dns", "No transfer lock", "The domain isn't locked against being moved to another registrar."))
    return f


# ---------------------------------------------------------------- subdomains


async def _certspotter(client, domain):
    r = await client.get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=20.0,
    )
    r.raise_for_status()
    return {n for item in r.json() for n in item.get("dns_names", [])}


async def _hackertarget(client, domain):
    r = await client.get("https://api.hackertarget.com/hostsearch/", params={"q": domain}, timeout=20.0)
    r.raise_for_status()
    if "error" in r.text[:60].lower() or "API count" in r.text:
        return set()
    return {line.split(",")[0] for line in r.text.splitlines() if "," in line}


async def _crtsh(client, domain):
    r = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=25.0)
    r.raise_for_status()
    return {n for item in r.json() for n in item.get("name_value", "").split("\n")}


async def subdomains(client: httpx.AsyncClient, domain: str) -> dict:
    """Merge three certificate/passive-DNS sources; any of them may be down on the day."""
    sources = {"certspotter": _certspotter, "hackertarget": _hackertarget, "crt.sh": _crtsh}
    got = await asyncio.gather(*(fn(client, domain) for fn in sources.values()), return_exceptions=True)
    names: set[str] = set()
    used = []
    for src, res in zip(sources, got):
        if isinstance(res, set):
            used.append(src)
            names |= res
    normalised = {re.sub(r"^\*\.", "", n.strip().lower()) for n in names}
    clean = sorted(n for n in normalised if n.endswith("." + domain))
    return {"names": clean, "sources": used}


async def resolve_many(client: httpx.AsyncClient, names: list[str], limit: int = 60) -> dict[str, list[str]]:
    """Resolve subdomains to IPs, interesting-looking names first."""
    ranked = sorted(names, key=lambda n: (not INTERESTING_SUBS.search(n.split(".")[0]), n.count("."), n))[:limit]
    sem = asyncio.Semaphore(20)

    async def one(n):
        async with sem:
            return n, (await doh(client, n, "A"))["answers"]

    pairs = await asyncio.gather(*(one(n) for n in ranked))
    return {n: [ip for ip in ips if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip)] for n, ips in pairs}


# ---------------------------------------------------------------- IP intelligence


async def ip_intel(client: httpx.AsyncClient, ips: list[str]) -> dict[str, dict]:
    ips = ips[:40]
    sem = asyncio.Semaphore(12)

    async def shodan(ip):
        async with sem:
            try:
                r = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=10.0)
                return ip, r.json() if r.status_code == 200 else {}
            except (httpx.HTTPError, ValueError):
                return ip, {}

    async def geo():
        try:
            r = await client.post(
                "http://ip-api.com/batch",
                params={"fields": "query,status,country,countryCode,city,lat,lon,isp,org,as"},
                json=ips,
                timeout=10.0,
            )
            rows = r.json() if r.status_code == 200 else []
            if not isinstance(rows, list):  # rate-limited replies are an object, not a list
                return {}
            return {g["query"]: g for g in rows if isinstance(g, dict) and g.get("status") == "success"}
        except Exception:
            return {}

    shodan_rows, geo_rows = await asyncio.gather(asyncio.gather(*(shodan(ip) for ip in ips)), geo())
    out = {}
    for ip, s in shodan_rows:
        g = geo_rows.get(ip, {})
        out[ip] = {
            "ports": s.get("ports", []),
            "vulns": s.get("vulns", []),
            "cpes": s.get("cpes", []),
            "hostnames": s.get("hostnames", []),
            "country": g.get("country"),
            "cc": g.get("countryCode"),
            "city": g.get("city"),
            "lat": g.get("lat"),
            "lon": g.get("lon"),
            "org": g.get("org") or g.get("isp"),
        }
    return out


def host_findings(intel: dict[str, dict], ip_names: dict[str, list[str]]) -> list[dict]:
    f = []
    for ip, h in intel.items():
        where = ", ".join(ip_names.get(ip, [])[:2]) or ip
        for p in h["ports"]:
            if p in RISKY_PORTS:
                sev = "medium" if p in (8080, 8443, 21) else "high"
                f.append(_f(sev, "hosts", f"{RISKY_PORTS[p]} open to the internet", f"Port {p} answers on {where}."))
        if h["vulns"]:
            n = len(h["vulns"])
            f.append(_f("high", "hosts", f"{n} known vulnerabilit{'y' if n == 1 else 'ies'} on one server",
                        f"{where} runs software with published CVEs, e.g. {', '.join(sorted(h['vulns'])[:3])}."))
    return f


# ---------------------------------------------------------------- web headers


async def web_check(client: httpx.AsyncClient, domain: str) -> dict | None:
    page = await safe_fetch(client, f"https://{domain}")
    https = True
    if page is None:
        page = await safe_fetch(client, f"http://{domain}")
        https = False
    if page is None:
        return None
    h = page.headers
    present = {k: (k in h) for k in SECURITY_HEADERS}
    score = sum(present.values())
    grade = "A" if score >= 6 else "B" if score >= 5 else "C" if score >= 3 else "D" if score >= 2 else "F"
    if not https:
        grade = "F"
    m = re.search(r"<title[^>]*>(.*?)</title>", page.text, re.I | re.S)
    return {
        "url": page.url,
        "status": page.status,
        "https": https,
        "title": re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else None,
        "server": h.get("server"),
        "powered_by": h.get("x-powered-by"),
        "headers": present,
        "grade": grade,
    }


def web_findings(w: dict | None) -> list[dict]:
    if not w:
        return []
    f = []
    if not w["https"]:
        f.append(_f("high", "web", "Website doesn't use HTTPS", "Visitors' traffic can be read and changed in transit."))
    missing = [k for k, ok in w["headers"].items() if not ok]
    if missing:
        sev = "medium" if len(missing) >= 3 else "low"
        f.append(_f(sev, "web", f"{len(missing)} security headers missing",
                    "Missing: " + ", ".join(missing) + "."))
    if w["powered_by"] or (w["server"] and re.search(r"\d", w["server"])):
        f.append(_f("low", "web", "Server reveals its software version",
                    f"It announces {w['powered_by'] or w['server']}, which helps attackers pick exploits."))
    return f


# ---------------------------------------------------------------- Wayback


async def wayback(client: httpx.AsyncClient, domain: str) -> dict | None:
    try:
        r = await client.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"{domain}/*", "output": "json", "fl": "original,timestamp", "collapse": "urlkey", "limit": "2000"},
            timeout=40.0,
        )
        rows = r.json()[1:] if r.status_code == 200 and r.text.strip() else []
    except (httpx.HTTPError, ValueError):
        return None
    juicy = []
    seen = set()
    for url, ts in rows:
        path = re.sub(r"^https?://[^/]+", "", url).split("?")[0]
        if JUICY_PATHS.search(path) and path not in seen:
            seen.add(path)
            juicy.append({"url": url, "year": ts[:4]})
    years = sorted({ts[:4] for _, ts in rows})
    return {"total": len(rows), "first_year": years[0] if years else None, "juicy": juicy[:40]}


def wayback_findings(w: dict | None) -> list[dict]:
    if not w or not w["juicy"]:
        return []
    sample = ", ".join(j["url"].split("/", 3)[-1][:40] for j in w["juicy"][:3])
    return [_f("medium", "history", f"{len(w['juicy'])} sensitive-looking URLs in the archive",
               f"The Wayback Machine remembers paths like {sample}. Worth checking they're gone.")]


def _f(severity: str, area: str, title: str, detail: str) -> dict:
    return {"severity": severity, "area": area, "title": title, "detail": detail}
