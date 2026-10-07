"""One scan = one stream of events. Modules run concurrently; each reports when it lands.

Event shapes (sent to the browser as Server-Sent Events):

* ``{"type": "start", "mode": "domain"|"handle", "target", "brand", "steps": [...]}``
* ``{"type": "step", "step", "state": "running"|"done"|"empty", "summary", "data"}``
* ``{"type": "item", "step", "data"}`` - one lookalike or account, as soon as it's found
* ``{"type": "done", "result": {...}}`` - everything, plus score and findings
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import AsyncIterator

import tldextract

from . import lookalike, recon, usernames
from .net import make_client
from .scoring import score

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
DOMAIN_RX = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

STEPS = {
    "dns": "DNS & email",
    "whois": "Registration",
    "subdomains": "Subdomains",
    "hosts": "Servers & ports",
    "web": "Website",
    "history": "Archive",
    "lookalikes": "Lookalike domains",
    "accounts": "Accounts",
}

CACHE_DIR = Path(__file__).resolve().parent.parent / "cache"
CACHE_TTL = 6 * 3600


def parse_target(raw: str) -> dict | None:
    q = raw.strip().lower()
    q = re.sub(r"^[a-z]+://", "", q).split("/")[0].split("?")[0].split(":")[0].strip(".@ ")
    if "." in q:
        try:
            q = q.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        ext = _extract(q)
        if not ext.domain or not ext.suffix:
            return None
        domain = f"{ext.domain}.{ext.suffix}"
        if not DOMAIN_RX.match(domain):
            return None
        return {"mode": "domain", "target": domain, "label": ext.domain, "suffix": ext.suffix,
                "brand": re.sub(r"[^a-z0-9_]", "", ext.domain)}
    handle = usernames.clean_handle(q)
    if len(handle) < 2:
        return None
    return {"mode": "handle", "target": handle, "brand": handle}


def _cache_path(t: dict) -> Path:
    return CACHE_DIR / f"{t['mode']}-{t['target']}.json"


def cached_events(t: dict) -> list[dict] | None:
    p = _cache_path(t)
    try:
        if time.time() - p.stat().st_mtime < CACHE_TTL:
            return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return None


async def replay(events: list[dict]) -> AsyncIterator[dict]:
    """Play a cached scan back with a little rhythm, so it still feels alive on stage."""
    for e in events:
        if e["type"] == "step" and e["state"] != "running":
            await asyncio.sleep(0.35)
        elif e["type"] == "item":
            await asyncio.sleep(0.04)
        yield e


async def run(t: dict) -> AsyncIterator[dict]:
    q: asyncio.Queue = asyncio.Queue()
    log: list[dict] = []

    async def emit(e: dict) -> None:
        await q.put(e)

    steps = list(STEPS) if t["mode"] == "domain" else ["accounts"]
    await emit({"type": "start", "mode": t["mode"], "target": t["target"], "brand": t["brand"],
                "steps": [{"id": s, "label": STEPS[s]} for s in steps]})

    task = asyncio.create_task(_work(t, emit))
    task.add_done_callback(lambda _: q.put_nowait(None))
    while (e := await q.get()) is not None:
        log.append(e)
        yield e
    if task.exception():
        e = {"type": "error", "message": "The scan stopped unexpectedly. Try again in a moment."}
        yield e
        return
    CACHE_DIR.mkdir(exist_ok=True)
    _cache_path(t).write_text(json.dumps(log), encoding="utf-8", newline="\n")


async def _work(t: dict, emit) -> None:
    async with make_client() as client:
        result: dict = {"mode": t["mode"], "target": t["target"], "brand": t["brand"], "scanned_at": int(time.time())}

        async def step(name, coro, summarise):
            await emit({"type": "step", "step": name, "state": "running"})
            try:
                data = await coro
            except Exception:  # one broken source must not sink the whole scan
                data = None
            result[name] = data
            summary, empty = summarise(data)
            await emit({"type": "step", "step": name, "state": "empty" if empty else "done", "summary": summary, "data": data})
            return data

        async def accounts():
            async def found(acc):
                await emit({"type": "item", "step": "accounts", "data": acc})
            return await step("accounts", usernames.hunt(client, t["brand"], emit=found), _sum_accounts)

        if t["mode"] == "handle":
            await accounts()
        else:
            d = t["target"]
            dns_t = asyncio.create_task(step("dns", recon.dns_records(client, d), _sum_dns))
            whois_t = asyncio.create_task(step("whois", recon.rdap(client, d), _sum_whois))
            subs_t = asyncio.create_task(step("subdomains", _subs_and_ips(client, d), _sum_subs))
            web_t = asyncio.create_task(step("web", recon.web_check(client, d), _sum_web))
            hist_t = asyncio.create_task(step("history", recon.wayback(client, d), _sum_history))
            acc_t = asyncio.create_task(accounts())

            async def hosts():
                dns, subs = await dns_t, await subs_t
                ip_names: dict[str, list[str]] = {}
                for ip in (dns or {}).get("A", []):
                    ip_names.setdefault(ip, []).append(d)
                for name, ips in ((subs or {}).get("resolved") or {}).items():
                    for ip in ips:
                        ip_names.setdefault(ip, []).append(name)
                result["ip_names"] = ip_names
                intel = await recon.ip_intel(client, list(ip_names)) if ip_names else {}
                for ip, h in intel.items():
                    h["names"] = ip_names.get(ip, [])
                return intel

            async def looks():
                who, web = await whois_t, await web_t
                ref = {"nameservers": (who or {}).get("nameservers", []), "title": (web or {}).get("title"),
                       "registrar": (who or {}).get("registrar")}

                async def found(c):
                    await emit({"type": "item", "step": "lookalikes", "data": c})
                return await lookalike.hunt(client, d, t["label"], t["suffix"], ref, emit=found)

            await asyncio.gather(
                step("hosts", hosts(), _sum_hosts),
                step("lookalikes", looks(), _sum_looks),
                hist_t, acc_t,
            )

        result.update(score(result))
        await emit({"type": "done", "result": result})


async def _subs_and_ips(client, domain):
    subs = await recon.subdomains(client, domain)
    subs["resolved"] = await recon.resolve_many(client, subs["names"])
    subs["interesting"] = [n for n in subs["names"] if recon.INTERESTING_SUBS.search(n[: -len(domain) - 1])]
    return subs


# ---------------------------------------------------------------- one-line summaries


def _sum_dns(r):
    if not r or not r["exists"]:
        return "This domain doesn't resolve", True
    bits = [f"{len(r['A'])} address{'es' if len(r['A']) != 1 else ''}"]
    bits.append("mail set up" if r["MX"] else "no mail servers")
    bits.append("DMARC on" if r["DMARC"] else "no DMARC")
    return ", ".join(bits), False


def _sum_whois(r):
    if not r:
        return "Registry didn't answer", True
    age = recon.age_days(r["created"])
    yrs = f"{age // 365} years old" if age and age >= 365 else f"{age} days old" if age is not None else "age unknown"
    return f"{yrs}, via {r['registrar'] or 'unknown registrar'}", False


def _sum_subs(r):
    if not r or not r["names"]:
        return "None found in certificate logs", True
    return f"{len(r['names'])} found, {len(r['interesting'])} worth a look", False


def _sum_hosts(r):
    if not r:
        return "No servers to look up", True
    ports = sum(len(h["ports"]) for h in r.values())
    vulns = sum(len(h["vulns"]) for h in r.values())
    countries = len({h["cc"] for h in r.values() if h["cc"]})
    return f"{len(r)} servers in {countries} countr{'y' if countries == 1 else 'ies'}, {ports} open ports, {vulns} CVEs", False


def _sum_web(r):
    if not r:
        return "Website didn't respond", True
    return f"Security headers grade {r['grade']}", False


def _sum_history(r):
    if not r or not r["total"]:
        return "Not in the archive (or archive busy)", True
    return f"{r['total']} archived URLs since {r['first_year']}, {len(r['juicy'])} sensitive-looking", False


def _sum_looks(r):
    if not r:
        return "Lookalike check failed", True
    bad = sum(1 for c in r["registered"] if c["verdict"] in ("Likely phishing", "Suspicious"))
    return f"{r['checked']} tried, {len(r['registered'])} registered, {bad} suspicious", False


def _sum_accounts(r):
    if not r:
        return "Account check failed", True
    return f"On {len(r['accounts'])} of {r['sites_checked']} sites, {len(r['impersonators'])} lookalike handles", False
