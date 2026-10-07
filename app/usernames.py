"""Username hunter: where does a handle exist, and who is squatting on look-alike handles?

Detection rules come from the Sherlock project's site list (MIT licence, see
``data/SHERLOCK-LICENSE``). ``scripts/calibrate_sites.py`` keeps only the sites that
answered correctly for both a known-taken and a random handle, so the demo is not
padded with false positives.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import httpx

SITES_FILE = Path(__file__).parent / "data" / "sites.json"

# Sites where impersonation of a brand turns into fraud: fake support, fake giveaways.
SCAM_PRONE = {
    "Telegram", "YouTube", "GitHub", "GitLab", "Discord", "threads", "Twitch", "Pinterest",
    "Medium", "Linktree", "Snapchat", "tumblr", "Patreon", "VK", "Bluesky", "Signal", "Venmo",
    "Substack", "mastodon.social", "Imgur", "Vimeo", "SoundCloud", "BuyMeACoffee", "Gumroad",
    "Docker Hub", "Hugging Face", "Rumble", "Carrd",
}

SUFFIXES = ("official", "_support", "support", "help", "hq", "_team", "app", "_care")


def load_sites() -> dict:
    return json.loads(SITES_FILE.read_text(encoding="utf-8"))


def clean_handle(raw: str) -> str:
    return re.sub(r"[^a-z0-9_.-]", "", raw.lower())[:30]


def handle_variants(handle: str) -> list[str]:
    """The impersonator's playbook: brand + support/official/help, plus a 0/o 1/l swap."""
    out = [handle + s for s in SUFFIXES]
    for a, b in (("o", "0"), ("l", "1"), ("i", "1"), ("e", "3")):
        if a in handle:
            out.append(handle.replace(a, b, 1))
            break
    return [v for v in dict.fromkeys(out) if v != handle and len(v) <= 30]


def _matches(rule: dict, handle: str) -> bool:
    rx = rule.get("regexCheck")
    if not rx:
        return True
    try:
        return re.search(rx, handle) is not None
    except re.error:
        return True


async def check_site(client: httpx.AsyncClient, name: str, rule: dict, handle: str) -> dict:
    """Returns ``{"site", "url", "state"}`` with state in found / missing / unknown."""
    profile = rule["url"].format(handle)
    result = {"site": name, "url": profile, "state": "unknown"}
    if not _matches(rule, handle):
        result["state"] = "missing"
        return result
    probe = rule.get("urlProbe", rule["url"]).format(handle)
    method = rule.get("request_method", "GET")
    payload = rule.get("request_payload")
    if payload:
        payload = json.loads(json.dumps(payload).replace("{}", handle))
    kind = rule["errorType"]
    try:
        r = await client.request(
            method,
            probe,
            headers=rule.get("headers"),
            json=payload,
            follow_redirects=kind != "response_url",
            timeout=9.0,
        )
    except httpx.HTTPError:
        return result

    if kind == "status_code":
        codes = rule.get("errorCode")
        codes = [codes] if isinstance(codes, int) else (codes or [])
        found = 200 <= r.status_code < 300 and r.status_code not in codes
    elif kind == "message":
        msgs = rule.get("errorMsg")
        msgs = [msgs] if isinstance(msgs, str) else (msgs or [])
        found = r.status_code < 500 and not any(m in r.text for m in msgs)
        if r.status_code == 429:
            return result
    elif kind == "response_url":
        found = 200 <= r.status_code < 300
    else:
        return result
    result["state"] = "found" if found else "missing"
    return result


async def hunt(client: httpx.AsyncClient, handle: str, variants: bool = True, emit=None) -> dict:
    """Check ``handle`` everywhere, and its impersonation variants on scam-prone sites.

    ``emit`` (optional) is called with each found account as it lands, so the UI can
    animate results in instead of waiting for the slowest site.
    """
    sites = load_sites()
    sem = asyncio.Semaphore(40)

    async def run(name, rule, h, role):
        async with sem:
            res = await check_site(client, name, rule, h)
        res.update(handle=h, role=role)
        if res["state"] == "found" and emit:
            await emit(res)
        return res

    jobs = [run(n, r, handle, "primary") for n, r in sites.items()]
    if variants:
        for v in handle_variants(handle):
            jobs += [run(n, r, v, "variant") for n, r in sites.items() if n in SCAM_PRONE]
    results = await asyncio.gather(*jobs)

    found = [r for r in results if r["state"] == "found"]
    primary = sorted((r for r in found if r["role"] == "primary"), key=lambda r: r["site"].lower())
    lookalikes = sorted((r for r in found if r["role"] == "variant"), key=lambda r: (r["site"].lower(), r["handle"]))
    return {
        "handle": handle,
        "sites_checked": len(sites),
        "variants": handle_variants(handle) if variants else [],
        "accounts": primary,
        "impersonators": lookalikes,
        "unknown": sum(1 for r in results if r["state"] == "unknown"),
    }
