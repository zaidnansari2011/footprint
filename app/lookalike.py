"""Lookalike hunter: which near-copies of a domain has someone already registered?

1. ``permutations`` invents the domains a phisher would buy (typos, swapped letters,
   Cyrillic look-alikes, ``-login`` add-ons, other endings).
2. One DNS query each tells us which exist.
3. The registered ones are profiled: do they accept email (MX), how new are they (RDAP),
   do they serve a copy of the real site, or do they belong to the brand itself?
"""

from __future__ import annotations

import asyncio
import difflib
import re

import httpx

from .net import doh, safe_fetch
from .recon import age_days, rdap

KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok",
    "o": "ipl", "p": "ol", "a": "qsz", "s": "adw", "d": "sfe", "f": "dgr", "g": "fht", "h": "gjy",
    "j": "hku", "k": "jli", "l": "kop", "z": "asx", "x": "zcs", "c": "xvd", "v": "cbf", "b": "vng",
    "n": "bmh", "m": "nj",
}
ASCII_GLYPHS = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "m": ["rn"], "w": ["vv"], "d": ["cl"]}
CYRILLIC = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}
KEYWORDS = ("login", "secure", "support", "verify", "account", "help", "pay", "online", "app", "official")
TLDS = ("com", "net", "org", "co", "io", "info", "xyz", "online", "shop", "site", "app", "in", "us", "biz", "me")
PARKED = re.compile(
    r"(domain (is )?for sale|buy this domain|this domain (may be|is) for sale|parked free|parkingcrew|sedo|"
    r"dan\.com|afternic|godaddy\.com/domain|hugedomains|domain parking|bodis|namecheap parking)",
    re.I,
)

# Corporate registrars that big brands use to hold their own defensive registrations.
BRAND_REGISTRARS = re.compile(r"markmonitor|csc corporate|corporation service company|com laude|safenames|ebrand|nameshield|brandsight|tucows corporate", re.I)

KIND_LABEL = {
    "tld": "Different ending",
    "keyword": "Brand + keyword",
    "homoglyph": "Look-alike letters",
    "idn": "Foreign-alphabet letters",
    "omission": "Missing letter",
    "repetition": "Doubled letter",
    "transposition": "Swapped letters",
    "replacement": "Keyboard typo",
    "hyphen": "Added hyphen",
}


def permutations(label: str, suffix: str, cap: int = 260) -> list[dict]:
    """Generate candidate lookalikes of ``label.suffix``, most dangerous kinds first."""
    out: dict[str, str] = {}

    def add(lbl: str, kind: str, sfx: str = suffix) -> None:
        if lbl and lbl != label and not lbl.startswith("-") and not lbl.endswith("-") and len(lbl) <= 63:
            out.setdefault(f"{lbl}.{sfx}", kind)

    for t in TLDS:
        if t != suffix:
            out.setdefault(f"{label}.{t}", "tld")
    for k in KEYWORDS:
        add(f"{label}-{k}", "keyword")
        add(f"{label}{k}", "keyword")
        add(f"{k}-{label}", "keyword")
    for i, ch in enumerate(label):
        for g in ASCII_GLYPHS.get(ch, []):
            add(label[:i] + g + label[i + 1:], "homoglyph")
    for i, ch in enumerate(label):
        if ch in CYRILLIC:
            add(label[:i] + CYRILLIC[ch] + label[i + 1:], "idn")
    for i in range(len(label)):
        add(label[:i] + label[i + 1:], "omission")
        add(label[:i] + label[i] + label[i:], "repetition")
        if i < len(label) - 1:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposition")
            add(label[:i + 1] + "-" + label[i + 1:], "hyphen")
        for r in KEYBOARD.get(label[i], ""):
            add(label[:i] + r + label[i + 1:], "replacement")

    rows = []
    for name, kind in list(out.items())[:cap]:
        try:
            ascii_name = name.encode("idna").decode("ascii")
        except UnicodeError:
            continue
        rows.append({"domain": ascii_name, "display": name, "kind": kind, "kind_label": KIND_LABEL[kind]})
    return rows


def _title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else None


async def hunt(client: httpx.AsyncClient, domain: str, label: str, suffix: str, ref: dict, emit=None) -> dict:
    """``ref`` carries what we know about the real domain: nameservers and homepage title."""
    candidates = permutations(label, suffix)
    sem = asyncio.Semaphore(30)

    async def exists(c):
        async with sem:
            res = await doh(client, c["domain"], "A")
        c["registered"] = res["status"] == 0
        c["ips"] = [a for a in res["answers"] if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", a)]
        return c

    await asyncio.gather(*(exists(c) for c in candidates))
    live = [c for c in candidates if c["registered"]]

    ref_ns = {n.rstrip(".").lower() for n in ref.get("nameservers", [])}
    ref_title = (ref.get("title") or "").lower()
    ref_registrar = ref.get("registrar")
    psem = asyncio.Semaphore(10)

    async def profile(c, deep: bool):
        try:
            return await _profile(c, deep)
        except Exception:
            c.update(mx=False, ns=[], created=None, registrar=None, age_days=None, final_url=None, title=None,
                     parked=False, brand_owned=False, redirects_to=None, login_form=False, clone_like=False)
            score_and_verdict(c)
            return c

    async def _profile(c, deep: bool):
        async with psem:
            mx, ns = await asyncio.gather(doh(client, c["domain"], "MX"), doh(client, c["domain"], "NS"))
            c["mx"] = bool([m for m in mx["answers"] if not m.endswith(" .")])
            c["ns"] = [n.rstrip(".").lower() for n in ns["answers"]]
            page = await safe_fetch(client, f"http://{c['domain']}", timeout=8.0) if c["ips"] else None
            who = await rdap(client, c["domain"]) if deep else None
        c["created"] = who.get("created") if who else None
        c["registrar"] = who.get("registrar") if who else None
        c["age_days"] = age_days(c["created"])
        c["final_url"] = page.url if page else None
        c["title"] = _title(page.text) if page else None
        body = page.text if page else ""
        c["parked"] = bool(PARKED.search(body[:60000])) if page else False
        final_host = re.sub(r"^https?://([^/:]+).*", r"\1", c["final_url"] or "").lower()
        same_guardian = bool(c["registrar"] and ref_registrar and c["registrar"] == ref_registrar
                             and BRAND_REGISTRARS.search(c["registrar"]))
        c["brand_owned"] = (bool(ref_ns and ref_ns & set(c["ns"])) or same_guardian
                            or final_host == domain or final_host.endswith("." + domain))
        c["redirects_to"] = final_host if final_host and final_host.removeprefix("www.") != c["domain"] else None
        c["login_form"] = bool(re.search(r"<input[^>]+type=[\"']?password", body, re.I))
        # A page titled with its own domain name says nothing; drop that before comparing.
        t = (c["title"] or "").lower().replace(c["domain"], "").replace(c["display"], "")
        c["clone_like"] = bool(t.strip()) and not c["parked"] and (
            (ref_title and difflib.SequenceMatcher(None, t, ref_title).ratio() > 0.6)
            or re.search(rf"\b{re.escape(label)}\b", t) is not None
        )
        score_and_verdict(c)
        if emit:
            await emit(c)
        return c

    # RDAP is slow and rate-limited: only ask about the first 24 registered names.
    await asyncio.gather(*(profile(c, i < 24) for i, c in enumerate(live)))
    live.sort(key=lambda c: -c["score"])
    return {
        "checked": len(candidates),
        "registered": live,
        "by_kind": {k: sum(1 for c in candidates if c["kind"] == k) for k in KIND_LABEL},
    }


def score_and_verdict(c: dict) -> None:
    reasons = []
    if c["brand_owned"]:
        c.update(score=0, verdict="Brand-owned", reasons=["Same nameservers, brand-protection registrar, or redirects to the real site"])
        return
    s = 10
    if c["mx"]:
        s += 20
        reasons.append("Can send and receive email")
    if c["age_days"] is not None and c["age_days"] <= 180:
        s += 25
        reasons.append(f"Registered {c['age_days']} days ago")
    elif c["age_days"] is not None and c["age_days"] <= 365:
        s += 10
        reasons.append("Registered within the last year")
    if c["clone_like"]:
        s += 20
        reasons.append("Homepage uses the brand's name")
    if c["login_form"] and not c["parked"]:
        s += 25
        reasons.append("Asks for a password")
    if c["kind"] in ("idn", "homoglyph", "keyword"):
        s += 10
        reasons.append("Built to fool the eye" if c["kind"] != "keyword" else "Uses a phishing keyword")
    if c["age_days"] is not None and c["age_days"] > 5 * 365:
        s -= 20
        reasons.append(f"Held for {c['age_days'] // 365} years, often a real business")
    if c["parked"]:
        s = min(s, 30)
        reasons.append("Parked or for sale")
    s = max(0, min(s, 100))
    # Mail records alone are common on parked typo domains, so they never make a verdict on their own.
    verdict = "Parked" if c["parked"] else "Likely phishing" if s >= 60 else "Suspicious" if s >= 40 else "Registered"
    c.update(score=s, verdict=verdict, reasons=reasons)
