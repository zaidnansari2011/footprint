"""Turn raw module output into plain-English findings and a single 0-100 exposure score.

The score is deliberately simple so it can be explained in one breath: every finding
adds points by severity (high 12, medium 6, low 2), capped at 100. Higher = more exposed.
"""

from __future__ import annotations

from . import recon

WEIGHT = {"high": 12, "medium": 6, "low": 2}


def score(result: dict) -> dict:
    f: list[dict] = []
    if result["mode"] == "domain":
        if result.get("dns"):
            f += recon.dns_findings(result["dns"])
        f += recon.whois_findings(result.get("whois"))
        f += recon.host_findings(result.get("hosts") or {}, result.get("ip_names") or {})
        f += recon.web_findings(result.get("web"))
        f += recon.wayback_findings(result.get("history"))
        subs = result.get("subdomains") or {}
        live_interesting = [n for n in subs.get("interesting", []) if (subs.get("resolved") or {}).get(n)]
        if live_interesting:
            f.append(recon._f("medium", "subdomains", f"{len(live_interesting)} revealing subdomains are live",
                              "Names like " + ", ".join(live_interesting[:3]) + " point at test or admin systems."))
        looks = (result.get("lookalikes") or {}).get("registered", [])
        phish = [c for c in looks if c["verdict"] == "Likely phishing"]
        sus = [c for c in looks if c["verdict"] == "Suspicious"]
        if phish:
            f.append(recon._f("high", "lookalikes", f"{len(phish)} lookalike domain{'s look' if len(phish) > 1 else ' looks'} ready for phishing",
                              "For example " + ", ".join(c["display"] for c in phish[:3]) + "."))
        if sus:
            f.append(recon._f("medium", "lookalikes", f"{len(sus)} suspicious lookalike domain{'s' if len(sus) > 1 else ''}",
                              "Registered by someone else and worth watching: " + ", ".join(c["display"] for c in sus[:3]) + "."))

    acc = result.get("accounts") or {}
    imps = acc.get("impersonators", [])
    if imps:
        f.append(recon._f("medium", "accounts", f"{len(imps)} lookalike account{'s' if len(imps) > 1 else ''} on social platforms",
                          "Handles like " + ", ".join(f"{i['handle']} on {i['site']}" for i in imps[:3]) + " could be impersonators."))

    order = {"high": 0, "medium": 1, "low": 2}
    f.sort(key=lambda x: order[x["severity"]])
    total = min(100, sum(WEIGHT[x["severity"]] for x in f))
    band = "Low" if total < 25 else "Moderate" if total < 50 else "High" if total < 75 else "Severe"
    return {"findings": f, "score": total, "band": band}
