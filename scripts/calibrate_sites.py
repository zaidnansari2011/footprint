"""Build app/data/sites.json from Sherlock's data.json, keeping only sites that behave.

A site is kept when, on two rounds, its known-taken handle is reported *found* and a random
handle is reported *missing*. Usage::

    python scripts/calibrate_sites.py path/to/sherlock/data.json
"""

from __future__ import annotations

import asyncio
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.net import make_client  # noqa: E402
from app.usernames import SITES_FILE, check_site  # noqa: E402


async def main(src: Path) -> None:
    data = json.loads(src.read_text(encoding="utf-8"))
    sites = {k: v for k, v in data.items() if isinstance(v, dict) and "url" in v and not v.get("isNSFW")}
    sem = asyncio.Semaphore(50)
    async with make_client() as client:

        async def probe(name, rule):
            for _ in range(2):
                async with sem:
                    taken = await check_site(client, name, rule, rule["username_claimed"])
                    free = await check_site(client, name, rule, "zq" + secrets.token_hex(6))
                if taken["state"] != "found" or free["state"] != "missing":
                    return name, False
            return name, True

        verdicts = await asyncio.gather(*(probe(n, r) for n, r in sites.items()))
    keep = {n: {k: v for k, v in sites[n].items() if k != "isNSFW"} for n, ok in verdicts if ok}
    SITES_FILE.write_text(json.dumps(dict(sorted(keep.items())), indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"kept {len(keep)} of {len(sites)} sites -> {SITES_FILE}")
    print(", ".join(sorted(keep)))


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1])))
