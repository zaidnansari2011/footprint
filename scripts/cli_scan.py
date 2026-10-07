"""Run a scan in the terminal and print each event's summary: python scripts/cli_scan.py tesla.com"""
import asyncio, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import scan

async def main(q):
    t0 = time.time()
    items = 0
    async for e in scan.run(scan.parse_target(q)):
        if e["type"] == "step" and e["state"] != "running":
            print(f"{time.time()-t0:5.1f}s  {e['step']:<11} {e['state']:<6} {e['summary']}")
        elif e["type"] == "item":
            items += 1
        elif e["type"] == "done":
            r = e["result"]
            print(f"{time.time()-t0:5.1f}s  DONE score={r['score']} band={r['band']} items={items}")
            for f in r["findings"]:
                print(f"   [{f['severity']}] {f['title']} - {f['detail'][:110]}")
            if r.get("lookalikes"):
                for c in r["lookalikes"]["registered"][:8]:
                    print(f"   {c['score']:3} {c['verdict']:<16} {c['display']:<24} {c['reasons']}")
            print("   accounts:", [a["site"] for a in r["accounts"]["accounts"]][:30])
            print("   impers:", [(a["handle"], a["site"]) for a in r["accounts"]["impersonators"]][:15])
        elif e["type"] == "error":
            print("ERROR", e)

asyncio.run(main(sys.argv[1]))
