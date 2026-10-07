# Sleuth

**Live:** https://osint.zaidansari.tech

**Spot the impostors.** Type a domain and Sleuth maps what it exposes to
the internet, which lookalike domains someone else has registered, and which social handles
are one typo away from the real one. Type a username and it finds everywhere that handle lives.

It is an open-source-intelligence (OSINT) web app built from three tools that share one
target and one evidence board:

| Tool | Question it answers | How |
|---|---|---|
| **Attack-surface recon** | What does this organisation expose? | DNS and email records (SPF, DMARC, CAA), RDAP registration data, subdomains from certificate-transparency logs, open ports and CVEs from Shodan InternetDB, server locations, website security headers, sensitive URLs remembered by the Wayback Machine |
| **Lookalike-domain hunter** | Who is impersonating it with fake domains? | Generates ~100-250 typo, swapped-letter, look-alike-letter, Cyrillic (IDN) and `-login` variants, checks which are registered, then profiles each: does it accept email, how new is it, does it show a password form, is it parked, or does it belong to the brand itself? |
| **Username hunter** | Where does the handle exist, and who is squatting on lookalikes? | Checks 200+ sites using the Sherlock project's detection rules (calibrated, see below), plus `support` / `official` / `0-for-o` variants on scam-prone platforms |

Everything is **passive and keyless**: Sleuth only reads public data and loads homepages
like any visitor. It never logs in, brute-forces or port-scans.

## What you see

1. **The trail.** One footprint icon per check; each lights up with a one-line summary as it lands.
2. **The evidence board.** A graph that pins itself up live: your infrastructure across the
   top (subdomains, then servers, then risky ports), lookalike domains on red string to the
   right, accounts and possible impostors to the left. Click any pin for details.
3. **The verdict.** A 0-100 exposure score and the top findings in plain English, then a
   "case closed" stamp.
4. **Tabs** for the detail: Exposure (with a server map), Lookalikes (filterable by verdict),
   Accounts, and a printable **Report** (Save as PDF, or download the raw JSON).

## How the scoring works

- **Exposure score:** every finding adds points by severity (high 12, medium 6, low 2),
  capped at 100. Higher means more exposed. Bands: Low < 25 <= Moderate < 50 <= High < 75 <= Severe.
- **Lookalike threat score:** starts at 10; +20 accepts email, +25 registered in the last 6
  months (+10 within a year), +20 homepage uses the brand name, +25 asks for a password,
  +10 built to fool the eye (look-alike letters or a phishing keyword), -20 held for over
  5 years (usually a real business). Parked domains are capped at 30. A domain sharing the
  real one's nameservers or brand-protection registrar, or redirecting to it, is marked
  **Brand-owned** and scores 0. Mail records alone never make a domain suspicious, because
  parked typo domains almost always have them.

## Engineering notes

- **Streaming.** `GET /api/scan?q=` returns Server-Sent Events. Modules run concurrently with
  `asyncio`; dependent ones wait only for what they need (servers wait for subdomains;
  lookalikes wait for the real site's nameservers and title).
- **Resilience.** Subdomains race three sources (Certspotter, HackerTarget, crt.sh) and merge
  whatever answers. RDAP goes straight to each registry via IANA's bootstrap file, because
  rdap.org throttles bursts. A failed source marks its step "empty" instead of failing the scan.
- **Replay cache.** Finished scans are kept for six hours and replay with the same animation,
  so a demo still works if a public API is down on the day. "Scan again, fresh" bypasses it.
- **SSRF guard.** Every URL Sleuth fetches on a visitor's behalf is resolved first, and
  every redirect hop is re-checked; private, loopback and link-local addresses (including the
  cloud metadata endpoint `169.254.169.254`) are refused.
- **Calibrated site list.** `scripts/calibrate_sites.py` keeps only Sherlock sites that report a
  known-taken handle as found *and* a random handle as missing, twice. 252 of 462 passed; piracy
  and adult-adjacent sites were then removed, leaving 218.
- **Rate limit.** Eight fresh scans per visitor per ten minutes; cached replays are free.

## Run it

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt     # or .venv/bin/pip on macOS/Linux
.venv/Scripts/python -m uvicorn app.main:app --reload
# open http://127.0.0.1:8000
.venv/Scripts/python -m pytest -q                     # offline tests
.venv/Scripts/python scripts/cli_scan.py tesla.com    # a scan in the terminal
```

Or with Docker: `docker build -t sleuth . && docker run -p 8000:8000 sleuth`.

(The repo, image and Azure resources keep their original name, `footprint`.)

Every push to `main` runs the tests and publishes `ghcr.io/zaidnansari2011/footprint`.

## Ethics

Sleuth is for organisations you work for or study, and for your own usernames. It shows
only what is already public, and it frames results as *exposure to fix*, not targets to attack.
A username search tells you a handle exists; it does not tell you who owns it.

## Credits

Username detection rules: [Sherlock](https://github.com/sherlock-project/sherlock) (MIT,
see `app/data/SHERLOCK-LICENSE`). Data: Google and Cloudflare DNS-over-HTTPS, IANA RDAP,
Certspotter, HackerTarget, crt.sh, Shodan InternetDB, ip-api.com, the Internet Archive.
Graph: Cytoscape.js. Map: Leaflet with Esri tiles.
