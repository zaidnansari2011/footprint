# Footprint: build plan

**Goal:** an OSINT web app for the subject submission, live on Azure for the demo on
2026-10-08. One input, three tools (recon, lookalike domains, usernames), one animated
evidence board.

## Decisions

| Decision | Chosen | Rejected, and why |
|---|---|---|
| Stack | FastAPI + one static page (vanilla JS, Cytoscape.js, Leaflet) | React/Next: a build step buys nothing for one page |
| Live results | Server-Sent Events over `fetch` | WebSockets: one-way stream is enough; `EventSource` can't read 400/429 bodies |
| Data sources | Keyless public APIs only | Shodan/HIBP/VirusTotal keys: a demo that depends on a key can break on the day |
| Subdomains | Race Certspotter + HackerTarget + crt.sh | crt.sh alone returned 502 on test day |
| Username rules | Sherlock's `data.json`, calibrated | Writing site rules by hand: slower and less credible |
| Hosting | Azure Container Apps, own resource group `rg-footprint` on the teammate's subscription (owner's choice, 2026-10-07) | Owner's own subscription: off-limits |
| Repo | Public, `zaidnansari2011/footprint` (owner's choice) | |

## Phases

- [x] Data-source probe (which free APIs answer today)
- [x] Backend: recon, lookalikes, usernames, scoring, streaming, replay cache, SSRF guard
- [x] Site-list calibration (218 sites)
- [x] Front end: trail, evidence board, verdict + stamp, tabs, report, mobile layout
- [x] Offline tests (26)
- [x] Repo + CI image to ghcr
- [ ] Azure deploy: `rg-footprint`, Container Apps env + app, scale to zero
- [ ] Pre-warm the demo targets so they replay instantly

## Owner steps

1. **After the demo,** delete the Azure resources so they stop using the teammate's credit:
   `az group delete -n rg-footprint --subscription 4e995e2f-5117-441f-97d2-149256d6215b`.

## Progress log

| Date | What |
|---|---|
| 2026-10-07 | Built and tested locally; full tesla.com scan in ~20 s |
