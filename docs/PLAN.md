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
| Hosting | Azure Container App `footprint` in resource group `rg-footprint`, running inside Q-Vault's existing environment `qvault-env` (Central India) on the teammate's subscription (owner's choice, 2026-10-07) | Own environment: Azure for Students allows only **one** Container Apps environment per subscription. Container Instance: HTTP only. App Service B1: paid monthly |
| Replicas | min 1, max 1 for the demo | Scale to zero: a cold start on stage, and it empties the in-memory replay cache |
| Repo | Public, `zaidnansari2011/footprint` (owner's choice) | |

## Phases

- [x] Data-source probe (which free APIs answer today)
- [x] Backend: recon, lookalikes, usernames, scoring, streaming, replay cache, SSRF guard
- [x] Site-list calibration (218 sites)
- [x] Front end: trail, evidence board, verdict + stamp, tabs, report, mobile layout
- [x] Offline tests (26)
- [x] Repo + CI image to ghcr
- [x] Azure deploy: https://footprint.livelybeach-69506dc5.centralindia.azurecontainerapps.io
- [x] Pre-warm the demo targets (tesla.com, github.com, torvalds) so they replay instantly

## Owner steps

1. **After the demo,** delete the app so it stops using the teammate's credit. This removes only
   Footprint; Q-Vault's environment and apps stay:
   `az group delete -n rg-footprint --subscription 4e995e2f-5117-441f-97d2-149256d6215b`.
2. **Redeploying a new build:** `az containerapp update -n footprint -g rg-footprint --subscription 4e995e2f-5117-441f-97d2-149256d6215b --image ghcr.io/zaidnansari2011/footprint:<commit sha>`.
   A restart empties the replay cache, so re-run the three demo scans afterwards.

## Progress log

| Date | What |
|---|---|
| 2026-10-07 | Built and tested locally; full tesla.com scan in ~20 s |
| 2026-10-07 | Live on Azure; fresh scans take ~45 s there (the Wayback Machine is the slowest source and often times out), cached replays ~5 s |
