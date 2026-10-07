/* Sleuth front end: reads the scan stream and builds the board as results land. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

const RISKY = { 21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MS SQL", 2375: "Docker API", 3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 5601: "Kibana", 8080: "Alt HTTP", 8443: "Alt HTTPS" };
const SOCIAL = new Set(["Telegram", "YouTube", "GitHub", "GitLab", "Discord", "threads", "Twitch", "Pinterest", "Medium", "Linktree", "Snapchat", "tumblr", "Patreon", "VK", "Bluesky", "Signal", "Venmo", "Substack", "mastodon.social", "Imgur", "Vimeo", "SoundCloud", "BuyMeACoffee", "Gumroad", "Docker Hub", "Hugging Face", "Rumble", "Carrd"]);
const STEP_ICON = `<svg viewBox="0 0 32 32"><use href="#foot"/></svg>`;

let S = null;      // state of the current scan
let cy = null;     // cytoscape instance
let map = null;    // leaflet map
let controller = null;

/* ------------------------------------------------------------ hero decoration */
(function trailDeco() {
  const box = $(".trail-deco");
  const n = 14;
  for (let i = 0; i < n; i++) {
    const t = i / (n - 1);
    const el = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    el.setAttribute("viewBox", "0 0 32 32");
    el.innerHTML = `<use href="#foot"/>`;
    const x = 4 + t * 92, y = 82 - Math.sin(t * Math.PI) * 50 + (i % 2 ? 4 : -4);
    el.style.left = x + "%";
    el.style.top = y + "%";
    el.style.transform = `rotate(${70 + Math.cos(t * Math.PI) * 30 + (i % 2 ? 8 : -8)}deg)`;
    el.style.animationDelay = (i * 0.35) + "s";
    box.appendChild(el);
  }
})();

/* ------------------------------------------------------------ search */
$("#searchForm").addEventListener("submit", (e) => {
  e.preventDefault();
  startScan($("#q").value);
});
$$(".try").forEach((b) => b.addEventListener("click", () => { $("#q").value = b.dataset.q; startScan(b.dataset.q); }));
$("#aboutBtn").addEventListener("click", () => $("#about").showModal());

async function startScan(raw, fresh = false) {
  const q = raw.trim();
  if (!q) return;
  $("#formError").textContent = "";
  controller?.abort();
  controller = new AbortController();
  const btn = $(".go");
  btn.disabled = true;
  history.replaceState(null, "", "?q=" + encodeURIComponent(q));
  const mine = controller;
  let res;
  try {
    res = await fetch(`/api/scan?q=${encodeURIComponent(q)}${fresh ? "&fresh=1" : ""}`, { signal: controller.signal });
  } catch (err) {
    if (err.name !== "AbortError") $("#formError").textContent = "Couldn't reach the server. Check your connection and try again.";
    btn.disabled = false;
    return;
  }
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    $("#formError").textContent = j.error || "That didn't work. Try a domain like example.com.";
    btn.disabled = false;
    return;
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (!chunk.startsWith("data: ")) continue;
        try { handle(JSON.parse(chunk.slice(6))); } catch (err) { console.error("render failed", err); }
      }
    }
  } catch (err) {
    if (err.name !== "AbortError") $("#formError").textContent = "The connection dropped mid-scan. Run it again.";
  }
  if (controller === mine) btn.disabled = false;
}

/* ------------------------------------------------------------ event router */
function handle(e) {
  if (e.type === "start") return onStart(e);
  if (!S) return;
  if (e.type === "step") return onStep(e);
  if (e.type === "item") return onItem(e);
  if (e.type === "done") return onDone(e.result);
  if (e.type === "error") $("#formError").textContent = e.message;
}

function onStart(e) {
  S = { mode: e.mode, target: e.target, brand: e.brand, data: {}, looks: new Map(), acc: [], imp: [], filter: "all", graphLooks: 0, graphAcc: 0, graphImp: 0 };
  document.body.classList.remove("is-idle", "mode-domain", "mode-handle");
  document.body.classList.add("mode-" + e.mode);
  $("#q").value = e.target;

  const stops = $("#stops");
  stops.style.setProperty("--n", e.steps.length);
  stops.innerHTML = e.steps.map((s) => `<li class="stop" data-step="${s.id}"><div class="stop-mark">${STEP_ICON}</div><div class="stop-label">${esc(s.label)}</div><div class="stop-sum"></div></li>`).join("");
  $("#trail").hidden = false;
  $("#case").hidden = false;

  // reset the case file
  $("#stamp").classList.remove("is-down");
  $(".verdict").classList.remove("is-shaken");
  setDial(0, "scanning");
  $("#caseTitle").textContent = `Following ${e.target}…`;
  $("#caseLede").textContent = "Results land on the board as each check finishes.";
  $("#topFindings").innerHTML = "";
  ["#lookList", "#accList", "#impList", "#emailChecks", "#webBox", "#hostTable", "#subList", "#historyBox", "#report"].forEach((s) => ($(s).innerHTML = ""));
  $("#impBox").hidden = true;
  $("#hostMore").hidden = true;
  if (map) map.eachLayer((l) => { if (l instanceof L.CircleMarker) map.removeLayer(l); });
  $("#lookCount").textContent = $("#accCount").textContent = "";
  $("#accTitle").textContent = e.mode === "handle" ? `Where “${e.target}” exists` : `Where “${e.brand}” is taken`;
  $("#pinCard").hidden = true;
  showTab("board");
  initBoard(e);
  $("#trail").scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
}

function onStep(e) {
  const stop = $(`.stop[data-step="${e.step}"]`);
  if (stop) {
    stop.classList.remove("is-running", "is-done", "is-empty");
    stop.classList.add("is-" + e.state);
    if (e.summary) $(".stop-sum", stop).textContent = e.summary;
  }
  if (e.state === "running") return;
  S.data[e.step] = e.data;
  const fn = { dns: stepDns, whois: stepWhois, subdomains: stepSubs, hosts: stepHosts, web: stepWeb, history: stepHistory, lookalikes: stepLooks, accounts: stepAccounts }[e.step];
  if (fn && e.data) fn(e.data);
}

function onItem(e) {
  if (e.step === "lookalikes") addLook(e.data);
  if (e.step === "accounts") addAccount(e.data);
}

/* ------------------------------------------------------------ verdict */
function setDial(score, band) {
  const fill = $("#dialFill");
  fill.style.strokeDashoffset = 314.16 * (1 - score / 100);
  fill.style.stroke = score < 25 ? "var(--mint)" : score < 50 ? "#F2B705" : score < 75 ? "#F08C00" : "var(--red)";
  $("#scoreBand").textContent = band;
  const el = $("#scoreNum");
  const from = +el.textContent || 0;
  const t0 = performance.now();
  const dur = reduceMotion ? 1 : 1200;
  (function tick(t) {
    const k = Math.min(1, (t - t0) / dur);
    el.textContent = Math.round(from + (score - from) * (1 - Math.pow(1 - k, 3)));
    if (k < 1) requestAnimationFrame(tick);
  })(t0);
}

function onDone(r) {
  S.result = r;
  const band = r.band.toLowerCase();
  setDial(r.score, band);
  if (r.mode === "domain") {
    $("#caseTitle").textContent = `${r.target} has ${r.band.toLowerCase()} exposure`;
    const looks = r.lookalikes?.registered || [];
    const bad = looks.filter((c) => c.verdict === "Likely phishing" || c.verdict === "Suspicious").length;
    $("#caseLede").textContent = `${plural(r.findings.length, "thing")} to look at, ${plural(bad, "suspicious lookalike")}, ${plural(r.accounts?.impersonators?.length || 0, "possible impostor account")}.`;
  } else {
    const n = r.accounts?.accounts?.length || 0;
    $("#caseTitle").textContent = `${r.target} turns up on ${plural(n, "site")}`;
    $("#caseLede").textContent = `Out of ${r.accounts?.sites_checked || 0} checked. Lookalike handles are listed under Accounts.`;
  }
  $("#topFindings").innerHTML = r.findings.slice(0, 4).map((f, i) =>
    `<li style="animation-delay:${i * 90}ms"><span class="sev sev-${f.severity}" title="${f.severity}"></span><span><b>${esc(f.title)}.</b> <span class="muted">${esc(f.detail)}</span></span></li>`).join("")
    || `<li><span class="sev sev-low"></span><span>Nothing alarming turned up.</span></li>`;
  setTimeout(() => {
    $("#stamp").classList.add("is-down");
    $(".verdict").classList.add("is-shaken");
  }, reduceMotion ? 0 : 900);
  renderReport(r);
  relayout(true);
}

/* ------------------------------------------------------------ tabs */
$("#tabs").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-tab]");
  if (b) showTab(b.dataset.tab);
});
function showTab(name) {
  $$("#tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === name));
  $$(".panel").forEach((p) => (p.hidden = p.dataset.panel !== name));
  if (name === "board" && cy) { cy.resize(); }
  if (name === "exposure" && map) setTimeout(() => { map.invalidateSize(); fitMap(); }, 50);
}

/* ------------------------------------------------------------ board */
function initBoard(e) {
  cy?.destroy();
  cy = null;
  if (typeof cytoscape === "undefined") { $("#board").textContent = "The board couldn't load. The other tabs still work."; return; }
  cy = cytoscape({
    container: $("#board"),
    wheelSensitivity: 0.25,
    minZoom: 0.3, maxZoom: 2.5,
    style: [
      { selector: "node", style: {
        "label": "data(label)", "font-family": "Atkinson Hyperlegible, sans-serif", "font-size": 15, "color": "#1D2445",
        "text-valign": "bottom", "text-margin-y": 5, "text-wrap": "wrap", "text-max-width": 190,
        "text-background-color": "#FBFCFE", "text-background-opacity": 0.85, "text-background-padding": 2,
        "width": 24, "height": 24, "background-color": "#A3AAC4", "border-width": 3, "border-color": "#fff",
      } },
      { selector: "node[kind='target']", style: { "width": 70, "height": 70, "background-color": "#1D2445", "font-size": 22, "font-weight": 700, "font-family": "Bricolage Grotesque, sans-serif", "border-width": 4, "border-color": "#FFD43B" } },
      { selector: "node[kind='sub']", style: { "background-color": "#3D5AFE" } },
      { selector: "node[kind='sub-hot']", style: { "background-color": "#3D5AFE", "border-color": "#FFD43B", "border-width": 3 } },
      { selector: "node[kind='more']", style: { "background-color": "#fff", "border-color": "#A3AAC4", "border-style": "dashed", "color": "#6B7394" } },
      { selector: "node[kind='ip']", style: { "shape": "round-rectangle", "width": 20, "height": 20, "background-color": "#A3AAC4" } },
      { selector: "node[kind='port']", style: { "shape": "diamond", "background-color": "#FFD43B", "border-color": "#E0B400", "width": 26, "height": 26 } },
      { selector: "node[kind='cve']", style: { "shape": "diamond", "background-color": "#E5383B", "width": 28, "height": 28 } },
      { selector: "node[kind='mail-ok']", style: { "shape": "round-rectangle", "background-color": "#12B886" } },
      { selector: "node[kind='mail-bad']", style: { "shape": "round-rectangle", "background-color": "#FFD43B", "border-color": "#E5383B", "border-width": 3 } },
      { selector: "node[kind='look']", style: { "background-color": "#E5383B", "width": 32, "height": 32 } },
      { selector: "node[kind='look-sus']", style: { "background-color": "#F7A4A5", "width": 26, "height": 26 } },
      { selector: "node[kind='acc']", style: { "background-color": "#12B886" } },
      { selector: "node[kind='imp']", style: { "background-color": "#fff", "border-color": "#E5383B", "border-width": 4 } },
      { selector: "node:selected", style: { "overlay-color": "#3D5AFE", "overlay-opacity": 0.15, "overlay-padding": 8 } },
      { selector: "edge", style: { "width": 1.5, "line-color": "#C6CCDD", "curve-style": "straight" } },
      { selector: "edge[kind='string']", style: { "width": 2.2, "line-color": "#E5383B" } },
      { selector: "edge[kind='imp']", style: { "width": 2, "line-color": "#E5383B", "line-style": "dashed", "line-dash-pattern": [6, 4] } },
    ],
    elements: [{ data: { id: "t", label: e.target, kind: "target", info: `<p>${e.mode === "domain" ? "The domain being investigated." : "The username being followed."}</p>` } }],
    layout: { name: "preset" },
  });
  cy.center();
  cy.on("tap", "node", (ev) => pinCard(ev.target.data()));
  cy.on("tap", (ev) => { if (ev.target === cy) $("#pinCard").hidden = true; });
}

function addNodes(nodes, edges) {
  if (!cy) return;
  const fresh = nodes.filter((n) => cy.getElementById(n.id).empty());
  if (!fresh.length) return;
  const t = cy.getElementById("t").position();
  const added = cy.add(fresh.map((n) => ({ group: "nodes", data: n, position: { x: t.x + (Math.random() - 0.5) * 60, y: t.y + (Math.random() - 0.5) * 60 } })));
  cy.add(edges.filter((e) => cy.getElementById(e.target).nonempty() && cy.getElementById(e.source).nonempty())
    .map((e) => ({ group: "edges", data: { id: `${e.source}>${e.target}`, ...e } })).filter((e) => cy.getElementById(e.data.id).empty()));
  if (!reduceMotion) {
    added.style("opacity", 0);
    added.animate({ style: { opacity: 1 } }, { duration: 500 });
  }
  relayout();
}

/* The board is laid out like a case wall: your own infrastructure fans out across the top,
   lookalike domains to the right, accounts and impostors to the left, email below. */
const GROUP = { sub: "subs", "sub-hot": "subs", more: "subs", ip: "ips", port: "ports", cve: "ports", look: "looks", "look-sus": "looks", acc: "people", imp: "people", "mail-ok": "mail", "mail-bad": "mail" };
const rad = (d) => (d * Math.PI) / 180;
const XS = 1.6; // the board is wide: stretch the wall sideways

function positions() {
  const pos = { t: { x: 0, y: 0 } };
  const by = {};
  cy.nodes().forEach((n) => { const g = GROUP[n.data("kind")]; if (g) (by[g] ||= []).push(n); });
  const arc = (list, from, to, r0, step, rings) => list.forEach((n, i) => {
    const a = list.length === 1 ? (from + to) / 2 : from + ((to - from) * i) / (list.length - 1);
    const r = r0 + (i % rings) * step;
    pos[n.id()] = { x: Math.cos(rad(a)) * r * XS, y: Math.sin(rad(a)) * r, a, r };
  });
  if (S.mode === "handle") {
    arc(by.people || [], -175, 175, 240, 95, 3);
    return pos;
  }
  arc(by.subs || [], -168, -12, 250, 95, 3);
  // servers sit beyond the subdomains that point at them
  const ips = (by.ips || []).map((n) => {
    const angs = n.incomers("node").map((m) => (pos[m.id()]?.a ?? -90));
    return { n, a: angs.length ? angs.reduce((x, y) => x + y, 0) / angs.length : -90 };
  }).sort((x, y) => x.a - y.a).map((o) => o.n);
  arc(ips, -165, -15, 600, 80, 2);
  (by.ports || []).forEach((n) => {
    const parent = n.incomers("node")[0];
    const pp = parent && pos[parent.id()];
    if (!pp) return;
    const sibs = parent.outgoers("node");
    const k = sibs.toArray().findIndex((m) => m.id() === n.id());
    const a = pp.a + (k - (sibs.length - 1) / 2) * 5, r = pp.r + 120;
    pos[n.id()] = { x: Math.cos(rad(a)) * r * XS, y: Math.sin(rad(a)) * r };
  });
  arc(by.looks || [], 2, 80, 260, 100, 3);
  arc(by.people || [], 100, 178, 260, 100, 3);
  arc(by.mail || [], 90, 90, 150, 0, 1);
  return pos;
}

let layoutTimer = null, lastLayout = 0;
function relayout(final = false) {
  clearTimeout(layoutTimer);
  const wait = final ? 0 : Math.max(200, 700 - (Date.now() - lastLayout));
  layoutTimer = setTimeout(() => {
    if (!cy) return;
    lastLayout = Date.now();
    const pos = positions();
    cy.layout({ name: "preset", positions: (n) => pos[n.id()] || { x: 0, y: 0 }, animate: !reduceMotion,
      animationDuration: 650, animationEasing: "ease-out-cubic", fit: true, padding: 40 }).run();
  }, wait);
}

function pinCard(d) {
  const card = $("#pinCard");
  card.innerHTML = `<button class="x" aria-label="Close">×</button><h4>${esc(d.title || d.label)}</h4>${d.info || ""}`;
  card.hidden = false;
  $(".x", card).onclick = () => (card.hidden = true);
}

/* ------------------------------------------------------------ steps → panels + board */
function stepDns(d) {
  renderChecks();
  const bad = !d.DMARC || !d.SPF;
  addNodes([{ id: "mail", label: bad ? "Email: spoofable" : "Email: protected", kind: bad ? "mail-bad" : "mail-ok",
    info: `<p>SPF: ${d.SPF ? esc(d.SPF) : "<b>missing</b>"}</p><p>DMARC: ${d.DMARC ? esc(d.DMARC) : "<b>missing</b>"}</p><p class="muted">${plural(d.MX.length, "mail server")}</p>` }],
    [{ source: "t", target: "mail" }]);
}
function stepWhois() { renderChecks(); }

function renderChecks() {
  const d = S.data.dns, w = S.data.whois;
  const rows = [];
  if (d) {
    const spf = d.SPF;
    rows.push(spf ? (/[+?]all\s*$/.test(spf) ? ["meh", "SPF is weak", spf] : ["ok", "SPF lists who may send mail", spf]) : ["bad", "No SPF record", "Anyone can send mail as this domain."]);
    const dm = d.DMARC;
    rows.push(dm ? (/p=none/i.test(dm) ? ["meh", "DMARC only monitors", dm] : ["ok", "DMARC blocks spoofed mail", dm]) : ["bad", "No DMARC policy", "Spoofed mail from this domain gets delivered."]);
    rows.push(d.MX.length ? ["ok", plural(d.MX.length, "mail server"), d.MX.slice(0, 3).join(", ")] : ["meh", "No mail servers", "This domain doesn't receive email."]);
    rows.push(d.CAA.length ? ["ok", "CAA limits who issues certificates", d.CAA.join(", ")] : ["meh", "No CAA record", "Any certificate authority may issue for it."]);
  }
  if (w) {
    const age = daysSince(w.created);
    rows.push(["ok", age != null ? `Registered ${fmtAge(age)} ago` : "Registered", `${w.registrar || "Unknown registrar"}${w.created ? ", since " + w.created.slice(0, 10) : ""}`]);
    const left = w.expires ? -daysSince(w.expires) : null;
    if (left != null) rows.push([left < 45 ? "bad" : "ok", left < 45 ? `Expires in ${left} days` : `Paid up until ${w.expires.slice(0, 10)}`, left < 45 ? "If it lapses, anyone can buy it." : ""]);
    const locked = (w.status || []).some((s) => /transfer.*prohibited/i.test(s));
    rows.push(locked ? ["ok", "Locked against transfer", ""] : ["meh", "No transfer lock", "Easier to hijack through the registrar."]);
  }
  const icon = { ok: "✓", bad: "!", meh: "~" };
  const clip = (t) => (t && t.length > 140 ? t.slice(0, 140) + "…" : t);
  $("#emailChecks").innerHTML = rows.map(([k, t, s]) => `<li><span class="tick ${k}">${icon[k]}</span><span>${esc(t)}${s ? `<small title="${esc(s)}">${esc(clip(s))}</small>` : ""}</span></li>`).join("");
}

function stepWeb(d) {
  const hdr = Object.entries(d.headers).map(([k, ok]) => `<li class="${ok ? "" : "no"}">${esc(k)}</li>`).join("");
  $("#webBox").innerHTML = `<div class="grade g-${d.grade}">${d.grade}</div>
    <div><p style="margin:0 0 8px">${d.title ? `“${esc(d.title)}”` : "No page title"}<br><span class="muted small">${d.https ? "Served over HTTPS" : "No HTTPS"}${d.server ? ", server " + esc(d.server) : ""}${d.powered_by ? ", " + esc(d.powered_by) : ""}</span></p>
    <ul class="hdrs">${hdr}</ul></div>`;
}

function stepSubs(d) {
  const resolved = d.resolved || {};
  const hot = new Set(d.interesting);
  $("#subCount").textContent = d.names.length ? `${d.names.length} found` : "";
  const sorted = [...d.names].sort((a, b) => (hot.has(b) - hot.has(a)) || a.localeCompare(b));
  $("#subList").innerHTML = sorted.slice(0, 300).map((n) => `<li class="${hot.has(n) ? "hot" : ""} ${resolved[n] && !resolved[n].length ? "dead" : ""}">${esc(n)}</li>`).join("")
    || `<li>None found in certificate logs.</li>`;

  const live = sorted.filter((n) => resolved[n]?.length);
  const shown = [...live.filter((n) => hot.has(n)).slice(0, 10), ...live.filter((n) => !hot.has(n)).slice(0, 4)];
  S.shownSubs = new Set(shown);
  const short = (n) => n.slice(0, -(S.target.length + 1));
  const nodes = shown.map((n) => ({ id: "s:" + n, label: short(n), title: n, kind: hot.has(n) ? "sub-hot" : "sub",
    info: `<p>${hot.has(n) ? "The name hints at a test, admin or internal system." : "A public subdomain."}</p><p class="muted">Resolves to ${esc(resolved[n].join(", "))}</p>` }));
  const edges = shown.map((n) => ({ source: "t", target: "s:" + n }));
  const extra = d.names.length - shown.length;
  if (extra > 0) {
    nodes.push({ id: "more", label: `+${extra} more`, kind: "more", info: `<p>${extra} more subdomains are listed in the Exposure tab.</p>` });
    edges.push({ source: "t", target: "more" });
  }
  addNodes(nodes, edges);
}

function stepHosts(d) {
  renderHosts(d);
  // Hang servers off the subdomains already on the board.
  const nodes = [], edges = [];
  let n = 0;
  for (const [ip, h] of Object.entries(d)) {
    const owners = h.names || [];
    if (n >= 12) break;
    const links = owners.filter((o) => o === S.target || S.shownSubs?.has(o));
    if (!links.length) continue;
    n++;
    const risky = h.ports.filter((p) => RISKY[p]);
    nodes.push({ id: "ip:" + ip, label: `${ip}${h.cc ? " " + h.cc : ""}`, kind: "ip",
      info: `<p>${esc(h.org || "Unknown network")}${h.city ? ", " + esc(h.city) : ""}${h.country ? ", " + esc(h.country) : ""}</p><p>Open ports: ${h.ports.length ? h.ports.join(", ") : "none indexed"}</p>${h.vulns.length ? `<p class="cve">${h.vulns.length} known CVEs</p>` : ""}` });
    links.forEach((o) => edges.push({ source: o === S.target ? "t" : "s:" + o, target: "ip:" + ip }));
    risky.slice(0, 3).forEach((p) => {
      nodes.push({ id: `p:${ip}:${p}`, label: `${RISKY[p]} :${p}`, kind: "port", info: `<p>${RISKY[p]} (port ${p}) is reachable from the internet on ${ip}. Services like this usually belong behind a VPN.</p>` });
      edges.push({ source: "ip:" + ip, target: `p:${ip}:${p}` });
    });
    if (h.vulns.length) {
      nodes.push({ id: `v:${ip}`, label: plural(h.vulns.length, "CVE"), kind: "cve", info: `<p>Shodan lists these known vulnerabilities:</p><p>${h.vulns.slice(0, 12).map(esc).join(", ")}</p>` });
      edges.push({ source: "ip:" + ip, target: `v:${ip}` });
    }
  }
  addNodes(nodes, edges);
}

function renderHosts(d) {
  const rows = Object.entries(d);
  $("#hostTable").innerHTML = rows.length ? `<thead><tr><th>Server</th><th>Where</th><th>Open ports</th><th>Known CVEs</th></tr></thead><tbody>` +
    rows.map(([ip, h], i) => `<tr${i >= 8 ? ' class="extra" hidden' : ""}><td><b>${esc(ip)}</b><br><span class="muted small">${esc((h.names || []).slice(0, 2).join(", "))}</span></td>
      <td>${esc([h.city, h.country].filter(Boolean).join(", ") || "Unknown")}<br><span class="muted small">${esc(h.org || "")}</span></td>
      <td>${h.ports.map((p) => `<span class="port ${RISKY[p] ? "risky" : ""}">${p}</span>`).join("") || '<span class="muted">none indexed</span>'}</td>
      <td>${h.vulns.length ? `<span class="cve">${h.vulns.length}</span>` : "0"}</td></tr>`).join("") + "</tbody>"
    : `<tbody><tr><td class="muted">No servers to show.</td></tr></tbody>`;
  $("#hostMore").hidden = rows.length <= 8;
  $("#hostMore").textContent = `Show all ${rows.length} servers`;

  if (!map && typeof L !== "undefined") {
    map = L.map("map", { scrollWheelZoom: false, worldCopyJump: true }).setView([25, 10], 2);
    L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}", {
      attribution: "Tiles &copy; Esri", maxZoom: 12,
    }).addTo(map);
  }
  S.mapPoints = [];
  if (!map) return;
  map.eachLayer((l) => { if (l instanceof L.CircleMarker) map.removeLayer(l); });
  for (const [ip, h] of rows) {
    if (h.lat == null) continue;
    const bad = h.vulns.length || h.ports.some((p) => RISKY[p]);
    L.circleMarker([h.lat, h.lon], { radius: 8, color: "#fff", weight: 2, fillColor: bad ? "#E5383B" : "#3D5AFE", fillOpacity: 0.9 })
      .bindPopup(`<b>${esc(ip)}</b><br>${esc(h.org || "")}<br>${esc([h.city, h.country].filter(Boolean).join(", "))}`).addTo(map);
    S.mapPoints.push([h.lat, h.lon]);
  }
  fitMap();
}
function fitMap() {
  if (map && S?.mapPoints?.length) map.fitBounds(S.mapPoints, { padding: [30, 30], maxZoom: 5 });
}

function stepHistory(d) {
  $("#historyBox").innerHTML = `<p style="margin:0"><span class="big-num">${d.total.toLocaleString()}</span> <span class="muted">archived URLs${d.first_year ? ", the oldest from " + d.first_year : ""}</span></p>` +
    (d.juicy.length ? `<p class="small" style="margin:14px 0 0">These look like files or pages that shouldn't be public:</p><ul class="juicy">${d.juicy.map((j) =>
      `<li><span>${j.year}</span><a href="https://web.archive.org/web/${j.year}/${encodeURI(j.url)}" target="_blank" rel="noopener">${esc(j.url.replace(/^https?:\/\//, ""))}</a></li>`).join("")}</ul>`
      : `<p class="muted small">Nothing sensitive-looking in the archive.</p>`);
}

/* ------------------------------------------------------------ lookalikes */
const VCLASS = { "Likely phishing": "v-phish", "Suspicious": "v-sus", "Brand-owned": "v-owned", "Parked": "v-parked", "Registered": "v-reg" };

function addLook(c) {
  S.looks.set(c.domain, c);
  $("#lookCount").textContent = S.looks.size;
  renderLooks();
  if ((c.verdict === "Likely phishing" || c.verdict === "Suspicious") && S.graphLooks < 14) {
    S.graphLooks++;
    addNodes([{ id: "l:" + c.domain, label: c.display, kind: c.verdict === "Likely phishing" ? "look" : "look-sus", info: lookInfo(c) }],
      [{ source: "t", target: "l:" + c.domain, kind: "string" }]);
  }
}
function lookInfo(c) {
  return `<p><b>${esc(c.verdict)}</b>, threat score ${c.score}/100</p><p class="muted">${esc(c.kind_label)}${c.display !== c.domain ? ` (really ${esc(c.domain)})` : ""}</p>` +
    (c.reasons.length ? `<p>${c.reasons.map(esc).join(". ")}.</p>` : "") + (c.title ? `<p class="muted">Page title: “${esc(c.title)}”</p>` : "");
}
function stepLooks(d) { d.registered.forEach((c) => S.looks.set(c.domain, c)); $("#lookCount").textContent = S.looks.size || ""; renderLooks(); }

$("#lookFilters").addEventListener("click", (e) => {
  const b = e.target.closest("[data-f]");
  if (!b || !S) return;
  S.filter = b.dataset.f;
  $$("#lookFilters .chip-btn").forEach((x) => x.classList.toggle("is-on", x === b));
  renderLooks();
});

let lookRender = null;
function renderLooks() {
  cancelAnimationFrame(lookRender);
  lookRender = requestAnimationFrame(() => {
    const prev = new Set($$("#lookList .look").map((li) => li.dataset.d));
    const rows = [...S.looks.values()].filter((c) => S.filter === "all" || c.verdict === S.filter).sort((a, b) => b.score - a.score);
    $("#lookList").innerHTML = rows.map((c) => `<li class="look ${VCLASS[c.verdict] || ""}" data-d="${esc(c.domain)}" style="${prev.has(c.domain) ? "animation:none" : ""}">
      <div class="look-score" title="Threat score">${c.score}</div>
      <div><div class="look-name">${esc(c.display)}<small>${esc(c.kind_label)}</small></div>
        <ul class="look-why">${c.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}${c.redirects_to ? `<li>Redirects to ${esc(c.redirects_to)}</li>` : ""}</ul></div>
      <span class="pill">${esc(c.verdict)}</span></li>`).join("");
    $("#lookEmpty").hidden = rows.length > 0;
  });
}

/* ------------------------------------------------------------ accounts */
function accTile(a, imp) {
  const host = new URL(a.url).hostname;
  return `<li><a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer"><img src="https://www.google.com/s2/favicons?domain=${esc(host)}&sz=64" alt="" loading="lazy">
    <span class="acc-text"><b>${esc(imp ? a.handle : a.site)}</b><small>${esc(imp ? a.site : host)}</small></span></a></li>`;
}

function addAccount(a) {
  const imp = a.role === "variant";
  (imp ? S.imp : S.acc).push(a);
  const list = imp ? $("#impList") : $("#accList");
  list.insertAdjacentHTML("beforeend", accTile(a, imp));
  if (imp) $("#impBox").hidden = false;
  $("#accCount").textContent = S.acc.length + S.imp.length;

  const cap = S.mode === "handle" ? 36 : 8;
  if (imp && S.graphImp < 10) {
    S.graphImp++;
    addNodes([{ id: `a:${a.site}:${a.handle}`, label: `${a.handle}\n${a.site}`, title: `${a.handle} on ${a.site}`, kind: "imp",
      info: `<p>A handle one step from “${esc(S.brand)}”. Could be a fan, could be a fake support account.</p><p><a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">Open profile</a></p>` }],
      [{ source: "t", target: `a:${a.site}:${a.handle}`, kind: "imp" }]);
  } else if (!imp && (S.mode === "handle" || SOCIAL.has(a.site)) && S.graphAcc < cap) {
    S.graphAcc++;
    addNodes([{ id: `a:${a.site}`, label: a.site, kind: "acc",
      info: `<p>“${esc(a.handle)}” exists on ${esc(a.site)}.</p><p><a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">Open profile</a></p>` }],
      [{ source: "t", target: `a:${a.site}` }]);
  }
}

function stepAccounts(d) {
  // On a replayed scan, items may have arrived already; make the lists exactly match the final data.
  S.acc = d.accounts; S.imp = d.impersonators;
  $("#accList").innerHTML = d.accounts.map((a) => accTile(a, false)).join("") || `<li class="muted">Not found on any of the ${d.sites_checked} sites checked.</li>`;
  $("#impList").innerHTML = d.impersonators.map((a) => accTile(a, true)).join("");
  $("#impBox").hidden = !d.impersonators.length;
  $("#accCount").textContent = d.accounts.length + d.impersonators.length || "";
}

/* ------------------------------------------------------------ report */
function renderReport(r) {
  const when = new Date(r.scanned_at * 1000).toLocaleString();
  const f = r.findings.map((x) => `<li><b>${esc(x.title)}</b> (${x.severity}). ${esc(x.detail)}</li>`).join("") || "<li>No findings.</li>";
  let body = `<h1>Sleuth report: ${esc(r.target)}</h1><p class="muted">Scanned ${esc(when)}. Passive, open-source data only.</p>
    <div class="rep-score"><strong>${r.score}</strong><div>out of 100<br><span class="muted">${esc(r.band)} exposure (higher means more exposed)</span></div></div>
    <h2>Findings</h2><ul>${f}</ul>`;
  if (r.mode === "domain") {
    const d = r.dns || {}, w = r.whois || {}, web = r.web || {}, subs = r.subdomains || { names: [], interesting: [] };
    body += `<h2>Domain and email</h2><table>
      <tr><th>Registrar</th><td>${esc(w.registrar || "unknown")}</td></tr>
      <tr><th>Created</th><td>${esc((w.created || "").slice(0, 10) || "unknown")}</td></tr>
      <tr><th>Expires</th><td>${esc((w.expires || "").slice(0, 10) || "unknown")}</td></tr>
      <tr><th>SPF</th><td>${esc(d.SPF || "missing")}</td></tr>
      <tr><th>DMARC</th><td>${esc(d.DMARC || "missing")}</td></tr>
      <tr><th>Website headers</th><td>${web.grade ? "Grade " + esc(web.grade) : "no response"}</td></tr></table>
      <h2>Subdomains</h2><p>${subs.names.length} found in certificate logs. Revealing names: ${esc(subs.interesting.slice(0, 25).join(", ") || "none")}.</p>`;
    const hosts = Object.entries(r.hosts || {});
    if (hosts.length) body += `<h2>Servers</h2><table><tr><th>IP</th><th>Location</th><th>Ports</th><th>CVEs</th></tr>${hosts.map(([ip, h]) =>
      `<tr><td>${esc(ip)}</td><td>${esc([h.city, h.country].filter(Boolean).join(", "))}</td><td>${h.ports.join(", ")}</td><td>${h.vulns.length}</td></tr>`).join("")}</table>`;
    const looks = (r.lookalikes?.registered || []).filter((c) => c.verdict !== "Brand-owned").slice(0, 25);
    body += `<h2>Lookalike domains</h2><p>${r.lookalikes?.checked || 0} variants generated, ${r.lookalikes?.registered?.length || 0} registered.</p>` +
      (looks.length ? `<table><tr><th>Domain</th><th>Type</th><th>Score</th><th>Verdict</th></tr>${looks.map((c) =>
        `<tr><td>${esc(c.display)}</td><td>${esc(c.kind_label)}</td><td>${c.score}</td><td>${esc(c.verdict)}</td></tr>`).join("")}</table>` : "");
  }
  const a = r.accounts || { accounts: [], impersonators: [], sites_checked: 0 };
  body += `<h2>Accounts</h2><p>“${esc(r.brand)}” exists on ${a.accounts.length} of ${a.sites_checked} sites checked.</p>` +
    (a.impersonators.length ? `<p><b>Possible impostors:</b> ${a.impersonators.map((i) => esc(`${i.handle} (${i.site})`)).join(", ")}.</p>` : "");
  body += `<h2>Method</h2><p class="small">Sources: DNS over HTTPS, RDAP, Certspotter, HackerTarget and crt.sh certificate logs, Shodan InternetDB, ip-api, the Wayback Machine, and Sherlock's site rules. Nothing was logged into or attacked.</p>`;
  $("#report").innerHTML = body;
}
$("#printBtn").addEventListener("click", () => window.print());
$("#jsonBtn").addEventListener("click", () => {
  if (!S?.result) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(S.result, null, 2)], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: `sleuth-${S.target}.json` });
  a.click();
  URL.revokeObjectURL(url);
});
$("#rescanBtn").addEventListener("click", () => S && startScan(S.target, true));

/* ------------------------------------------------------------ helpers */
function daysSince(iso) {
  if (!iso) return null;
  const t = Date.parse(iso);
  return isNaN(t) ? null : Math.floor((Date.now() - t) / 864e5);
}
function fmtAge(d) { return d >= 730 ? `${Math.floor(d / 365)} years` : d >= 60 ? `${Math.floor(d / 30)} months` : plural(d, "day"); }

/* deep links: /?q=tesla.com starts straight away */
const initial = new URLSearchParams(location.search).get("q");
if (initial) { $("#q").value = initial; startScan(initial); }

$("#hostMore").addEventListener("click", (e) => {
  $$("#hostTable tr.extra").forEach((tr) => (tr.hidden = false));
  e.currentTarget.hidden = true;
});
