const ext = (typeof browser !== "undefined") ? browser : chrome;

const DEFAULTS = { base: "http://127.0.0.1:8777", token: "" };

function getCfg() {
  return new Promise((resolve) => {
    ext.storage.local.get(DEFAULTS, (c) => resolve(c));
  });
}

async function api(path, method = "GET", body = null) {
  const cfg = await getCfg();
  const headers = { "X-r3d-Token": cfg.token };
  if (body) headers["Content-Type"] = "application/json";
  const res = await fetch(cfg.base.replace(/\/$/, "") + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

function out(html) { document.getElementById("out").innerHTML = html; }
function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function rows(items, fmt) {
  if (!items || !items.length) return "<span class='muted'>nothing found</span>";
  return items.map((i) => `<div class="row">${fmt(i)}</div>`).join("");
}

let currentTab = null;

async function init() {
  // status
  try { await api("/health"); dot("ok"); } catch (e) { dot("bad"); }
  // current tab
  const tabs = await ext.tabs.query({ active: true, currentWindow: true });
  currentTab = tabs[0];
  const u = new URL(currentTab.url);
  document.getElementById("host").textContent = u.host + u.pathname;
  // intercept state
  try {
    const r = await api("/intercept");
    setIntercept(r.enabled);
  } catch (e) {}
}

function dot(cls) {
  const d = document.getElementById("status");
  d.className = "dot " + cls;
  d.title = cls === "ok" ? "API connected" : "API unreachable — run r3dProxy or `r3dproxy.cli serve`";
}
function setIntercept(on) {
  document.getElementById("intercept").textContent = "Intercept: " + (on ? "ON" : "off");
}

async function grabPageText() {
  const [res] = await ext.scripting.executeScript({
    target: { tabId: currentTab.id },
    func: () => document.documentElement.outerHTML,
  });
  return res.result || "";
}

const actions = {
  async scope() {
    const host = new URL(currentTab.url).host;
    const r = await api("/scope", "POST", { action: "add", host });
    out(`Scope now:\n${r.scope.map(esc).join("\n")}`);
  },
  async intercept() {
    const cur = document.getElementById("intercept").textContent.includes("ON");
    const r = await api("/intercept", "POST", { enabled: !cur });
    setIntercept(r.enabled);
    out(`Interception ${r.enabled ? "ON — edit/forward in the r3dProxy app" : "off"}.`);
  },
  async secrets() {
    out("scanning page for secrets…");
    const text = await grabPageText();
    const r = await api("/secrets", "POST", { text });
    out("<b>Secrets</b>\n" + rows(r.hits, (h) =>
      `<span class="${esc(h.severity)}">[${esc(h.severity)}]</span> ${esc(h.name)}: ${esc(h.match)}`));
  },
  async passive() {
    out("running passive audit (server-side fetch)…");
    const r = await api("/passive", "POST", { url: currentTab.url });
    out("<b>Passive issues</b>\n" + rows(r.issues, (i) =>
      `<span class="${esc(i.severity)}">[${esc(i.severity)}]</span> ${esc(i.name)}`));
  },
  async subs() {
    const host = new URL(currentTab.url).host;
    const domain = host.split(".").slice(-2).join(".");
    out(`running subfinder on ${esc(domain)}… (needs subfinder installed)`);
    try {
      const r = await api("/run", "POST", { tool: "subfinder", domain, timeout: 90 });
      out(`<b>Subdomains (${esc(domain)})</b>\n` + esc(r.output || "(none)"));
    } catch (e) { out("error: " + esc(e.message)); }
  },
  scan() {
    const u = new URL(currentTab.url);
    const params = [...u.searchParams.keys()];
    const box = document.getElementById("params");
    if (!params.length) { out("No query parameters on this URL to scan."); return; }
    box.classList.remove("hidden");
    box.innerHTML = "";
    params.forEach((p) => {
      const b = document.createElement("button");
      b.textContent = p;
      b.onclick = () => runScan(p);
      box.appendChild(b);
    });
    out("Pick a parameter above to scan.");
  },
};

async function runScan(param) {
  out(`scanning param '${esc(param)}'…`);
  try {
    const r = await api("/scan", "POST", { url: currentTab.url, param });
    out(`<b>Scan: ${esc(param)}</b>\n` + rows(r.findings, (f) =>
      `<span class="${esc(f.confidence)}">[${esc(f.confidence)}]</span> ${esc(f.name)} — ${esc(f.evidence)}`));
  } catch (e) { out("error: " + esc(e.message)); }
}

document.querySelectorAll("button[data-act]").forEach((b) => {
  b.addEventListener("click", async () => {
    try { await actions[b.dataset.act](); }
    catch (e) { out("error: " + esc(e.message) + "\n\nIs r3dProxy running? Start the app or `python -m r3dproxy.cli serve`, and set the token in settings."); dot("bad"); }
  });
});
document.getElementById("opts").addEventListener("click", (e) => {
  e.preventDefault(); ext.runtime.openOptionsPage();
});

init();
