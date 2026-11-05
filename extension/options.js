const ext = (typeof browser !== "undefined") ? browser : chrome;
const DEFAULTS = { base: "http://127.0.0.1:8777", token: "" };

function load() {
  ext.storage.local.get(DEFAULTS, (c) => {
    document.getElementById("base").value = c.base;
    document.getElementById("token").value = c.token;
  });
}

document.getElementById("save").addEventListener("click", () => {
  const base = document.getElementById("base").value.trim() || DEFAULTS.base;
  const token = document.getElementById("token").value.trim();
  ext.storage.local.set({ base, token }, () => {
    document.getElementById("msg").textContent = "saved.";
  });
});

document.getElementById("test").addEventListener("click", async () => {
  const base = document.getElementById("base").value.trim() || DEFAULTS.base;
  const msg = document.getElementById("msg");
  msg.textContent = "testing…";
  try {
    const r = await fetch(base.replace(/\/$/, "") + "/health");
    const d = await r.json();
    msg.textContent = `OK — r3dProxy ${d.version} (proxy ${d.proxy_running ? "running" : "stopped"})`;
  } catch (e) {
    msg.textContent = "unreachable — is r3dProxy running? (`python -m r3dproxy.cli serve`)";
  }
});

load();
