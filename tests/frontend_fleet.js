// Лента парка на обзоре: число зажжённых сегментов = CPU/5 и значения обновляются без перезагрузки страницы
//   npm i --no-save jsdom@24 && node tests/frontend_fleet.js
const { JSDOM, VirtualConsole } = require("jsdom");
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "..", "app", "static") + path.sep;
const read = (f) => fs.readFileSync(root + f, "utf8");
const srv = (cpu, extra) => Object.assign({ name: "Россия вход 3", host: "h", status: "up", cpu_percent: cpu, disk_total_gb: 100, disk_free_gb: 60, ram_total_gb: 8, ram_used_gb: 2 }, extra);
let cpu = 55;
const overview = { ready: true, refresh_sec: 300, generated_at: new Date().toISOString(), server_groups: [], tls: [], projects: [] };
const html = read("index.html")
  .replace(/<script src="\/static\/app\.js[^"]*"><\/script>/, "<script>" + read("app.js") + "</script>")
  .replace(/<script src="\/static\/views\.js[^"]*"><\/script>/, "<script>" + read("views.js") + "</script>");
const errors = [];
const vc = new VirtualConsole();
vc.on("jsdomError", (e) => errors.push(String(e.message || e)));
const dom = new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true, url: "https://dash.test/#overview", virtualConsole: vc,
  beforeParse(w) {
    w.fetch = async (url) => ({ ok: true, status: 200, headers: new Map(), json: async () => {
      const u = String(url);
      if (u.includes("/api/auth/status")) return { has_password: true, logged_in: true };
      if (u.startsWith("/api/projects")) return overview;
      return { servers: [srv(cpu), srv(0, { name: "Простаивает" })], refresh_interval_sec: 3, generated_at: null };
    } });
    w.localStorage.clear();
  } });
const tile = (name) => [...dom.window.document.querySelectorAll("#overviewView .fc")].find((t) => t.textContent.includes(name));
const lit = (t) => t.querySelectorAll(".fc-meter i.on").length;
setTimeout(() => {
  const checks = [];
  const t = tile("Россия вход 3");
  checks.push(["55 % = 11 сегментов", !!t && lit(t) === 11 && t.textContent.includes("CPU 55")]);
  checks.push(["0 % = ни одного сегмента", lit(tile("Простаивает")) === 0]);
  cpu = 20;
  setTimeout(() => {
    const t2 = tile("Россия вход 3");
    checks.push(["после смены данных лента показывает 20 % = 4 сегмента (без перезагрузки)", !!t2 && lit(t2) === 4 && t2.textContent.includes("CPU 20")]);
    let bad = errors.length;
    console.log("errors:", errors.length ? errors : "none");
    checks.forEach(([n, ok]) => { console.log((ok ? "ok   " : "FAIL ") + n); if (!ok) bad++; });
    process.exit(bad ? 1 : 0);
  }, 4500);
}, 900);
