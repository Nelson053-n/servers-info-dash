// Обзор: под графиком дохода проекта — сумма с начала текущего года.
//   npm i --no-save jsdom@24 && node tests/frontend_money.js
const { JSDOM, VirtualConsole } = require("jsdom");
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "..", "app", "static") + path.sep;
const read = (f) => fs.readFileSync(root + f, "utf8");

const year = new Date().getFullYear();
const kpi = { id: "revenue_month", label: "Доход с 1", value: 5, unit: "₽" };
const detail = { id: "flux", name: "FluxRadar", analytics: { kpis: [kpi], tables: [], matrices: [], charts: [
  { id: "revenue_monthly", kind: "bar", unit: "₽", series: [{ name: "₽", points: [[`${year - 1}-12`, 1000], [`${year}-01`, 100], [`${year}-02`, 250]] }] }] } };
const overview = { ready: true, refresh_sec: 300, generated_at: new Date().toISOString(), server_groups: [], tls: [],
  projects: [{ id: "flux", name: "FluxRadar", stage: "", state: "ok", check: null, tls: null, issues: [], analytics: { kpis: [kpi], has_revenue_month: true } }] };
const html = read("index.html")
  .replace(/<script src="\/static\/app\.js[^"]*"><\/script>/, "<script>" + read("app.js") + "</script>")
  .replace(/<script src="\/static\/views\.js[^"]*"><\/script>/, "<script>" + read("views.js") + "</script>");
const errors = [];
const vc = new VirtualConsole();
vc.on("jsdomError", (e) => errors.push(String(e.message || e)));
const dom = new JSDOM(html, { runScripts: "dangerously", url: "https://dash.test/#overview", virtualConsole: vc, pretendToBeVisual: true,
  beforeParse(w) {
    w.fetch = async (url) => ({ ok: true, status: 200, headers: new Map(), json: async () => {
      const u = String(url);
      if (u.includes("/api/auth/status")) return { has_password: true, logged_in: true };
      if (u.startsWith("/api/projects/flux")) return detail;
      if (u.startsWith("/api/projects")) return overview;
      return { servers: [], generated_at: null };
    } });
    w.localStorage.clear();
  } });
setTimeout(() => {
  const ytd = dom.window.document.querySelector("#overviewView .money-ytd");
  const txt = ytd ? ytd.textContent.replace(/\s/g, "") : "";
  const checks = [
    ["строка «С начала года» есть", !!ytd],
    ["сумма только за текущий год (350, декабрь прошлого года не входит)", txt.includes("350")],
  ];
  let bad = errors.length;
  console.log("errors:", errors.length ? errors : "none");
  checks.forEach(([n, ok]) => { console.log((ok ? "ok   " : "FAIL ") + n); if (!ok) bad++; });
  process.exit(bad ? 1 : 0);
}, 800);
