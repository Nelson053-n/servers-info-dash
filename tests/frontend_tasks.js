// Закладка «Задачи»: грузит index.html + app.js + views.js в jsdom с подставными
// /api/projects и /api/metrics и проверяет, что открытые пункты видны, а закрытые на сутки уходят вниз.
//   npm i --no-save jsdom@24 && node tests/frontend_tasks.js
const { JSDOM, VirtualConsole } = require("jsdom");
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "..", "app", "static") + path.sep;
const read = (f) => fs.readFileSync(root + f, "utf8");

const overview = {
  ready: true, refresh_sec: 300, generated_at: new Date().toISOString(), server_groups: [], tls: [],
  projects: [{ id: "otpuska", name: "График отпусков", stage: "", state: "warn", check: null, tls: null, analytics: null,
    issues: [{ severity: "warn", text: "Просрочено задач согласования: 19" }] }],
};
let html = read("index.html")
  .replace(/<script src="\/static\/app\.js[^"]*"><\/script>/, "<script>" + read("app.js") + "</script>")
  .replace(/<script src="\/static\/views\.js[^"]*"><\/script>/, "<script>" + read("views.js") + "</script>");
const errors = [];
const vc = new VirtualConsole();
vc.on("jsdomError", (e) => errors.push(String(e.message || e)));
vc.on("error", (...a) => errors.push(a.join(" ")));
const dom = new JSDOM(html, { runScripts: "dangerously", url: "https://dash.test/#tasks", virtualConsole: vc,
  beforeParse(w) {
    w.fetch = async (url) => ({ ok: true, status: 200, headers: new Map(), json: async () => {
      const u = String(url);
      if (u.includes("/api/auth/status")) return { has_password: true, logged_in: true };
      if (u.startsWith("/api/projects")) return overview;
      return { servers: [], generated_at: null };
    } });
    w.localStorage.clear();
  } });
setTimeout(() => {
  const d = dom.window.document;
  const view = d.getElementById("tasksView");
  const text = view.textContent;
  const checks = [
    ["страница «Задачи» открыта", !view.classList.contains("hidden")],
    ["пункт проекта показан", text.includes("Просрочено задач согласования: 19")],
    ["группа «Проверить»", text.includes("Проверить")],
    ["счётчик в меню", d.getElementById("cntTasks").textContent === "1"],
  ];
  // закрыть пункт → он уходит в «Закрыто на сутки», счётчики и статус проекта сбрасываются
  view.querySelector(".ins-acts .ghost").click();
  const after = d.getElementById("tasksView").textContent;
  checks.push(["после «Закрыть на сутки» пункт в блоке «Закрыто на сутки»", after.includes("Закрыто на сутки") && after.includes("Вернуть все закрытые")]);
  checks.push(["счётчик после закрытия пуст", d.getElementById("cntTasks").textContent === ""]);
  checks.push(["проект без открытых замечаний в меню снова «ok»", d.querySelector("#railProjects .sdot").classList.contains("ok")]);
  d.querySelector("#tasksView .attn2:last-of-type .ghost").click();
  checks.push(["«Вернуть все закрытые» возвращает пункт", d.getElementById("cntTasks").textContent === "1" && d.querySelector("#railProjects .sdot").classList.contains("warn")]);
  let bad = errors.length;
  console.log("errors:", errors.length ? errors : "none");
  checks.forEach(([n, ok]) => { console.log((ok ? "ok   " : "FAIL ") + n); if (!ok) bad++; });
  process.exit(bad ? 1 : 0);
}, 800);
