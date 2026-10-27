// Страница проекта: сортировка таблиц по клику на заголовок, красная подсветка блокировок,
// закрытие замечания на сутки (на странице проекта и в статусе проекта).
//   npm i --no-save jsdom@24 && node tests/frontend_tables.js
const { JSDOM, VirtualConsole } = require("jsdom");
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "..", "app", "static") + path.sep;
const read = (f) => fs.readFileSync(root + f, "utf8");

const issues = [{ severity: "warn", text: "ТСПУ блокирует 2 ноды" }];
const detail = { id: "vpn", name: "VPN", stage: "", state: "warn", check: null, tls: null, issues,
  analytics: { kpis: [], charts: [], matrices: [], tables: [{ id: "nodes", title: "Ноды", columns: [
    { key: "node", label: "Нода" }, { key: "online", label: "Онлайн", num: true },
    { key: "tspu", label: "ТСПУ-блок" }, { key: "rf", label: "Блок из РФ (флаг)" }, { key: "st", label: "Статус", state: true }],
  rows: [
    { node: "Латвия", online: 3, tspu: "нет", rf: "нет", st: "ok" },
    { node: "Швеция", online: 0, tspu: "да", rf: "да", st: "warn" },
    { node: "Россия (вход)", online: 74, tspu: "нет", rf: "нет", st: "ok" },
    { node: "Казахстан", online: 5, tspu: "нет", rf: "нет", st: "ok" }] }] } };
const overview = { ready: true, refresh_sec: 300, generated_at: new Date().toISOString(), server_groups: [], tls: [],
  projects: [{ id: "vpn", name: "VPN", stage: "", state: "warn", check: null, tls: null, analytics: null, issues }] };

let html = read("index.html")
  .replace(/<script src="\/static\/app\.js[^"]*"><\/script>/, "<script>" + read("app.js") + "</script>")
  .replace(/<script src="\/static\/views\.js[^"]*"><\/script>/, "<script>" + read("views.js") + "</script>");
const errors = [];
const vc = new VirtualConsole();
vc.on("jsdomError", (e) => errors.push(String(e.message || e)));
vc.on("error", (...a) => errors.push(a.join(" ")));
const dom = new JSDOM(html, { runScripts: "dangerously", url: "https://dash.test/#projects/vpn", virtualConsole: vc,
  beforeParse(w) {
    w.fetch = async (url) => ({ ok: true, status: 200, headers: new Map(), json: async () => {
      const u = String(url);
      if (u.includes("/api/auth/status")) return { has_password: true, logged_in: true };
      if (u.startsWith("/api/projects/vpn")) return JSON.parse(JSON.stringify(detail));
      if (u.startsWith("/api/projects")) return JSON.parse(JSON.stringify(overview));
      return { servers: [], generated_at: null };
    } });
    w.localStorage.clear();
  } });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  await wait(900);
  const d = dom.window.document, checks = [];
  const names = () => [...d.querySelectorAll("#projectsView .ptable tbody tr")].map((tr) => tr.cells[0].textContent);
  const th = (label) => [...d.querySelectorAll("#projectsView .ptable th")].find((x) => x.textContent.startsWith(label));
  checks.push(["таблица нод показана", names().length === 4]);
  checks.push(["блокированная нода: строка подсвечена", d.querySelectorAll("#projectsView .ptable tr.blk").length === 1 && d.querySelector("#projectsView tr.blk td").textContent === "Швеция"]);
  checks.push(["ячейки «да» в колонках «блок» красные, «нет» — нет", d.querySelectorAll("#projectsView td.blocked").length === 2]);
  th("Онлайн").click();
  checks.push(["сортировка по числу по возрастанию", names().join() === "Швеция,Латвия,Казахстан,Россия (вход)"]);
  th("Онлайн").click();
  checks.push(["повторный клик — по убыванию", names().join() === "Россия (вход),Казахстан,Латвия,Швеция"]);
  th("Нода").click();
  checks.push(["сортировка строк по алфавиту", names().join() === "Казахстан,Латвия,Россия (вход),Швеция"]);
  checks.push(["у заголовка aria-sort", th("Нода").getAttribute("aria-sort") === "ascending" && !th("Онлайн").getAttribute("aria-sort")]);
  th("Статус").click();
  checks.push(["колонка статуса: сначала «внимание»", names()[0] === "Швеция"]);
  // замечание: закрыть на странице проекта
  const issue = () => d.querySelectorAll("#projectsView .issue:not(.closed)").length;
  checks.push(["замечание показано", issue() === 1 && d.querySelector("#projectsView .chip").textContent.includes("замечания")]);
  d.querySelector("#projectsView .issue .ghost").click();
  await wait(300);
  checks.push(["после закрытия замечания на странице нет", issue() === 0]);
  checks.push(["статус проекта «работает»", d.querySelector("#projectsView .chip").textContent.includes("работает")]);
  checks.push(["в «Закрыто на сутки» оно есть", d.querySelector("#projectsView .issue-closed").textContent.includes("ТСПУ блокирует")]);
  checks.push(["точка проекта в меню зелёная", d.querySelector("#railProjects .sdot").classList.contains("ok")]);
  d.querySelector("#projectsView .issue-closed .ghost").click();
  await wait(300);
  checks.push(["«Вернуть» возвращает замечание", issue() === 1 && d.querySelector("#railProjects .sdot").classList.contains("warn")]);
  let bad = errors.length;
  console.log("errors:", errors.length ? errors : "none");
  checks.forEach(([n, ok]) => { console.log((ok ? "ok   " : "FAIL ") + n); if (!ok) bad++; });
  process.exit(bad ? 1 : 0);
})();
