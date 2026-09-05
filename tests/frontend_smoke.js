// Loads index.html + app.js in jsdom and fails on any runtime error — the
// check a plain `node --check` cannot do (e.g. a variable read before its
// `let`). Needs node and jsdom:
//   npm i --no-save jsdom@24 && node tests/frontend_smoke.js
// Pass a URL as the first argument to check a live deployment instead.
const { JSDOM, VirtualConsole } = require("jsdom");
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "..", "app", "static") + path.sep;
const live = process.argv[2];  // e.g. https://host:4443/ (self-signed: NODE_TLS_REJECT_UNAUTHORIZED=0)

async function load() {
  if (!live) {
    return {
      html: fs.readFileSync(root + "index.html", "utf8"),
      js: fs.readFileSync(root + "app.js", "utf8"),
    };
  }
  const base = live.replace(/\/$/, "");
  const html = await (await fetch(base + "/")).text();
  const src = (html.match(/<script src="([^"]+)"><\/script>/) || [])[1];
  if (!src) throw new Error("no <script src> in live index.html");
  return { html, js: await (await fetch(base + src)).text() };
}

load().then(run).catch(e => { console.error("load failed:", e.message); process.exit(2); });

function run({ html, js }) {
// inline the external script so no network/file loader is needed
html = html.replace(/<script src="\/static\/app\.js[^"]*"><\/script>/,
  "<script>" + js + "</script>");
const errors = [];
const vc = new VirtualConsole();
vc.on("jsdomError", e => errors.push(String(e.message || e)));
vc.on("error", (...a) => errors.push(a.join(" ")));
const dom = new JSDOM(html, { runScripts: "dangerously", url: "https://dash.test/", virtualConsole: vc,
  beforeParse(w) {
    w.fetch = async (url) => ({ ok: true, status: 200, json: async () => {
      if (String(url).includes("/api/auth/status")) return { has_password: true, logged_in: false };
      return { servers: [], generated_at: null };
    }, headers: new Map() });
    w.localStorage.clear();
  } });
setTimeout(() => {
  const d = dom.window.document;
  const ovl = d.getElementById("loginOverlay");
  console.log("errors:", errors.length ? errors : "none");
  console.log("login overlay visible:", ovl && !ovl.classList.contains("hidden"));
  console.log("login button text:", d.getElementById("loginBtn").textContent);
  console.log("rows tbody present:", !!d.getElementById("rows"));
  dom.window.clearInterval(dom.window.__di);
  process.exit(errors.length ? 1 : 0);
}, 500);
}
