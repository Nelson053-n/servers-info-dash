/* Вкладка «Проекты»: переключатель вкладок и отрисовка /api/projects.
   Отдельный файл, чтобы не трогать логику таблицы серверов в app.js. */
(function () {
  "use strict";
  const view = document.getElementById("projectsView");
  const serverParts = [".toolbar", "#addForm", "#botForm", "#secPanel", "table:not(.pj-table)"];
  const tabs = document.querySelectorAll("#tabs [data-tab]");
  let timer = null;

  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  const num = (v) => (v == null ? "—" : Number(v).toLocaleString("ru-RU"));
  const STATE = {ok: "Работает", warn: "Есть замечания", bad: "Проблема"};

  function show(tab) {
    const pj = tab === "projects";
    view.classList.toggle("hidden", !pj);
    serverParts.forEach((sel) => document.querySelectorAll(sel).forEach((n) => {
      if (!view.contains(n)) n.classList.toggle("pj-off", pj);
    }));
    tabs.forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
    try { localStorage.setItem("tab", tab); } catch (e) { /* приватный режим */ }
    if (history.replaceState) history.replaceState(null, "", pj ? "#projects" : "#");
    clearInterval(timer);
    if (pj) { load(); timer = setInterval(load, 60000); }
  }

  function pill(state, text) {
    return el("span", "pj-pill " + state, text || STATE[state] || state);
  }

  function tile(label, value, state) {
    const t = el("div", "pj-tile" + (state && state !== "ok" ? " " + state : ""));
    t.append(el("span", "pj-lbl", label), el("span", "pj-val", value));
    return t;
  }

  function renderAttention(projects, servers) {
    const box = document.getElementById("pjAttention");
    box.textContent = "";
    const items = [];
    projects.forEach((p) => p.reasons.forEach((r) => items.push([p.state === "bad" ? "bad" : "warn", p.name, r])));
    (servers || []).forEach((s) => {
      if (s.status !== "up") items.push(["bad", "Серверы", s.name + ": нет связи"]);
      else if (s.disk_total_gb && 1 - s.disk_free_gb / s.disk_total_gb >= 0.85)
        items.push(["warn", "Серверы", s.name + ": диск " + Math.round(100 * (1 - s.disk_free_gb / s.disk_total_gb)) + " %"]);
    });
    items.sort((a, b) => (a[0] === "bad" ? 0 : 1) - (b[0] === "bad" ? 0 : 1));
    const head = document.getElementById("pjTakeaway");
    const nBad = items.filter((i) => i[0] === "bad").length;
    head.textContent = items.length ? `Срочно: ${nBad}, проверить: ${items.length - nBad}` : "Всё в норме";
    head.className = "pj-take " + (nBad ? "bad" : items.length ? "warn" : "ok");
    items.forEach(([sev, where, what]) => {
      const li = el("li");
      li.append(pill(sev, sev === "bad" ? "Срочно" : "Проверить"), el("b", null, where), el("span", null, what));
      box.appendChild(li);
    });
  }

  function renderVpn(p) {
    const box = document.getElementById("pjVpn");
    box.textContent = "";
    const s = (p && p.summary) || {};
    if (!p || s.error) { box.append(el("p", "pj-muted", s.error ? "Сводка недоступна: " + s.error : "Нет данных")); return; }
    const c = s.clients || {}, pay = s.payments || {}, b = s.backups || {}, srv = s.servers || {};
    box.append(
      tile("Активных ключей", num(c.active)),
      tile("Онлайн за 15 мин", num(c.online_15m)),
      tile("Оплаты за 30 дн", num(pay.rub_30d) + " ₽"),
      tile("Оплаты за сутки", num(pay.rub_24h) + " ₽"),
      tile("Истекают за 7 дн", num(c.expiring_7d), c.expiring_7d > 0 ? "warn" : "ok"),
      tile("Бэкапов за сутки", num(b.completed_24h) + (b.failed_24h ? " / ошибок " + b.failed_24h : ""), b.failed_24h ? "warn" : "ok"),
      tile("Ноды online", num(srv.online) + " из " + num(srv.total), srv.offline && srv.offline.length ? "warn" : "ok"),
      tile("SSH-алерты", num(s.ssh_alerts_open), s.ssh_alerts_open ? "warn" : "ok"),
    );
    (s.rf || []).forEach((r) => {
      const ok = !r.error && r.exits_alive === r.exits_total;
      box.append(tile("Вход " + r.label + ": выходы", r.error ? "нет данных" : r.exits_alive + " из " + r.exits_total + (r.active_peers != null ? " · " + r.active_peers + " онлайн" : ""), r.error ? "bad" : ok ? "ok" : "warn"));
    });
    if (s.rf_error) box.append(tile("Связность", s.rf_error, "bad"));
  }

  function renderNb(p) {
    const box = document.getElementById("pjNb");
    box.textContent = "";
    const s = (p && p.summary) || {};
    if (!p || s.error) { box.append(el("p", "pj-muted", s.error ? "Сводка недоступна: " + s.error : "Нет данных")); return; }
    const g = s.generations_24h || {}, pay = s.purchases_24h || {};
    const failPct = g.total ? Math.round(1000 * g.failed / g.total) / 10 : null;
    const svcBad = Object.values(s.services || {}).some((v) => v !== "active");
    box.append(
      tile("Сервисы", svcBad ? "есть остановленные" : "все работают", svcBad ? "bad" : "ok"),
      tile("Генераций за сутки", num(g.total)),
      tile("Ошибок генерации", failPct == null ? "—" : failPct.toLocaleString("ru-RU") + " %", failPct > 20 ? "warn" : "ok"),
      tile("Зависших", num(g.stuck), g.stuck ? "warn" : "ok"),
      tile("Оплаты за сутки", num(pay.rub) + " ₽ · " + num(pay.count)),
      tile("Алерты API за сутки", num(s.api_alerts_24h), s.api_alerts_24h ? "warn" : "ok"),
    );
    if (s.stale) box.append(el("p", "pj-muted", "Сводка не обновлялась " + s.age_min + " мин"));
  }

  function renderProjects(projects) {
    const tb = document.getElementById("pjRows");
    tb.textContent = "";
    const order = {bad: 0, warn: 1, ok: 2};
    projects.slice().sort((a, b) => order[a.state] - order[b.state]).forEach((p) => {
      const tr = el("tr");
      const name = el("td");
      if (p.link) { const a = el("a", null, p.name); a.href = p.link; a.target = "_blank"; a.rel = "noopener"; name.append(a); }
      else name.textContent = p.name;
      const st = el("td"); st.append(pill(p.state));
      const http = p.check ? (p.check.http == null ? "нет ответа" : String(p.check.http)) : "—";
      const ms = p.check && p.check.http != null ? num(p.check.ms) : "—";
      const tls = p.tls ? (p.tls.error ? "ошибка" : p.tls.days_left + " дн") : "—";
      tr.append(name, st, el("td", "pj-narrow", p.stage), el("td", "num", http), el("td", "num pj-narrow", ms),
        el("td", "num" + (p.tls && (p.tls.error || p.tls.days_left < 21) ? " pj-badtext" : ""), tls),
        el("td", "pj-muted pj-narrow", p.reasons.length ? p.reasons.join("; ") : p.note));
      tb.appendChild(tr);
    });
  }

  function renderTls(certs) {
    const box = document.getElementById("pjTls");
    box.textContent = "";
    const max = Math.max(90, ...certs.map((c) => c.days_left || 0));
    certs.forEach((c) => {
      const row = el("div", "pj-tls" + (c.error || c.days_left < 21 ? " bad" : c.days_left < 45 ? " warn" : ""));
      const bar = el("div", "pj-bar"); const fill = el("i");
      fill.style.width = c.error ? "0" : Math.max(2, 100 * c.days_left / max) + "%";
      bar.append(fill);
      row.append(el("span", "pj-host", c.host), bar, el("span", "num", c.error ? "ошибка" : c.days_left + " дн"));
      box.append(row);
    });
  }

  function renderServers(servers) {
    const box = document.getElementById("pjServers");
    box.textContent = "";
    if (!servers) return;
    const up = servers.filter((s) => s.status === "up");
    const diskPct = (s) => s.disk_total_gb ? Math.round(100 * (1 - s.disk_free_gb / s.disk_total_gb)) : 0;
    const hot = up.filter((s) => diskPct(s) >= 85 || s.cpu_percent >= 80);
    box.append(
      tile("На связи", up.length + " из " + servers.length, up.length < servers.length ? "bad" : "ok"),
      tile("Перегружены", String(hot.length), hot.length ? "warn" : "ok"),
      tile("Макс. CPU", up.length ? Math.round(Math.max(...up.map((s) => s.cpu_percent || 0))) + " %" : "—"),
      tile("Макс. диск", up.length ? Math.max(...up.map(diskPct)) + " %" : "—", up.some((s) => diskPct(s) >= 85) ? "warn" : "ok"),
    );
  }

  async function load() {
    try {
      const [pr, mr] = await Promise.all([
        fetch("/api/projects", {cache: "no-store"}),
        fetch("/api/metrics", {cache: "no-store"}),
      ]);
      if (!pr.ok) throw new Error("HTTP " + pr.status);
      const data = await pr.json();
      const metrics = mr.ok ? await mr.json() : {};
      const meta = document.getElementById("pjMeta");
      if (!data.ready) { meta.textContent = "Сбор данных по проектам…"; return; }
      meta.textContent = "Обновлено " + new Date(data.generated_at).toLocaleString("ru-RU") + " · раз в " + Math.round(data.refresh_sec / 60) + " мин";
      const by = (n) => data.projects.find((p) => p.summary && n(p.summary));
      renderAttention(data.projects, metrics.servers);
      renderVpn(by((s) => "clients" in s || "rf" in s) || data.projects.find((p) => /vpn/i.test(p.name)));
      renderNb(by((s) => "generations_24h" in s));
      renderServers(metrics.servers);
      renderProjects(data.projects);
      renderTls(data.tls);
      view.classList.remove("stale");
    } catch (err) {
      document.getElementById("pjMeta").textContent = "Не удалось обновить: " + err.message;
      view.classList.add("stale");
    }
  }

  tabs.forEach((b) => b.addEventListener("click", () => show(b.dataset.tab)));
  let start = "servers";
  try { start = localStorage.getItem("tab") || "servers"; } catch (e) { /* приватный режим */ }
  if (location.hash === "#projects") start = "projects";
  show(start);
})();
