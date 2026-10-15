/* Вкладка «Проекты»: обзор карточками (#projects) и страница проекта (#projects/<id>).
   Данные — /api/projects и /api/projects/<id> (формат: docs/analytics-schema.md).
   Отдельный файл, чтобы не трогать логику таблицы серверов в app.js. */
(function () {
  "use strict";
  const view = document.getElementById("projectsView");
  const serverParts = [".toolbar", "#addForm", "#botForm", "#secPanel", "table:not(.pj-table)", "#meta"];
  const tabs = document.querySelectorAll("#tabs [data-tab]");
  const SVG = "http://www.w3.org/2000/svg";
  const STATE = {ok: "Работает", warn: "Есть замечания", bad: "Проблема"};
  const SEV = {bad: "Срочно", warn: "Проверить"};
  let timer = null;
  let current = null;           // id открытого проекта или null
  let overview = null;          // последний ответ /api/projects
  let metrics = null;           // последний ответ /api/metrics

  /* ---------- утилиты ---------- */
  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  const svg = (tag, attrs) => {
    const e = document.createElementNS(SVG, tag);
    for (const k in attrs || {}) e.setAttribute(k, attrs[k]);
    return e;
  };
  const nf = (v, digits) => Number(v).toLocaleString("ru-RU", {maximumFractionDigits: digits == null ? 2 : digits});
  function fmtValue(v, unit) {
    if (v == null || v === "") return "—";
    if (typeof v !== "number") return String(v);
    const abs = Math.abs(v);
    let s;
    if (unit === "$") s = abs < 1 ? nf(v, 4) : abs >= 10000 ? nf(v, 0) : nf(v, 2);
    else if (abs >= 1e6) s = nf(v / 1e6, 2) + " млн";
    else if (abs >= 1e5) s = nf(v / 1e3, 0) + " тыс";
    else s = nf(v, abs < 10 ? 2 : abs < 100 ? 1 : 0);
    if (!unit || unit === "шт") return s;
    if (unit === "$") return "$" + s;
    return s + " " + unit;
  }
  /* подпись оси: знаков после запятой ровно столько, чтобы соседние деления различались */
  function compact(v, step) {
    if (v === 0) return "0";
    const a = Math.max(Math.abs(v), step || 0);
    const digits = (div) => Math.min(3, Math.max(0, Math.ceil(-Math.log10((step || div) / div) - 1e-9)));
    if (a >= 1e6) return nf(v / 1e6, digits(1e6)) + " млн";
    if (a >= 1e3) return nf(v / 1e3, digits(1e3)) + " тыс";
    return nf(v, digits(1));
  }
  const parseX = (x) => new Date(/^\d{4}-\d{2}-\d{2}$/.test(x) ? x + "T00:00:00" : x);
  const fmtX = (x, withTime) => {
    const d = parseX(x);
    if (isNaN(d)) return String(x);
    const dm = String(d.getDate()).padStart(2, "0") + "." + String(d.getMonth() + 1).padStart(2, "0");
    return withTime ? dm + " " + String(d.getHours()).padStart(2, "0") + ":00" : dm;
  };
  const ago = (min) => min == null ? "" : min < 1 ? "только что" : min < 60 ? min + " мин назад" : Math.round(min / 60) + " ч назад";
  function pill(state, text) { return el("span", "pj-pill " + (state || "ok"), text || STATE[state] || state); }

  /* серия «ошибки» — всегда красная, остальные по палитре */
  const PALETTE = ["var(--accent)", "#f59e0b", "#14b8a6", "#a855f7", "#64748b"];
  const colorFor = (name, i) => /fail|ошиб|error|отказ/i.test(name) ? "var(--bad)" : PALETTE[i % PALETTE.length];

  /* ---------- графики ---------- */
  /* шаг оси 1/2/2,5/5 × 10^n — подписи делений круглые */
  function niceStep(raw) {
    const p = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= raw - 1e-12) return m * p;
    return 10 * p;
  }

  function drawChart(box, chart, opts) {
    opts = opts || {};
    box.textContent = "";
    const series = (chart.series || []).filter((s) => s.points && s.points.length);
    if (!series.length) { box.append(el("p", "pj-muted", "Нет данных за период")); return; }
    const xs = series[0].points.map((p) => p[0]);
    const withTime = xs.some((x) => x.length > 10);
    const W = Math.max(box.clientWidth, 200);
    const H = opts.spark ? 46 : 220;
    const m = opts.spark ? {l: 0, r: 0, t: 4, b: 2} : {l: 52, r: 12, t: 10, b: 26};  /* l уточняется по подписям ниже */
    const ih = H - m.t - m.b;
    const stacked = chart.kind === "bar" && series.length > 1;
    const val = (s, i) => Number((s.points[i] || [])[1]) || 0;
    const totals = xs.map((_, i) => series.reduce((a, s) => a + val(s, i), 0));
    /* для стопки положительные части растут вверх от нуля, отрицательные — вниз */
    const posSum = xs.map((_, i) => series.reduce((a, s) => a + Math.max(0, val(s, i)), 0));
    const negSum = xs.map((_, i) => series.reduce((a, s) => a + Math.min(0, val(s, i)), 0));
    const vals = series.flatMap((s) => s.points.map((p) => Number(p[1]) || 0));
    let lo = stacked ? Math.min(...negSum) : Math.min(...vals);
    let hi = stacked ? Math.max(...posSum) : Math.max(...vals);
    /* уровень далеко от нуля (курс, стоимость портфеля): ось по диапазону данных, иначе линия плоская */
    const level = chart.kind === "line" && lo > 0 && hi > lo && lo > hi * 0.5;
    if (!level) { lo = Math.min(0, lo); hi = Math.max(0, hi); }
    if (hi === lo) hi = lo + 1;
    const step = niceStep((hi - lo) / 4);
    const minV = Math.floor(lo / step + 1e-9) * step;
    const maxV = Math.ceil(hi / step - 1e-9) * step;
    if (!opts.spark) {
      /* левое поле по самой длинной подписи деления, ~6,5 px на символ при 11 px */
      let longest = 0;
      for (let v = minV; v <= maxV + step / 2; v += step) longest = Math.max(longest, compact(Math.abs(v) < step / 2 ? 0 : v, step).length);
      m.l = Math.max(36, Math.ceil(longest * 6.5) + 12);
    }
    const iw = W - m.l - m.r;
    const colW = iw / xs.length;
    const xc = (i) => m.l + colW * i + colW / 2;
    const y = (v) => m.t + ih - (ih * (v - minV)) / (maxV - minV || 1);
    const root = svg("svg", {viewBox: `0 0 ${W} ${H}`, width: "100%", height: H, role: "img", "aria-label": chart.title || ""});

    if (!opts.spark) {
      for (let v = minV; v <= maxV + step / 2; v += step) {
        root.append(svg("line", {x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: Math.abs(v) < step / 2 && minV < 0 ? "pj-grid pj-zero" : "pj-grid"}));
        const t = svg("text", {x: m.l - 6, y: y(v) + 4, "text-anchor": "end", class: "pj-axis"});
        t.textContent = compact(Math.abs(v) < step / 2 ? 0 : v, step);
        root.append(t);
      }
      const every = Math.max(1, Math.ceil(xs.length / Math.max(2, Math.floor(iw / 56))));
      xs.forEach((x, i) => {
        const last = i === xs.length - 1;
        if (i % every && !last) return;
        if (!last && xs.length - 1 - i < every) return;
        const anchor = last ? "end" : i === 0 ? "start" : "middle";
        const t = svg("text", {x: last ? W - m.r : i === 0 ? m.l : xc(i), y: H - 8, "text-anchor": anchor, class: "pj-axis"});
        /* почасовой ряд — только часы, дневной — дд.мм */
        t.textContent = withTime ? String(parseX(x).getHours()).padStart(2, "0") + ":00" : fmtX(x);
        root.append(t);
      });
    }

    if (chart.kind === "bar") {
      const bw = Math.max(1, Math.min(28, colW * 0.7));
      xs.forEach((_, i) => {
        let up = 0, down = 0;
        series.forEach((s, si) => {
          const v = val(s, i);
          if (!v) return;
          const base = !stacked ? 0 : v > 0 ? up : down;
          if (stacked) { if (v > 0) up += v; else down += v; }
          const top = y(Math.max(base, base + v)), bottom = y(Math.min(base, base + v));
          root.append(svg("rect", {x: xc(i) - bw / 2, y: top, width: bw, height: Math.max(1, bottom - top),
            rx: Math.min(3, bw / 2), fill: colorFor(s.name, si), class: "pj-barrect"}));
        });
      });
    } else {
      series.forEach((s, si) => {
        const pts = s.points.map((p, i) => [xc(i), y(Number(p[1]) || 0)]);
        const d = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
        if (series.length === 1) {
          const base = y(Math.max(minV, Math.min(0, maxV)));
          const area = d + ` L ${pts[pts.length - 1][0].toFixed(1)} ${level ? y(minV) : base} L ${pts[0][0].toFixed(1)} ${level ? y(minV) : base} Z`;
          root.append(svg("path", {d: area, fill: colorFor(s.name, si), opacity: 0.12}));
        }
        root.append(svg("path", {d, fill: "none", stroke: colorFor(s.name, si), "stroke-width": opts.spark ? 1.6 : 2,
          "stroke-linejoin": "round", "stroke-linecap": "round"}));
      });
    }
    box.append(root);
    if (opts.spark) return;

    if (series.length > 1) {
      const lg = el("div", "pj-legend");
      series.forEach((s, si) => {
        const it = el("span");
        const sw = el("i"); sw.style.background = colorFor(s.name, si);
        it.append(sw, document.createTextNode(s.name));
        lg.append(it);
      });
      box.append(lg);
    }

    /* подсказка по наведению: ближайшая точка по X */
    const tip = el("div", "pj-tip hidden");
    const cursor = svg("line", {y1: m.t, y2: m.t + ih, class: "pj-cursor", visibility: "hidden"});
    root.append(cursor);
    box.append(tip);
    root.addEventListener("mousemove", (ev) => {
      const r = root.getBoundingClientRect();
      const px = ((ev.clientX - r.left) / r.width) * W;
      const i = Math.min(xs.length - 1, Math.max(0, Math.floor((px - m.l) / colW)));
      cursor.setAttribute("x1", xc(i)); cursor.setAttribute("x2", xc(i)); cursor.setAttribute("visibility", "visible");
      tip.textContent = "";
      tip.append(el("div", "pj-tip-x", fmtX(xs[i], withTime)));
      series.forEach((s, si) => {
        const row = el("div", "pj-tip-row");
        const sw = el("i"); sw.style.background = colorFor(s.name, si);
        row.append(sw, el("span", null, s.name), el("b", null, fmtValue(Number((s.points[i] || [])[1]) || 0, chart.unit)));
        tip.append(row);
      });
      if (stacked) tip.append(el("div", "pj-tip-row pj-tip-sum", "Всего: " + fmtValue(totals[i], chart.unit)));
      tip.classList.remove("hidden");
      const left = (xc(i) / W) * r.width;
      tip.style.left = Math.min(r.width - tip.offsetWidth - 4, Math.max(4, left + 12)) + "px";
      tip.style.top = "8px";
    });
    root.addEventListener("mouseleave", () => { tip.classList.add("hidden"); cursor.setAttribute("visibility", "hidden"); });
  }

  /* ---------- плитки и таблицы ---------- */
  function kpiTile(k, big) {
    const t = el("div", "pj-kpi " + (k.state && k.state !== "ok" ? k.state : "") + (big ? " big" : ""));
    const txt = fmtValue(k.value, k.unit);
    t.append(el("span", "pj-kpi-label", k.label), el("span", "pj-kpi-value" + (txt.length > 8 ? " long" : ""), txt));
    if (typeof k.delta === "number") {
      const up = k.delta >= 0;
      const d = el("span", "pj-delta " + (up ? "pj-up" : "pj-down"), (up ? "▲ +" : "▼ ") + nf(k.delta, 1) + " %" + (k.delta_label ? " " + k.delta_label : ""));
      t.append(d);
    }
    if (k.hint) t.title = k.hint;
    return t;
  }

  function tableCard(tb) {
    const card = el("section", "pj-card pj-wide");
    card.append(el("h3", null, tb.title));
    const wrap = el("div", "pj-scroll");
    const table = el("table", "pj-table");
    const thead = el("thead"), hr = el("tr");
    (tb.columns || []).forEach((c) => hr.append(el("th", c.num ? "num" : "", c.label)));
    thead.append(hr);
    const body = el("tbody");
    (tb.rows || []).forEach((r) => {
      const tr = el("tr");
      (tb.columns || []).forEach((c) => {
        const v = r[c.key];
        const td = el("td", c.num ? "num" : "");
        if (c.state) td.append(pill(v, {ok: "норма", warn: "внимание", bad: "проблема"}[v] || String(v)));
        else if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v)) td.textContent = v.slice(8) + "." + v.slice(5, 7) + "." + v.slice(0, 4);
        else td.textContent = v == null || v === "" ? "—" : c.num && typeof v === "number" ? fmtValue(v, c.unit) : String(v);
        tr.append(td);
      });
      body.append(tr);
    });
    if (!(tb.rows || []).length) {
      const tr = el("tr"); const td = el("td", "pj-muted", "Пусто"); td.colSpan = (tb.columns || []).length || 1; tr.append(td); body.append(tr);
    }
    table.append(thead, body); wrap.append(table); card.append(wrap);
    return card;
  }

  function siteLine(p) {
    const parts = [];
    if (p.check) parts.push(p.check.http == null ? "сайт не отвечает" : "HTTP " + p.check.http + " · " + nf(p.check.ms, 0) + " мс");
    if (p.tls) parts.push(p.tls.error ? "TLS: ошибка" : "TLS " + p.tls.days_left + " дн");
    return parts.join(" · ");
  }

  /* ---------- обзор ---------- */
  function renderOverview() {
    view.textContent = "";
    if (!overview || !overview.ready) { view.append(el("p", "pj-muted", "Сбор данных по проектам…")); return; }
    const ps = overview.projects;
    const cnt = {ok: 0, warn: 0, bad: 0};
    ps.forEach((p) => cnt[p.state]++);

    const head = el("div", "pj-head");
    const h = el("div");
    h.append(el("h2", "pj-title", "Проекты"),
      el("div", "pj-muted", "Обновлено " + new Date(overview.generated_at).toLocaleTimeString("ru-RU", {hour: "2-digit", minute: "2-digit"}) + " · проверка раз в " + Math.round(overview.refresh_sec / 60) + " мин"));
    const sum = el("div", "pj-summary");
    if (cnt.bad) sum.append(pill("bad", cnt.bad + " с проблемами"));
    if (cnt.warn) sum.append(pill("warn", cnt.warn + " с замечаниями"));
    sum.append(pill("ok", cnt.ok + " в норме"));
    head.append(h, sum);
    view.append(head);

    /* что требует внимания — по всем проектам и серверам */
    const items = [];
    ps.forEach((p) => p.issues.forEach((r) => items.push({sev: r.severity, where: p.name, what: r.text, id: p.id})));
    (metrics && metrics.servers || []).forEach((s) => {
      if (s.status !== "up") items.push({sev: "bad", where: "Серверы", what: s.name + ": нет связи"});
      else if (s.disk_total_gb && 1 - s.disk_free_gb / s.disk_total_gb >= 0.85)
        items.push({sev: "warn", where: "Серверы", what: s.name + ": диск занят на " + Math.round(100 * (1 - s.disk_free_gb / s.disk_total_gb)) + " %"});
    });
    if (items.length) {
      items.sort((a, b) => (a.sev === "bad" ? 0 : 1) - (b.sev === "bad" ? 0 : 1));
      const att = el("section", "pj-card pj-attention");
      att.append(el("h3", null, "Требует внимания"));
      const ul = el("ul");
      items.forEach((it) => {
        const li = el("li");
        const where = it.id ? el("a", "pj-link", it.where) : el("b", null, it.where);
        if (it.id) { where.href = "#projects/" + it.id; }
        li.append(pill(it.sev, SEV[it.sev]), where, el("span", null, it.what));
        ul.append(li);
      });
      att.append(ul);
      view.append(att);
    }

    const grid = el("div", "pj-cards");
    const order = {bad: 0, warn: 1, ok: 2};
    ps.slice().sort((a, b) => order[a.state] - order[b.state]).forEach((p) => {
      const card = el("a", "pj-card pj-project " + p.state);
      card.href = "#projects/" + p.id;
      const top = el("div", "pj-project-top");
      const nm = el("div");
      nm.append(el("div", "pj-project-name", p.name), el("div", "pj-muted", p.stage || ""));
      top.append(nm, pill(p.state));
      card.append(top);
      const a = p.analytics;
      if (a && a.kpis && a.kpis.length) {
        const k = el("div", "pj-project-kpis");
        a.kpis.forEach((x) => k.append(kpiTile(x)));
        card.append(k);
      } else if (a && a.error) {
        card.append(el("p", "pj-muted", a.error));
      } else {
        card.append(el("p", "pj-muted", "Подробной аналитики пока нет — только сайт и сертификат"));
      }
      if (a && a.spark) {
        const sp = el("div", "pj-spark");
        const cap = el("div", "pj-spark-cap", a.spark.title);
        card.append(cap, sp);
        requestAnimationFrame(() => drawChart(sp, a.spark, {spark: true}));
      }
      card.append(el("div", "pj-project-foot", siteLine(p)));
      grid.append(card);
    });
    view.append(grid);

    const bottom = el("div", "pj-two");
    bottom.append(serversCard(), tlsCard());
    view.append(bottom);
  }

  function serversCard() {
    const card = el("section", "pj-card");
    card.append(el("h3", null, "Серверы"));
    const servers = (metrics && metrics.servers) || [];
    const up = servers.filter((s) => s.status === "up");
    const diskPct = (s) => s.disk_total_gb ? Math.round(100 * (1 - s.disk_free_gb / s.disk_total_gb)) : 0;
    const k = el("div", "pj-kpis");
    k.append(
      kpiTile({label: "На связи", value: up.length + " из " + servers.length, state: up.length < servers.length ? "bad" : "ok"}),
      kpiTile({label: "Макс. CPU", value: up.length ? Math.round(Math.max(...up.map((s) => s.cpu_percent || 0))) : null, unit: "%"}),
      kpiTile({label: "Макс. диск", value: up.length ? Math.max(...up.map(diskPct)) : null, unit: "%", state: up.some((s) => diskPct(s) >= 85) ? "warn" : "ok"}),
      kpiTile({label: "Трафик за сутки", value: Math.round(servers.reduce((a, s) => a + (s.traffic_1d_gb || 0), 0)), unit: "ГБ"}),
    );
    card.append(k);
    const link = el("button", "btn small", "Открыть таблицу серверов");
    link.type = "button";
    link.addEventListener("click", () => show("servers"));
    card.append(link);
    return card;
  }

  function tlsCard() {
    const card = el("section", "pj-card");
    card.append(el("h3", null, "Сертификаты"));
    const certs = [];
    (overview.projects || []).forEach((p) => { if (p.tls) certs.push(p.tls); });
    (overview.tls || []).forEach((c) => certs.push(c));
    const seen = new Set();
    const list = certs.filter((c) => !seen.has(c.host) && seen.add(c.host))
      .sort((a, b) => (a.days_left == null ? -1 : a.days_left) - (b.days_left == null ? -1 : b.days_left));
    const max = Math.max(90, ...list.map((c) => c.days_left || 0));
    list.forEach((c) => {
      const st = c.error || c.days_left < 21 ? "bad" : c.days_left < 45 ? "warn" : "ok";
      const row = el("div", "pj-tls " + st);
      const bar = el("div", "pj-bar"); const fill = el("i");
      fill.style.width = c.error ? "0" : Math.max(2, (100 * c.days_left) / max) + "%";
      bar.append(fill);
      row.append(el("span", "pj-host", c.host), bar, el("span", "num", c.error ? "ошибка" : c.days_left + " дн"));
      card.append(row);
    });
    return card;
  }

  /* ---------- страница проекта ---------- */
  async function renderDetail(id) {
    let p;
    try {
      const r = await fetch("/api/projects/" + encodeURIComponent(id), {cache: "no-store"});
      if (!r.ok) throw new Error("HTTP " + r.status);
      p = await r.json();
    } catch (err) {
      view.textContent = "";
      view.append(backLink(), el("p", "pj-muted", "Не удалось загрузить проект: " + err.message));
      return;
    }
    if (current !== id) return;
    view.textContent = "";
    view.append(backLink());

    const head = el("div", "pj-head");
    const h = el("div");
    const title = el("h2", "pj-title", p.name);
    h.append(title);
    const sub = el("div", "pj-muted");
    sub.textContent = [p.stage, siteLine(p), p.analytics && p.analytics.age_min != null ? "данные " + ago(p.analytics.age_min) : ""].filter(Boolean).join(" · ");
    h.append(sub);
    const right = el("div", "pj-summary");
    right.append(pill(p.state));
    if (p.link) { const a = el("a", "btn small", "Открыть сайт ↗"); a.href = p.link; a.target = "_blank"; a.rel = "noopener"; right.append(a); }
    head.append(h, right);
    view.append(head);

    if (p.issues.length) {
      const att = el("section", "pj-card pj-attention");
      const ul = el("ul");
      p.issues.forEach((r) => {
        const li = el("li"); li.append(pill(r.severity, SEV[r.severity]), el("span", null, r.text)); ul.append(li);
      });
      att.append(ul);
      view.append(att);
    }

    const a = p.analytics;
    if (!a || a.error) {
      view.append(el("p", "pj-muted", a && a.error ? a.error : "Для этого проекта подробная аналитика ещё не подключена: видны только сайт и сертификат."));
      return;
    }
    if ((a.kpis || []).length) {
      const k = el("div", "pj-kpis pj-kpis-big");
      a.kpis.forEach((x) => k.append(kpiTile(x, true)));
      view.append(k);
    }
    if ((a.charts || []).length) {
      const g = el("div", "pj-charts");
      a.charts.forEach((c) => {
        const card = el("section", "pj-card");
        card.append(el("h3", null, c.title));
        if (c.note) card.append(el("div", "pj-muted pj-note", c.note));
        const box = el("div", "pj-chart");
        card.append(box);
        g.append(card);
        requestAnimationFrame(() => drawChart(box, c));
      });
      view.append(g);
    }
    (a.tables || []).forEach((tb) => view.append(tableCard(tb)));
  }

  function backLink() {
    const b = el("a", "pj-back", "← Все проекты");
    b.href = "#projects";
    return b;
  }

  /* ---------- данные и навигация ---------- */
  async function loadOverview() {
    try {
      const [pr, mr] = await Promise.all([
        fetch("/api/projects", {cache: "no-store"}),
        fetch("/api/metrics", {cache: "no-store"}),
      ]);
      if (!pr.ok) throw new Error("HTTP " + pr.status);
      overview = await pr.json();
      metrics = mr.ok ? await mr.json() : null;
      view.classList.remove("stale");
    } catch (err) {
      view.classList.add("stale");
      if (!overview) { view.textContent = ""; view.append(el("p", "pj-muted", "Не удалось загрузить проекты: " + err.message)); }
    }
  }

  async function route() {
    const m = location.hash.match(/^#projects(?:\/([a-z0-9_-]+))?$/);
    if (!m) return;
    current = m[1] || null;
    if (current) await renderDetail(current);
    else { await loadOverview(); if (!current) renderOverview(); }
    window.scrollTo(0, 0);
  }

  async function tick() {
    if (view.classList.contains("hidden")) return;
    if (current) await renderDetail(current);
    else { await loadOverview(); renderOverview(); }
  }

  function show(tab, keepHash) {
    const pj = tab === "projects";
    view.classList.toggle("hidden", !pj);
    serverParts.forEach((sel) => document.querySelectorAll(sel).forEach((n) => {
      if (!view.contains(n)) n.classList.toggle("pj-off", pj);
    }));
    document.querySelector(".wrap").classList.toggle("pj-wide-wrap", pj);
    tabs.forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
    try { localStorage.setItem("tab", tab); } catch (e) { /* приватный режим */ }
    clearInterval(timer);
    if (pj) {
      if (!keepHash) location.hash = "#projects";
      else route();
      timer = setInterval(tick, 60000);
    } else if (history.replaceState) {
      history.replaceState(null, "", location.pathname);
    }
  }

  window.addEventListener("hashchange", () => {
    if (/^#projects/.test(location.hash)) {
      if (view.classList.contains("hidden")) show("projects", true);
      else route();
    }
  });
  let resizeT = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeT);
    resizeT = setTimeout(() => { if (!view.classList.contains("hidden")) (current ? renderDetail(current) : renderOverview()); }, 250);
  });
  tabs.forEach((b) => b.addEventListener("click", () => show(b.dataset.tab)));

  let start = "servers";
  try { start = localStorage.getItem("tab") || "servers"; } catch (e) { /* приватный режим */ }
  if (/^#projects/.test(location.hash)) show("projects", true);
  else show(start);
})();
