/* Разделы info: Обзор, Проекты (+ страница проекта), Серверы, Сертификаты.
   Таблицу серверов, формы и вход ведёт app.js; здесь — навигация, обзор, проекты и сертификаты.
   Данные: /api/projects, /api/projects/<id> (формат docs/analytics-schema.md), /api/metrics. */
(function () {
  "use strict";
  const VIEWS = ["overview", "projects", "servers", "tls"];
  const SVG = "http://www.w3.org/2000/svg";
  const STATE = {ok: "норма", warn: "замечания", bad: "проблема"};
  const SEV = {bad: "Срочно", warn: "Проверить"};
  let overview = null, metrics = null, current = {view: "overview", id: null}, timer = null, projFilter = "all", retrying = false;

  /* ---------- утилиты ---------- */
  const $ = (id) => document.getElementById(id);
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
  const nf = (v, d) => Number(v).toLocaleString("ru-RU", {maximumFractionDigits: d == null ? 2 : d});
  function fmtValue(v, unit) {
    if (v == null || v === "") return "—";
    if (typeof v !== "number") return String(v);
    const a = Math.abs(v);
    let s;
    if (unit === "$") s = a < 1 ? nf(v, 4) : a >= 10000 ? nf(v, 0) : nf(v, 2);
    else if (a >= 1e6) s = nf(v / 1e6, 2) + " млн";
    else if (a >= 1e5) s = nf(v / 1e3, 0) + " тыс";
    else s = nf(v, a < 10 ? 2 : a < 100 ? 1 : 0);
    if (!unit || unit === "шт") return s;
    return unit === "$" ? "$" + s : s + " " + unit;
  }
  const isLong = (txt) => /[a-zа-яё]{3}/i.test(txt) && !/^[\d\s.,−\-+$₽%]+(млн|тыс)?/.test(txt);
  const parseX = (x) => new Date(/^\d{4}-\d{2}-\d{2}$/.test(x) ? x + "T00:00:00" : x);
  const dm = (x) => { const d = parseX(x); return isNaN(d) ? String(x) : String(d.getDate()).padStart(2, "0") + "." + String(d.getMonth() + 1).padStart(2, "0"); };
  const ago = (min) => min == null ? "" : min < 1 ? "только что" : min < 60 ? min + " мин назад" : Math.round(min / 60) + " ч назад";
  const chip = (state, text) => el("span", "chip " + (state || "ok"), text || STATE[state] || state);
  const diskPct = (s) => s.disk_total_gb ? Math.round(100 * (1 - s.disk_free_gb / s.disk_total_gb)) : 0;
  const PALETTE = ["var(--accent)", "var(--warn)", "#14b8a6", "#a855f7", "var(--muted)"];
  const colorFor = (name, i) => /fail|ошиб|error|отказ/i.test(name) ? "var(--bad)" : PALETTE[i % PALETTE.length];

  function stat(label, value, opts) {
    opts = opts || {};
    const s = el("div", "stat" + (opts.state && opts.state !== "ok" ? " " + opts.state : ""));
    s.append(el("span", "stat-label", label));
    const v = el("span", "stat-value" + (opts.long ? " long" : ""));
    v.textContent = value;
    if (opts.of != null) v.append(el("small", null, " / " + opts.of));
    s.append(v);
    if (opts.note) s.append(el("span", "stat-note" + (opts.noteCls ? " " + opts.noteCls : ""), opts.note));
    if (opts.hint) s.title = opts.hint;
    return s;
  }
  function kpiStat(k) {
    const txt = fmtValue(k.value, k.unit);
    let note = null, noteCls = null;
    if (typeof k.delta === "number") {
      note = (k.delta >= 0 ? "▲ +" : "▼ ") + nf(k.delta, 1) + " %" + (k.delta_label ? " " + k.delta_label : "");
      noteCls = k.delta >= 0 ? "pos" : "neg";
    }
    return stat(k.label, txt, {state: k.state, long: isLong(txt), note, noteCls, hint: k.hint});
  }

  /* ---------- графики (SVG) ---------- */
  function niceStep(raw) {
    const p = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= raw - 1e-12) return m * p;
    return 10 * p;
  }
  function compact(v, step) {
    if (v === 0) return "0";
    const a = Math.max(Math.abs(v), step || 0);
    const digits = (div) => Math.min(3, Math.max(0, Math.ceil(-Math.log10((step || div) / div) - 1e-9)));
    if (a >= 1e6) return nf(v / 1e6, digits(1e6)) + " млн";
    if (a >= 1e3) return nf(v / 1e3, digits(1e3)) + " тыс";
    return nf(v, digits(1));
  }
  function drawChart(box, chart, opts) {
    opts = opts || {};
    box.textContent = "";
    const series = (chart.series || []).filter((s) => s.points && s.points.length);
    if (!series.length) { box.append(el("p", "muted", "Нет данных за период")); return; }
    const xs = series[0].points.map((p) => p[0]);
    const withTime = xs.some((x) => x.length > 10);
    const W = Math.max(box.clientWidth, 200), H = opts.spark ? 44 : 220;
    const m = opts.spark ? {l: 0, r: 0, t: 3, b: 1} : {l: 52, r: 12, t: 10, b: 26};
    const ih = H - m.t - m.b;
    const stacked = chart.kind === "bar" && series.length > 1;
    const val = (s, i) => Number((s.points[i] || [])[1]) || 0;
    const totals = xs.map((_, i) => series.reduce((a, s) => a + val(s, i), 0));
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
    const minV = Math.floor(lo / step + 1e-9) * step, maxV = Math.ceil(hi / step - 1e-9) * step;
    if (!opts.spark) {
      let longest = 0;
      for (let v = minV; v <= maxV + step / 2; v += step) longest = Math.max(longest, compact(Math.abs(v) < step / 2 ? 0 : v, step).length);
      m.l = Math.max(36, Math.ceil(longest * 6.6) + 12);
    }
    const iw = W - m.l - m.r, colW = iw / xs.length;
    const xc = (i) => m.l + colW * i + colW / 2;
    const y = (v) => m.t + ih - (ih * (v - minV)) / (maxV - minV || 1);
    const root = svg("svg", {viewBox: `0 0 ${W} ${H}`, width: "100%", height: H, role: "img", "aria-label": chart.title || ""});
    if (!opts.spark) {
      for (let v = minV; v <= maxV + step / 2; v += step) {
        const zero = Math.abs(v) < step / 2;
        root.append(svg("line", {x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: zero && minV < 0 ? "pj-grid pj-zero" : "pj-grid"}));
        const t = svg("text", {x: m.l - 6, y: y(v) + 4, "text-anchor": "end", class: "pj-axis"});
        t.textContent = compact(zero ? 0 : v, step);
        root.append(t);
      }
      const every = Math.max(1, Math.ceil(xs.length / Math.max(2, Math.floor(iw / 56))));
      xs.forEach((x, i) => {
        const last = i === xs.length - 1;
        if ((i % every && !last) || (!last && xs.length - 1 - i < every)) return;
        const t = svg("text", {x: last ? W - m.r : i === 0 ? m.l : xc(i), y: H - 8, "text-anchor": last ? "end" : i === 0 ? "start" : "middle", class: "pj-axis"});
        t.textContent = withTime ? String(parseX(x).getHours()).padStart(2, "0") + ":00" : dm(x);
        root.append(t);
      });
    }
    if (chart.kind === "bar") {
      const bw = Math.max(1, Math.min(28, colW * 0.68));
      xs.forEach((_, i) => {
        let up = 0, down = 0;
        series.forEach((s, si) => {
          const v = val(s, i);
          if (!v) return;
          const base = !stacked ? 0 : v > 0 ? up : down;
          if (stacked) { if (v > 0) up += v; else down += v; }
          const top = y(Math.max(base, base + v)), bottom = y(Math.min(base, base + v));
          root.append(svg("rect", {x: xc(i) - bw / 2, y: top, width: bw, height: Math.max(1, bottom - top),
            rx: Math.min(3, bw / 2), fill: colorFor(s.name, si)}));
        });
      });
    } else {
      series.forEach((s, si) => {
        const pts = s.points.map((p, i) => [xc(i), y(Number(p[1]) || 0)]);
        const d = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
        if (series.length === 1) {
          const base = level ? y(minV) : y(Math.max(minV, Math.min(0, maxV)));
          root.append(svg("path", {d: d + ` L ${pts[pts.length - 1][0].toFixed(1)} ${base} L ${pts[0][0].toFixed(1)} ${base} Z`,
            fill: colorFor(s.name, si), opacity: 0.12}));
        }
        root.append(svg("path", {d, fill: "none", stroke: colorFor(s.name, si), "stroke-width": opts.spark ? 1.6 : 2,
          "stroke-linejoin": "round", "stroke-linecap": "round"}));
      });
    }
    box.append(root);
    if (opts.spark) return;
    if (series.length > 1) {
      const lg = el("div", "pj-legend");
      series.forEach((s, si) => { const it = el("span"); const sw = el("i"); sw.style.background = colorFor(s.name, si); it.append(sw, document.createTextNode(s.name)); lg.append(it); });
      box.append(lg);
    }
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
      tip.append(el("div", "pj-tip-x", withTime ? dm(xs[i]) + " " + String(parseX(xs[i]).getHours()).padStart(2, "0") + ":00" : dm(xs[i])));
      series.forEach((s, si) => {
        const row = el("div", "pj-tip-row"); const sw = el("i"); sw.style.background = colorFor(s.name, si);
        row.append(sw, el("span", null, s.name), el("b", null, fmtValue(val(s, i), chart.unit))); tip.append(row);
      });
      if (stacked) tip.append(el("div", "pj-tip-row pj-tip-sum", "Всего: " + fmtValue(totals[i], chart.unit)));
      tip.classList.remove("hidden");
      const left = (xc(i) / W) * r.width;
      tip.style.left = Math.min(r.width - tip.offsetWidth - 4, Math.max(4, left + 12)) + "px";
      tip.style.top = "8px";
    });
    root.addEventListener("mouseleave", () => { tip.classList.add("hidden"); cursor.setAttribute("visibility", "hidden"); });
  }

  /* ---------- общие блоки ---------- */
  function siteLine(p) {
    const parts = [];
    if (p.check) parts.push(p.check.http == null ? "сайт не отвечает" : p.check.http + " · " + nf(p.check.ms, 0) + " мс");
    if (p.tls) parts.push(p.tls.error ? "TLS: ошибка" : "TLS " + p.tls.days_left + " дн");
    return parts.join(" · ");
  }
  function attentionItems() {
    const items = [];
    (overview && overview.projects || []).forEach((p) => p.issues.forEach((r) => items.push({sev: r.severity, where: p.name, what: r.text, href: "#projects/" + p.id})));
    (metrics && metrics.servers || []).forEach((s) => {
      if (s.status !== "up") items.push({sev: "bad", where: "Серверы", what: s.name + ": нет связи", href: "#servers"});
      else if (diskPct(s) >= 85) items.push({sev: "warn", where: "Серверы", what: s.name + ": диск занят на " + diskPct(s) + " %", href: "#servers"});
    });
    return items.sort((a, b) => (a.sev === "bad" ? 0 : 1) - (b.sev === "bad" ? 0 : 1));
  }
  function attentionCard(items, title) {
    const card = el("section", "card attn");
    const head = el("div", "card-head");
    const nBad = items.filter((i) => i.sev === "bad").length;
    head.append(el("h2", null, title || "Требует внимания"), el("span", "muted", items.length ? `${nBad} срочно · ${items.length - nBad} проверить` : ""));
    card.append(head);
    if (!items.length) { card.append(el("div", "attn-empty", "Всё в норме")); return card; }
    items.forEach((it) => {
      const row = el("div", "attn-row");
      const open = el("a", null, "Открыть"); open.href = it.href || "#overview";
      row.append(el("span", null), el("span", "where", it.where), el("span", "what", it.what), open);
      row.firstChild.append(chip(it.sev, SEV[it.sev]));
      card.append(row);
    });
    return card;
  }
  function projectCard(p) {
    const a = p.analytics;
    const card = el("a", "pcard " + p.state);
    card.href = "#projects/" + p.id;
    const top = el("div", "pcard-top"), nm = el("div");
    nm.append(el("div", "pcard-name", p.name), el("div", "pcard-sub", p.stage || ""));
    top.append(nm, chip(p.state));
    card.append(top);
    if (a && a.kpis && a.kpis.length) {
      const k = el("div", "pcard-kpis");
      a.kpis.forEach((x) => {
        const cell = el("div");
        const txt = fmtValue(x.value, x.unit);
        cell.append(el("div", "pk-label", x.label), el("div", "pk-value" + (isLong(txt) ? " long" : "") + (x.state && x.state !== "ok" ? " " + x.state : ""), txt));
        if (typeof x.delta === "number") cell.append(el("div", "pk-delta " + (x.delta >= 0 ? "pos" : "neg"), (x.delta >= 0 ? "+" : "") + nf(x.delta, 1) + " %"));
        k.append(cell);
      });
      card.append(k);
    } else {
      card.append(el("p", "muted", a && a.error ? a.error : "Подробной аналитики нет — только сайт и сертификат"));
    }
    if (a && a.spark) {
      const sp = el("div", "pcard-spark");
      card.append(sp);
      requestAnimationFrame(() => drawChart(sp, a.spark, {spark: true}));
    }
    card.append(el("div", "pcard-foot", siteLine(p)));
    return card;
  }
  function allCerts() {
    const list = [];
    (overview && overview.projects || []).forEach((p) => { if (p.tls) list.push(p.tls); });
    (overview && overview.tls || []).forEach((c) => list.push(c));
    const seen = new Set();
    return list.filter((c) => !seen.has(c.host) && seen.add(c.host))
      .sort((a, b) => (a.days_left == null ? -1 : a.days_left) - (b.days_left == null ? -1 : b.days_left));
  }
  const certState = (c) => c.error || c.days_left < 21 ? "bad" : c.days_left < 45 ? "warn" : "ok";
  function certCard(full) {
    const card = el("section", "card");
    const head = el("div", "card-head");
    head.append(el("h2", null, "Сертификаты — до истечения"));
    if (!full) { const a = el("a", null, "Все сертификаты"); a.href = "#tls"; head.append(a); }
    card.append(head);
    const certs = allCerts(), MAX = 90;
    const tl = el("div", "tl"), zone = el("div", "tl-zone");
    zone.style.width = (100 * 21 / MAX) + "%";
    tl.append(zone);
    certs.forEach((c) => {
      if (c.days_left == null) return;
      const mk = el("div", "tl-mark " + certState(c));
      mk.style.left = Math.min(98, Math.max(1, 100 * c.days_left / MAX)) + "%";
      mk.title = c.host + " — " + c.days_left + " дн";
      tl.append(mk);
    });
    const scale = el("div", "tl-scale");
    ["сегодня", "21 дн", "45 дн", "90+ дн"].forEach((t) => scale.append(el("span", null, t)));
    card.append(tl, scale);
    const lst = el("div", "cert-list");
    (full ? certs : certs.slice(0, 6)).forEach((c) => {
      const st = certState(c);
      lst.append(el("span", null, c.host), chip(st, st === "ok" ? "в норме" : st === "warn" ? "скоро" : c.error ? "ошибка" : "срочно"),
        el("span", "d " + st, c.error ? "ошибка" : c.days_left + " дн · " + (c.expires ? dm(c.expires) + "." + c.expires.slice(0, 4) : "")));
    });
    card.append(lst);
    if (full) {
      const err = certs.filter((c) => c.error);
      if (err.length) card.append(el("p", "muted", "Ошибки проверки: " + err.map((c) => c.host + " — " + c.error).join("; ")));
    }
    return card;
  }
  function heatCard() {
    const card = el("section", "card");
    const head = el("div", "card-head");
    const a = el("a", null, "Все серверы"); a.href = "#servers";
    head.append(el("h2", null, "Серверы — нагрузка сейчас"), a);
    card.append(head);
    const heat = el("div", "heat");
    (metrics && metrics.servers || []).forEach((s) => {
      const t = el("a");
      t.href = "#servers";
      let cls = "";
      if (s.status !== "up") cls = "bad";
      else if (diskPct(s) >= 85) cls = "warn";
      else if ((s.cpu_percent || 0) >= 60) cls = "l3";
      else if ((s.cpu_percent || 0) >= 20) cls = "l2";
      t.className = cls;
      t.textContent = s.name;
      t.title = s.name + (s.status === "up" ? ` · CPU ${Math.round(s.cpu_percent || 0)} % · диск ${diskPct(s)} %` : " · нет связи");
      heat.append(t);
    });
    card.append(heat);
    const lg = el("div", "legend");
    [["до 20 % CPU", "color-mix(in srgb,var(--accent) 10%,var(--panel2))"], ["20–60 %", "color-mix(in srgb,var(--accent) 26%,var(--panel2))"],
     ["от 60 %", "color-mix(in srgb,var(--accent) 45%,var(--panel2))"], ["диск от 85 %", "color-mix(in srgb,var(--warn) 24%,var(--panel2))"],
     ["нет связи", "color-mix(in srgb,var(--bad) 22%,var(--panel2))"]].forEach(([t, c]) => { const s = el("span"); const i = el("i"); i.style.background = c; s.append(i, document.createTextNode(t)); lg.append(s); });
    card.append(lg);
    return card;
  }
  function viewHead(eyebrow, title, right) {
    const h = el("div", "view-head"), l = el("div");
    l.append(el("div", "eyebrow", eyebrow), el("h1", "view-title", title));
    h.append(l);
    if (right) h.append(right);
    return h;
  }
  const updated = () => overview && overview.generated_at
    ? "обновлено " + new Date(overview.generated_at).toLocaleString("ru-RU", {day: "numeric", month: "long", hour: "2-digit", minute: "2-digit"})
    : "";

  /* ---------- Обзор ---------- */
  function renderOverview() {
    const v = $("overviewView");
    v.textContent = "";
    if (!overview || !overview.ready) { v.append(el("p", "muted", "Сбор данных…")); return; }
    v.append(viewHead(updated(), "Обзор"));
    const ps = overview.projects, servers = (metrics && metrics.servers) || [];
    const okP = ps.filter((p) => p.state === "ok").length, warnP = ps.filter((p) => p.state !== "ok").length;
    const up = servers.filter((s) => s.status === "up").length;
    const down = servers.filter((s) => s.status !== "up");
    const rev = ps.filter((p) => p.analytics && typeof p.analytics.revenue_30d === "number");
    const revSum = rev.reduce((a, p) => a + p.analytics.revenue_30d, 0);
    const cert = allCerts()[0];
    const stats = el("section", "stats big");
    stats.setAttribute("aria-label", "Сводка");
    stats.append(
      stat("Проекты в норме", String(okP), {of: ps.length, note: warnP ? warnP + " с замечаниями" : "все в норме", noteCls: warnP ? "neg" : "pos"}),
      stat("Серверы на связи", String(up), {of: servers.length, state: down.length ? "bad" : "ok", note: down.length ? down.map((s) => s.name).join(", ") : "все отвечают"}),
      stat("Выручка за 30 дней", fmtValue(revSum, "₽"), {note: rev.map((p) => p.name + " " + fmtValue(p.analytics.revenue_30d, "")).join(" · ")}),
      stat("Ближайший сертификат", cert ? (cert.error ? "ошибка" : cert.days_left + " дн") : "—", {state: cert ? certState(cert) : "ok", note: cert ? cert.host : ""}),
    );
    v.append(stats, attentionCard(attentionItems()));
    const ph = el("div", "view-head"), pt = el("h2", "view-title", "Проекты");
    pt.style.fontSize = "18px";
    const all = el("a", null, "Все проекты"); all.href = "#projects";
    ph.append(pt, all);
    const grid = el("div", "pcards");
    const order = {bad: 0, warn: 1, ok: 2};
    ps.slice().sort((a, b) => order[a.state] - order[b.state]).forEach((p) => grid.append(projectCard(p)));
    const bottom = el("div", "grid2");
    bottom.append(heatCard(), certCard(false));
    v.append(ph, grid, bottom);
  }

  /* ---------- Проекты ---------- */
  function renderProjects() {
    const v = $("projectsView");
    v.textContent = "";
    if (!overview || !overview.ready) { v.append(el("p", "muted", "Сбор данных…")); return; }
    const filters = el("div", "filters");
    filters.setAttribute("role", "group"); filters.setAttribute("aria-label", "Фильтр");
    const issues = overview.projects.filter((p) => p.state !== "ok").length;
    [["all", "Все · " + overview.projects.length], ["issues", "С замечаниями · " + issues], ["money", "Деньги"]].forEach(([k, t]) => {
      const b = el("button", k === "issues" && issues ? "warn" : "", t);
      b.type = "button"; b.setAttribute("aria-pressed", String(projFilter === k));
      b.addEventListener("click", () => { projFilter = k; renderProjects(); });
      filters.append(b);
    });
    v.append(viewHead(updated() + " · проверка раз в " + Math.round(overview.refresh_sec / 60) + " мин", "Проекты", filters));
    let ps = overview.projects.slice();
    if (projFilter === "issues") ps = ps.filter((p) => p.state !== "ok");
    if (projFilter === "money") ps = ps.filter((p) => p.analytics && typeof p.analytics.revenue_30d === "number");
    const order = {bad: 0, warn: 1, ok: 2};
    const grid = el("div", "pcards");
    ps.sort((a, b) => order[a.state] - order[b.state]).forEach((p) => grid.append(projectCard(p)));
    if (!ps.length) grid.append(el("p", "muted", "Нет проектов под этот фильтр"));
    v.append(grid);
  }

  function tableCard(tb) {
    const card = el("section", "card tcard");
    const head = el("div", "card-head"); head.append(el("h2", null, tb.title)); card.append(head);
    const wrap = el("div", "tscroll"), table = el("table", "ptable"), thead = el("thead"), hr = el("tr");
    (tb.columns || []).forEach((c) => hr.append(el("th", c.num ? "num" : "", c.label)));
    thead.append(hr);
    const body = el("tbody");
    (tb.rows || []).forEach((r) => {
      const tr = el("tr");
      (tb.columns || []).forEach((c) => {
        const v = r[c.key], td = el("td", c.num ? "num" : "");
        if (c.state) td.append(chip(v, {ok: "норма", warn: "внимание", bad: "проблема"}[v] || String(v)));
        else if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v)) td.textContent = v.slice(8) + "." + v.slice(5, 7) + "." + v.slice(0, 4);
        else td.textContent = v == null || v === "" ? "—" : c.num && typeof v === "number" ? fmtValue(v, c.unit) : String(v);
        tr.append(td);
      });
      body.append(tr);
    });
    if (!(tb.rows || []).length) { const tr = el("tr"), td = el("td", "muted", "Пусто"); td.colSpan = (tb.columns || []).length || 1; tr.append(td); body.append(tr); }
    table.append(thead, body); wrap.append(table); card.append(wrap);
    return card;
  }
  function matrixCard(mx) {
    const card = el("section", "card");
    const head = el("div", "card-head"); head.append(el("h2", null, mx.title)); if (mx.note) head.append(el("span", "muted", mx.note));
    card.append(head);
    const cols = mx.columns || [];
    const grid = el("div", "matrix");
    grid.style.gridTemplateColumns = `56px repeat(${cols.length}, minmax(22px, 1fr)) auto`;
    grid.append(el("span"));
    cols.forEach((c) => grid.append(el("span", "mh", c)));
    grid.append(el("span", "mh", ""));
    (mx.rows || []).forEach((r) => {
      grid.append(el("span", "mr", r.label));
      (r.cells || []).forEach((c) => { const cell = el("span", "mc " + (c.state === "ok" ? "" : c.state)); cell.title = c.title || ""; grid.append(cell); });
      grid.append(el("span", "mv", r.value || ""));
    });
    card.append(grid);
    const lg = el("div", "legend");
    [["выход жив", "color-mix(in srgb,var(--ok) 50%,transparent)"], ["не отвечает", "color-mix(in srgb,var(--bad) 60%,transparent)"], ["выключен или нет на копии", "transparent"]].forEach(([t, c], i) => {
      const s = el("span"), sw = el("i"); sw.style.background = c; if (i === 2) sw.style.border = "1px dashed var(--muted)"; s.append(sw, document.createTextNode(t)); lg.append(s);
    });
    card.append(lg);
    return card;
  }

  async function renderProject(id) {
    const v = $("projectsView");
    let p;
    try {
      const r = await fetch("/api/projects/" + encodeURIComponent(id), {cache: "no-store"});
      if (!r.ok) throw new Error("HTTP " + r.status);
      p = await r.json();
    } catch (err) {
      v.textContent = ""; v.append(el("p", "muted", "Не удалось загрузить проект: " + err.message)); return;
    }
    if (current.id !== id) return;
    v.textContent = "";
    const crumbs = el("div", "crumbs"), a1 = el("a", null, "Обзор"), a2 = el("a", null, "Проекты");
    a1.href = "#overview"; a2.href = "#projects";
    crumbs.append(a1, document.createTextNode(" / "), a2, document.createTextNode(" / " + p.name));
    v.append(crumbs);
    const right = el("div", "filters");
    right.append(chip(p.state, p.state === "ok" ? "работает" : p.state === "warn" ? "есть замечания" : "проблема"));
    if (p.link) { const a = el("a", "btn", "Открыть сайт ↗"); a.href = p.link; a.target = "_blank"; a.rel = "noopener"; right.append(a); }
    const an = p.analytics;
    v.append(viewHead([p.stage, siteLine(p), an && an.age_min != null ? "данные " + ago(an.age_min) : ""].filter(Boolean).join(" · "), p.name, right));
    p.issues.forEach((r) => { const d = el("div", "issue" + (r.severity === "bad" ? " bad" : "")); d.append(chip(r.severity, SEV[r.severity]), el("span", null, r.text)); v.append(d); });
    if (!an || an.error) { v.append(el("p", "muted", an && an.error ? an.error : "Подробная аналитика не подключена: видны сайт и сертификат.")); return; }
    if ((an.kpis || []).length) { const s = el("section", "stats"); s.setAttribute("aria-label", "Ключевые цифры"); an.kpis.forEach((k) => s.append(kpiStat(k))); v.append(s); }
    const blocks = [];
    (an.matrices || []).forEach((mx) => blocks.push(matrixCard(mx)));
    (an.charts || []).forEach((c) => {
      const card = el("section", "card"), head = el("div", "card-head");
      head.append(el("h2", null, c.title)); if (c.note) head.append(el("span", "muted", c.note));
      const box = el("div", "pj-chart");
      card.append(head, box); blocks.push(card);
      requestAnimationFrame(() => drawChart(box, c));
    });
    if (blocks.length) { const g = el("div", "grid2"); blocks.forEach((b) => g.append(b)); v.append(g); }
    (an.tables || []).forEach((tb) => v.append(tableCard(tb)));
  }

  /* ---------- Серверы (сводка над таблицей app.js) и Сертификаты ---------- */
  function renderServersSummary() {
    const box = $("srvSummary");
    if (!box) return;
    box.textContent = "";
    const servers = (metrics && metrics.servers) || [];
    if (!servers.length) return;
    box.className = "stats";
    const up = servers.filter((s) => s.status === "up");
    const down = servers.filter((s) => s.status !== "up");
    const maxCpu = up.reduce((a, s) => (s.cpu_percent || 0) > (a.cpu_percent || 0) ? s : a, up[0] || {});
    const maxDisk = up.reduce((a, s) => diskPct(s) > diskPct(a) ? s : a, up[0] || {});
    const traffic = servers.reduce((a, s) => a + (s.traffic_1d_gb || 0), 0);
    const topT = servers.reduce((a, s) => (s.traffic_1d_gb || 0) > (a.traffic_1d_gb || 0) ? s : a, servers[0]);
    box.append(
      stat("На связи", String(up.length), {of: servers.length, state: down.length ? "bad" : "ok", note: down.length ? down.map((s) => s.name).join(", ") + " — нет ответа" : "все отвечают"}),
      stat("Макс. CPU", maxCpu.name ? Math.round(maxCpu.cpu_percent || 0) + " %" : "—", {state: (maxCpu.cpu_percent || 0) >= 80 ? "warn" : "ok", note: maxCpu.name || ""}),
      stat("Макс. диск", maxDisk.name ? diskPct(maxDisk) + " %" : "—", {state: diskPct(maxDisk) >= 85 ? "warn" : "ok", note: maxDisk.name ? maxDisk.name + " · свободно " + nf(maxDisk.disk_free_gb, 1) + " ГБ" : ""}),
      stat("Трафик за сутки", traffic >= 1000 ? nf(traffic / 1000, 2) + " ТБ" : Math.round(traffic) + " ГБ", {note: topT ? Math.round(topT.traffic_1d_gb || 0) + " ГБ — " + topT.name : ""}),
    );
  }
  function renderTls() {
    const v = $("tlsView");
    v.textContent = "";
    if (!overview || !overview.ready) { v.append(el("p", "muted", "Сбор данных…")); return; }
    v.append(viewHead("проверка раз в " + Math.round(overview.refresh_sec / 60) + " мин · предупреждение за 45 дней, срочно — за 21", "Сертификаты"), certCard(true));
  }

  /* ---------- меню ---------- */
  function renderRail() {
    document.querySelectorAll(".rail-nav > a").forEach((a) => a.classList.toggle("active", a.dataset.view === current.view));
    const sub = $("railProjects");
    sub.textContent = "";
    if (overview && overview.ready) {
      overview.projects.forEach((p) => {
        const a = el("a", current.id === p.id ? "active" : "");
        a.href = "#projects/" + p.id;
        a.append(el("span", null, p.name), el("span", "sdot " + p.state));
        sub.append(a);
      });
      const issues = overview.projects.filter((p) => p.state !== "ok").length;
      const cp = $("cntProjects"); cp.textContent = issues ? String(issues) : String(overview.projects.length); cp.className = "cnt" + (issues ? " warn" : "");
      const soon = allCerts().filter((c) => certState(c) !== "ok").length;
      const ct = $("cntTls"); ct.textContent = soon ? String(soon) : ""; ct.className = "cnt" + (soon ? " warn" : "");
    }
    const servers = (metrics && metrics.servers) || [];
    const down = servers.filter((s) => s.status !== "up").length;
    const cs = $("cntServers"); cs.textContent = down ? String(down) : servers.length ? String(servers.length) : ""; cs.className = "cnt" + (down ? " bad" : "");
    const st = $("railStatus");
    if (metrics && metrics.generated_at) {
      st.textContent = "серверы · " + (metrics.refresh_interval_sec || "") + " с · проекты · " + (overview ? Math.round(overview.refresh_sec / 60) : 5) + " мин";
    }
  }

  /* ---------- данные и навигация ---------- */
  async function load() {
    try {
      const [pr, mr] = await Promise.all([fetch("/api/projects", {cache: "no-store"}), fetch("/api/metrics", {cache: "no-store"})]);
      if (pr.ok) overview = await pr.json();
      if (mr.ok) metrics = await mr.json();
      if (overview && overview.server_groups && JSON.stringify(window.infoServerGroups) !== JSON.stringify(overview.server_groups)) {
        window.infoServerGroups = overview.server_groups;
        if (typeof renderTable === "function") renderTable();
      }
      $("railDot").classList.toggle("stale", !(pr.ok && mr.ok));
      /* до входа API отвечает 401 — пробуем снова через 5 с, чтобы разделы ожили сразу после логина */
      if ((pr.status === 401 || mr.status === 401) && !retrying) { retrying = true; setTimeout(() => { retrying = false; tick(); }, 5000); }
    } catch (err) {
      $("railDot").classList.add("stale");
    }
  }
  function parseHash() {
    const m = location.hash.match(/^#(overview|projects|servers|tls)(?:\/([a-z0-9_-]+))?$/);
    return m ? {view: m[1], id: m[1] === "projects" ? m[2] || null : null} : {view: "overview", id: null};
  }
  function paint() {
    VIEWS.forEach((v) => $(v + "View").classList.toggle("hidden", v !== current.view));
    renderRail();
    if (current.view === "overview") renderOverview();
    else if (current.view === "projects") { if (current.id) renderProject(current.id); else renderProjects(); }
    else if (current.view === "servers") renderServersSummary();
    else if (current.view === "tls") renderTls();
  }
  async function route(scroll) {
    current = parseHash();
    paint();
    if (scroll) window.scrollTo(0, 0);
  }
  async function tick() {
    await load();
    if (document.hidden) return;
    paint();
  }
  window.addEventListener("hashchange", () => route(true));
  let resizeT = null;
  window.addEventListener("resize", () => { clearTimeout(resizeT); resizeT = setTimeout(paint, 250); });
  (async () => {
    if (!location.hash) history.replaceState(null, "", "#overview");
    current = parseHash();
    paint();
    await load();
    paint();
    timer = setInterval(tick, 60000);
  })();
})();
