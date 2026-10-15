/* Разделы info: Обзор, Проекты (+ страница проекта), Серверы, Сертификаты.
   Таблицу серверов, формы и вход ведёт app.js; здесь — навигация, обзор, проекты и сертификаты.
   Данные: /api/projects, /api/projects/<id> (формат docs/analytics-schema.md), /api/metrics. */
(function () {
  "use strict";
  const VIEWS = ["overview", "projects", "servers", "tls"];
  const SVG = "http://www.w3.org/2000/svg";
  const STATE = {ok: "норма", warn: "замечания", bad: "проблема"};
  const SEV = {bad: "Срочно", warn: "Проверить"};
  let overview = null, metrics = null, current = {view: "overview", id: null}, timer = null, projFilter = "all", retrying = false, details = {};

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
  const isMonth = (x) => /^\d{4}-\d{2}$/.test(x);
  const parseX = (x) => new Date(isMonth(x) ? x + "-01T00:00:00" : /^\d{4}-\d{2}-\d{2}$/.test(x) ? x + "T00:00:00" : x);
  const MON = ["янв", "фев", "мар", "апр", "май", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"];
  const MONTH = ["январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь"];
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
    /* знаков столько, чтобы шаг в выбранных единицах был точным: 2 500 → «2,5 тыс», а не «3 тыс» */
    const digits = (div) => { const q = (step || div) / div; let d = 0; while (d < 3 && Math.abs(Math.round(q * 10 ** d) - q * 10 ** d) > 1e-9) d++; return d; };
    if (a >= 1e6) return nf(v / 1e6, digits(1e6)) + " млн";
    if (a >= 1e3) return nf(v / 1e3, digits(1e3)) + " тыс";
    return nf(v, digits(1));
  }
  function drawChart(box, chart, opts) {
    opts = opts || {};
    box.textContent = "";
    let series = (chart.series || []).filter((s) => s.points && s.points.length);
    /* помесячный ряд: месяцы до первых данных не показываем — иначе пол-графика пустые нули */
    if (series.length && isMonth(series[0].points[0][0])) {
      let first = 0;
      while (first < series[0].points.length - 1 && series.every((s) => !Number((s.points[first] || [])[1]))) first++;
      if (first) series = series.map((s) => ({...s, points: s.points.slice(first)}));
    }
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
        t.textContent = isMonth(x) ? MON[parseX(x).getMonth()] : withTime ? String(parseX(x).getHours()).padStart(2, "0") + ":00" : dm(x);
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
      const xd = parseX(xs[i]);
      tip.append(el("div", "pj-tip-x", isMonth(xs[i]) ? MONTH[xd.getMonth()] + " " + xd.getFullYear()
        : withTime ? dm(xs[i]) + " " + String(xd.getHours()).padStart(2, "0") + ":00" : dm(xs[i])));
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

  /* ---------- связанные выводы ---------- */
  const plural = (n, one, few, many) => {
    const a = Math.abs(n) % 100, b = a % 10;
    return a > 10 && a < 20 ? many : b === 1 ? one : b >= 2 && b <= 4 ? few : many;
  };
  const SNOOZE_KEY = "info.snooze";
  function snoozed() {
    try { const s = JSON.parse(localStorage.getItem(SNOOZE_KEY) || "{}"); const now = Date.now(); return Object.fromEntries(Object.entries(s).filter(([, t]) => t > now)); }
    catch (e) { return {}; }
  }
  function snooze(key) {
    try { const s = snoozed(); s[key] = Date.now() + 24 * 3600 * 1000; localStorage.setItem(SNOOZE_KEY, JSON.stringify(s)); }
    catch (e) { /* приватный режим: отложить не получится, пункт останется */ }
  }
  /* Все матрицы связности из подробных документов проектов (сейчас — OneYearSolution). */
  const allMatrices = () => Object.values(details).flatMap((d) => (d && d.analytics && d.analytics.matrices) || []);
  /* Живые VPN-выходы через сервер с таким именем: «up0 · Финляндия · 15 мс» → {exit, ping, copy}. */
  function liveExitsVia(name) {
    const out = [];
    allMatrices().forEach((mx) => (mx.rows || []).forEach((r) => (r.cells || []).forEach((c) => {
      const parts = String(c.title || "").split(" · ");
      if (c.state === "ok" && parts[1] === name) {
        const ping = (parts[2] || "").match(/(\d+)\s*мс/);
        out.push({exit: parts[0], copy: r.label, ping: ping ? Number(ping[1]) : null});
      }
    })));
    return out;
  }
  function insights() {
    const items = [];
    (metrics && metrics.servers || []).forEach((s) => {
      const href = "#servers/" + encodeURIComponent(s.name);
      if (s.status !== "up") {
        const exits = liveExitsVia(s.name);
        let text = "Мониторинг не получает данные по SSH.";
        if (exits.length) {
          const best = exits.filter((e) => e.ping != null).sort((a, b) => a.ping - b.ping)[0] || exits[0];
          text = `VPN-выход ${best.exit} через этот сервер при этом жив` + (best.ping != null ? `: пинг ${best.ping} мс с ${best.copy}` : "") +
            ". Клиенты не страдают — не работает канал мониторинга.";
        }
        items.push({key: "srv-down:" + s.name, sev: "bad", title: s.name + ": SSH не отвечает", text, src: "серверы", href, kind: "server"});
      } else if (diskPct(s) >= 85) {
        items.push({key: "srv-disk:" + s.name, sev: "warn", title: `${s.name}: диск ${diskPct(s)} %`, text: `Свободно ${nf(s.disk_free_gb, 1)} ГБ из ${nf(s.disk_total_gb, 1)}.`, src: "серверы", href, kind: "server"});
      }
    });
    (overview && overview.projects || []).forEach((p) => p.issues.forEach((r) => {
      /* сроки сертификатов собираем ниже одним пунктом на дату */
      if (/^сертификат истекает/.test(r.text)) return;
      items.push({key: "prj:" + p.id + ":" + r.text, sev: r.severity, title: r.text, text: "", src: p.name, href: "#projects/" + p.id, kind: "project"});
    }));
    const byDate = {};
    allCerts().forEach((c) => {
      const st = certState(c);
      if (st === "ok") return;
      const k = c.error ? "ошибка" : c.expires;
      (byDate[k] = byDate[k] || {st, days: c.days_left, hosts: [], error: c.error}).hosts.push(c.host);
    });
    Object.entries(byDate).forEach(([date, g]) => {
      const n = g.hosts.length;
      items.push({key: "tls:" + date, sev: g.st, kind: "tls", src: "сертификаты", href: "#tls",
        title: g.error ? `${n} ${plural(n, "сертификат", "сертификата", "сертификатов")} не проверяется` :
          `${n} ${plural(n, "сертификат истекает", "сертификата истекают", "сертификатов истекают")} ${dm(date)}`,
        text: g.hosts.join(", ") + (g.error ? "" : ` — через ${g.days} ${plural(g.days, "день", "дня", "дней")}. Проверить автопродление.`)});
    });
    return items.sort((a, b) => (a.sev === "bad" ? 0 : 1) - (b.sev === "bad" ? 0 : 1));
  }
  function headline(items) {
    const bad = items.filter((i) => i.sev === "bad"), warn = items.filter((i) => i.sev !== "bad");
    const parts = [];
    const srv = bad.filter((i) => i.kind === "server").length, prj = bad.filter((i) => i.kind === "project").length, tls = bad.filter((i) => i.kind === "tls").length;
    if (srv) parts.push(`${srv} ${plural(srv, "сервера", "серверов", "серверов")}`);
    if (prj) parts.push(`${prj} ${plural(prj, "проблемы в проекте", "проблем в проектах", "проблем в проектах")}`);
    if (tls) parts.push("сертификатов");
    const h = el("h1", "headline");
    if (parts.length) { h.append(document.createTextNode("Всё работает, кроме "), el("span", "hl-bad", parts.join(" и ")), document.createTextNode(".")); }
    else h.append(document.createTextNode("Всё работает."));
    if (warn.length) { h.append(el("br")); h.append(el("span", "hl-sub", `${warn.length === 1 ? "Ещё 1 пункт" : `Ещё ${warn.length} ${plural(warn.length, "пункт", "пункта", "пунктов")}`} стоит проверить.`)); }
    else if (!parts.length) { h.append(el("br")); h.append(el("span", "hl-sub", "Замечаний нет.")); }
    return h;
  }
  function attentionV2(items) {
    const hidden = snoozed();
    const shown = items.filter((i) => !hidden[i.key]);
    const nHidden = items.length - shown.length;
    const showAll = el("button", "btn small ghost", `Отложено: ${nHidden} — показать`);
    showAll.type = "button";
    showAll.addEventListener("click", () => { try { localStorage.removeItem(SNOOZE_KEY); } catch (e) { /* ничего */ } renderOverview(); });
    if (!shown.length) {
      /* нечего показывать — одна строка вместо пустой карточки */
      const bar = el("section", "attn-bar");
      bar.append(el("span", "ins-dot ok"), el("span", null, items.length ? "Срочного нет — всё отложенное вернётся через сутки" : "Всё в норме, замечаний нет"));
      if (nHidden) bar.append(showAll);
      return bar;
    }
    const card = el("section", "card attn2");
    const head = el("div", "card-head");
    const nb = shown.filter((i) => i.sev === "bad").length;
    head.append(el("h2", null, "Требует внимания"), el("span", "muted", (nb ? nb + " срочно · " : "") + (shown.length - nb) + " проверить · с учётом всех источников"));
    if (nHidden) head.append(showAll);
    card.append(head);
    const grid = el("div", "ins-grid");
    shown.forEach((it) => {
      const row = el("div", "ins");
      row.append(el("span", "ins-dot " + it.sev));
      const body = el("div", "ins-body"), top = el("div", "ins-top");
      top.append(el("b", null, it.title), el("span", "ins-src", it.src));
      body.append(top);
      if (it.text) body.append(el("div", "ins-text", it.text));
      const acts = el("div", "ins-acts");
      const open = el("a", "btn small", it.kind === "server" ? "Открыть сервер" : "Открыть"); open.href = it.href;
      const later = el("button", "btn small ghost", "Отложить на сутки"); later.type = "button";
      later.addEventListener("click", () => { snooze(it.key); renderOverview(); renderRail(); });
      acts.append(open, later);
      body.append(acts);
      row.append(body);
      grid.append(row);
    });
    card.append(grid);
    return card;
  }

  /* ---------- доход по месяцам ---------- */
  function moneyCards() {
    const out = [];
    Object.values(details).forEach((d) => {
      const a = d && d.analytics;
      const k = a && (a.kpis || []).find((x) => x.id === "revenue_month");
      if (!k) return;
      const prev = (a.kpis || []).find((x) => x.id === "revenue_prev_month");
      const chart = (a.charts || []).find((c) => c.id === "revenue_monthly");
      const card = el("section", "card money");
      card.id = "money";
      const head = el("div", "card-head"); head.append(el("h2", null, d.name + " — доход"), el("span", "muted", k.hint || ""));
      card.append(head);
      const row = el("div", "money-row");
      const main = el("div"); main.append(el("div", "stat-label", k.label), el("div", "money-value", fmtValue(k.value, k.unit)));
      row.append(main);
      if (typeof k.delta === "number") {
        const d2 = el("div", "money-delta");
        d2.append(el("div", k.delta >= 0 ? "pos" : "neg", (k.delta >= 0 ? "▲ +" : "▼ ") + nf(k.delta, 1) + " % " + (k.delta_label || "")));
        row.append(d2);
      }
      if (prev) { const p = el("div"); p.append(el("div", "stat-label", prev.label), el("div", "money-prev", fmtValue(prev.value, prev.unit))); row.append(p); }
      card.append(row);
      if (chart) { const box = el("div", "pj-chart money-chart"); card.append(box); requestAnimationFrame(() => drawChart(box, chart)); }
      out.push(card);
    });
    return out;
  }

  /* ---------- матрица связности с пингом ---------- */
  function matrixGrid(mx, serversRows) {
    const cols = mx.columns || [];
    const country = {};
    (serversRows || []).forEach((s) => { if (s.name && s.country) country[s.name] = s.country; });
    /* подпись колонки — страна ноды-выхода (FI, FI2…), имя ноды берём из подсказок клеток */
    const seen = {};
    const heads = cols.map((c, i) => {
      let node = null;
      (mx.rows || []).forEach((r) => { const t = String(((r.cells || [])[i] || {}).title || "").split(" · "); if (!node && t[1] && !/выключен|нет на этой|не ответила/.test(t[1])) node = t[1]; });
      if (!node) return {label: c, title: c};
      const cc = country[node] && country[node] !== "—" ? country[node] : node.slice(0, 3);
      seen[cc] = (seen[cc] || 0) + 1;
      return {label: seen[cc] > 1 ? cc + seen[cc] : cc, title: c + " · " + node};
    });
    const grid = el("div", "matrix ping");
    grid.style.gridTemplateColumns = `48px repeat(${cols.length}, minmax(30px, 1fr)) auto`;
    grid.append(el("span"));
    heads.forEach((h) => { const s = el("span", "mh", h.label); s.title = h.title; grid.append(s); });
    grid.append(el("span", "mh", ""));
    (mx.rows || []).forEach((r) => {
      grid.append(el("span", "mr", r.label));
      (r.cells || []).forEach((c) => {
        const ping = String(c.title || "").match(/(\d+)\s*мс/);
        let cls = "mc", txt = "";
        if (c.state === "ok") { const p = ping ? Number(ping[1]) : null; txt = p != null ? String(p) : "ок"; cls += p != null && p >= 40 ? " slow" : ""; }
        else if (c.state === "bad") { cls += " bad"; txt = "нет"; }
        else { cls += " off"; txt = /выключен/.test(c.title || "") ? "выкл" : "—"; }
        const cell = el("span", cls, txt); cell.title = c.title || ""; grid.append(cell);
      });
      grid.append(el("span", "mv", r.value || ""));
    });
    return grid;
  }
  function matrixLegend() {
    const lg = el("div", "legend");
    [["до 40 мс", "color-mix(in srgb,var(--ok) 28%,transparent)"], ["40 мс и больше", "color-mix(in srgb,var(--warn) 24%,transparent)"],
     ["не отвечает", "color-mix(in srgb,var(--bad) 55%,transparent)"], ["выключен или нет на копии", "transparent"]].forEach(([t, c], i) => {
      const s = el("span"), sw = el("i"); sw.style.background = c; if (i === 3) sw.style.border = "1px dashed var(--muted)"; s.append(sw, document.createTextNode(t)); lg.append(s);
    });
    return lg;
  }
  function matrixCard(mx, serversRows) {
    const card = el("section", "card");
    const head = el("div", "card-head"); head.append(el("h2", null, mx.title)); head.append(el("span", "muted", "пинг, мс" + (mx.note ? " · " + mx.note : "")));
    card.append(head, matrixGrid(mx, serversRows), matrixLegend());
    return card;
  }
  const serversTableOf = (an) => ((an && an.tables) || []).find((t) => t.id === "servers");

  /* ---------- проекты плотным списком ---------- */
  let listSort = "issues";
  function projectList() {
    const card = el("section", "card tcard");
    card.id = "projects-list";
    const head = el("div", "card-head");
    const f = el("div", "filters");
    [["issues", "Сначала проблемы"], ["money", "По доходу"]].forEach(([k, t]) => {
      const b = el("button", "", t); b.type = "button"; b.setAttribute("aria-pressed", String(listSort === k));
      b.addEventListener("click", () => { listSort = k; renderOverview(); });
      f.append(b);
    });
    head.append(el("h2", null, "Проекты"), f);
    card.append(head);
    const order = {bad: 0, warn: 1, ok: 2};
    const money = (p) => { const k = ((p.analytics && p.analytics.kpis) || []).find((x) => x.unit === "₽" || x.unit === "$"); return k && typeof k.value === "number" ? (k.unit === "$" ? k.value * 80 : k.value) : -1; };
    const ps = overview.projects.slice().sort(listSort === "money" ? (a, b) => money(b) - money(a) : (a, b) => order[a.state] - order[b.state]);
    const wrap = el("div", "tscroll"), list = el("div", "plist");
    ["", "Проект", "Главное", "Деньги", "Ещё", "Динамика", "Сайт · TLS"].forEach((t, i) => list.append(el("span", "ph" + (i === 6 ? " r" : ""), t)));
    ps.forEach((p) => {
      const ks = (p.analytics && p.analytics.kpis) || [];
      const moneyK = ks.find((x) => x.unit === "₽" || x.unit === "$");
      const rest = ks.filter((x) => x !== moneyK);
      const cell = (k) => {
        const s = el("span", "pc");
        if (!k) { s.append(el("span", "faint", "—")); return s; }
        const txt = fmtValue(k.value, k.unit);
        s.append(el("span", isLong(txt) ? "" : "mono", txt), el("span", "pl", " " + k.label.toLowerCase()));
        if (typeof k.delta === "number") s.append(el("span", k.delta >= 0 ? "pos" : "neg", " " + (k.delta >= 0 ? "+" : "") + nf(k.delta, 1) + " %"));
        return s;
      };
      const dot = el("span", "pc"); dot.append(el("span", "sdot " + p.state));
      const name = el("a", "pc pname"); name.href = "#projects/" + p.id;
      name.append(el("b", null, p.name), el("br"), el("span", "pl", p.stage || ""));
      const spark = el("span", "pc pspark");
      if (p.analytics && p.analytics.spark) requestAnimationFrame(() => drawChart(spark, p.analytics.spark, {spark: true}));
      else spark.append(el("span", "faint", p.analytics && p.analytics.error ? "нет данных" : "—"));
      list.append(dot, name, cell(rest[0]), cell(moneyK), cell(rest[1]), spark, el("span", "pc r mono pl", siteLine(p)));
    });
    wrap.append(list); card.append(wrap);
    return card;
  }

  /* ---------- трафик по серверам ---------- */
  let trafficPeriod = "1d";
  const gb = (v) => v == null ? "—" : v >= 1000 ? nf(v / 1000, 2) + " ТБ" : v >= 10 ? Math.round(v) + " ГБ" : nf(v, 1) + " ГБ";
  function trafficCard() {
    const card = el("section", "card");
    card.id = "traffic";
    const head = el("div", "card-head"), f = el("div", "filters");
    const monthLabel = "С 1 " + ["января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"][new Date().getUTCMonth()];
    /* с 1-го числа, а не 30 дней: лимиты трафика у хостеров считаются с начала месяца */
    [["1d", "Сутки"], ["month", monthLabel]].forEach(([k, t]) => {
      const b = el("button", "", t); b.type = "button"; b.setAttribute("aria-pressed", String(trafficPeriod === k));
      b.addEventListener("click", () => { trafficPeriod = k; renderOverview(); });
      f.append(b);
    });
    head.append(el("h2", null, "Трафик по серверам"), f);
    card.append(head);
    const key = trafficPeriod === "1d" ? "traffic_1d_gb" : "traffic_month_gb";
    const servers = ((metrics && metrics.servers) || []).filter((s) => s[key] != null).sort((a, b) => (b[key] || 0) - (a[key] || 0));
    if (!servers.length) { card.append(el("p", "muted", "Нет данных о трафике")); return card; }
    const total = servers.reduce((a, s) => a + (s[key] || 0), 0), max = servers[0][key] || 1;
    card.append(el("div", "muted tr-total", "Всего " + gb(total) + (trafficPeriod === "1d" ? " за сутки" : " " + monthLabel.toLowerCase()) + " · сейчас приём / отдача, Мбит/с"));
    const list = el("div", "tr-list");
    servers.forEach((s) => {
      const row = el("a", "tr-row" + (s.status !== "up" ? " down" : ""));
      row.href = "#servers/" + encodeURIComponent(s.name);
      const bar = el("span", "tr-bar"), fill = el("i");
      fill.style.width = Math.max(1, 100 * (s[key] || 0) / max) + "%";
      bar.append(fill);
      row.append(el("span", "tr-name", s.name), bar, el("span", "tr-v mono", gb(s[key])),
        el("span", "tr-now mono", s.status === "up" ? nf(s.rx_mbps || 0, 1) + " / " + nf(s.tx_mbps || 0, 1) : "нет связи"));
      row.title = `${s.name}: ${gb(s[key])}, сейчас приём ${nf(s.rx_mbps || 0, 1)} и отдача ${nf(s.tx_mbps || 0, 1)} Мбит/с`;
      list.append(row);
    });
    card.append(list);
    return card;
  }

  /* ---------- серверы по ролям ---------- */
  function rolesCard() {
    const card = el("section", "card");
    const head = el("div", "card-head"); const a = el("a", null, "Таблица"); a.href = "#servers";
    head.append(el("h2", null, "Серверы по ролям"), a);
    card.append(head);
    const servers = (metrics && metrics.servers) || [];
    const groups = (overview && overview.server_groups && overview.server_groups.length) ? overview.server_groups : [{title: "Все", servers: servers.map((s) => s.name)}];
    const used = new Set();
    const rows = groups.map((g) => ({title: g.title, list: (g.servers || []).map((n) => servers.find((s) => s.name === n)).filter(Boolean)}));
    rows.forEach((r) => r.list.forEach((s) => used.add(s.name)));
    const rest = servers.filter((s) => !used.has(s.name));
    if (rest.length) rows.push({title: "Прочие", list: rest});
    rows.forEach((r) => {
      if (!r.list.length) return;
      const line = el("div", "role-row");
      line.append(el("span", "muted", r.title));
      const tiles = el("div", "heat");
      r.list.forEach((s) => {
        const t = el("a"); t.href = "#servers/" + encodeURIComponent(s.name);
        let cls = "";
        if (s.status !== "up") cls = "bad"; else if (diskPct(s) >= 85) cls = "warn"; else if ((s.cpu_percent || 0) >= 60) cls = "l3"; else if ((s.cpu_percent || 0) >= 20) cls = "l2";
        t.className = cls;
        t.textContent = s.name + (s.status === "up" ? " · " + Math.round(s.cpu_percent || 0) + " %" : "");
        t.title = s.name + (s.status === "up" ? ` · CPU ${Math.round(s.cpu_percent || 0)} % · диск ${diskPct(s)} %` : " · нет связи");
        tiles.append(t);
      });
      line.append(tiles);
      card.append(line);
    });
    return card;
  }

  /* ---------- Обзор (v2) ---------- */
  function renderOverview() {
    const v = $("overviewView");
    v.textContent = "";
    if (!overview || !overview.ready) { v.append(el("p", "muted", "Сбор данных…")); return; }
    const items = insights();
    const servers = (metrics && metrics.servers) || [];
    const ps = overview.projects;
    const top = el("section", "hero");
    const left = el("div");
    left.append(el("div", "eyebrow", new Date().toLocaleDateString("ru-RU", {weekday: "long", day: "numeric", month: "long"}) + " · " + updated()), headline(items));
    const pills = el("div", "hero-pills");
    const pill = (label, val, of, st) => { const p = el("div", "hero-pill" + (st && st !== "ok" ? " " + st : "")); p.append(el("div", "stat-label", label)); const b = el("div", "mono hp-v", String(val)); if (of != null) b.append(el("small", null, "/" + of)); p.append(b); return p; };
    pills.append(pill("проекты", ps.filter((p) => p.state === "ok").length, ps.length, ps.some((p) => p.state === "bad") ? "bad" : ps.some((p) => p.state === "warn") ? "warn" : "ok"));
    const up = servers.filter((s) => s.status === "up").length;
    pills.append(pill("серверы", up, servers.length, up < servers.length ? "bad" : "ok"));
    const exitsK = Object.values(details).map((d) => ((d && d.analytics && d.analytics.kpis) || []).find((k) => k.id === "rf_exits")).find(Boolean);
    if (exitsK) { const [a, b] = String(exitsK.value).split("/").map((x) => x.trim()); pills.append(pill("выходы VPN", a, b, exitsK.state)); }
    top.append(left, pills);
    v.append(top);

    v.append(attentionV2(items));
    const money = moneyCards();
    if (money.length) { const g = el("div", "grid2"); money.forEach((c) => g.append(c)); v.append(g); }
    const mid = el("div", "grid2");
    Object.values(details).forEach((d) => ((d && d.analytics && d.analytics.matrices) || []).forEach((mx) => mid.append(matrixCard(mx, (serversTableOf(d.analytics) || {}).rows))));
    mid.append(trafficCard());
    v.append(mid, projectList());
    const bottom = el("div", "grid2");
    bottom.append(rolesCard(), certCard(false));
    v.append(bottom);
  }

  /* ---------- карточка сервера ---------- */
  let drawerFor = null, drawerHasData = false;
  async function openDrawer(name) {
    drawerFor = name;
    let d = $("srvDrawer");
    if (!d) {
      d = el("aside", "drawer");
      d.id = "srvDrawer";
      d.setAttribute("role", "dialog");
      document.body.append(d);
      const shade = el("div", "drawer-shade"); shade.id = "srvShade";
      shade.addEventListener("click", closeDrawer);
      document.body.append(shade);
    }
    $("srvShade").classList.remove("hidden");
    d.classList.remove("hidden");
    d.setAttribute("aria-label", "Сервер " + name);
    const s = ((metrics && metrics.servers) || []).find((x) => x.name === name);
    /* по прямой ссылке карточка открывается раньше, чем пришли метрики — тогда paint() перерисует её ещё раз */
    drawerHasData = !!s;
    d.textContent = "";
    const head = el("div", "drawer-head"), hl = el("div");
    const grp = ((overview && overview.server_groups) || []).find((g) => (g.servers || []).includes(name));
    hl.append(el("div", "eyebrow", (grp ? grp.title : "Сервер") + (s && s.host ? " · " + s.host : "")), el("h2", "drawer-title", name));
    const meta = el("div", "drawer-meta");
    if (s) {
      meta.append(chip(s.status === "up" ? "ok" : "bad", s.status === "up" ? "работает" : "нет связи по SSH"));
      if (s.status === "up") meta.append(el("span", "mono muted", `аптайм ${nf(s.uptime_days, 1)} дн · пинг ${nf(s.ping_ms, 0)} мс`));
    }
    hl.append(meta);
    const close = el("button", "btn small", "Закрыть"); close.type = "button"; close.addEventListener("click", closeDrawer);
    head.append(hl, close);
    d.append(head);
    if (s && s.status !== "up") {
      const exits = liveExitsVia(name);
      d.append(el("div", "issue bad", exits.length
        ? `SSH не отвечает, но VPN-выходы через сервер живы: ${exits.map((e) => `${e.exit} с ${e.copy}${e.ping != null ? " · " + e.ping + " мс" : ""}`).join("; ")}.`
        : "SSH не отвечает: данных о нагрузке нет." + (s.error ? " Ошибка: " + s.error : "")));
    }
    if (s && s.status === "up") {
      const st = el("div", "stats");
      st.append(stat("CPU", Math.round(s.cpu_percent || 0) + " %", {state: (s.cpu_percent || 0) >= 80 ? "warn" : "ok"}),
        stat("RAM", s.ram_total_gb ? Math.round(100 * s.ram_used_gb / s.ram_total_gb) + " %" : "—"),
        stat("Диск", diskPct(s) + " %", {state: diskPct(s) >= 85 ? "warn" : "ok", note: "свободно " + nf(s.disk_free_gb, 1) + " ГБ"}),
        stat("Трафик за сутки", s.traffic_1d_gb != null ? (s.traffic_1d_gb >= 1000 ? nf(s.traffic_1d_gb / 1000, 2) + " ТБ" : Math.round(s.traffic_1d_gb) + " ГБ") : "—",
          {note: s.traffic_month_gb != null ? "с 1-го числа: " + gb(s.traffic_month_gb) : ""}));
      d.append(st);
    }
    const cpuBox = el("div", "pj-chart"), rxBox = el("div", "pj-chart");
    const sec = (title, box) => { const c = el("section", "drawer-sec"); const h = el("div", "card-head"); h.append(el("h3", null, title)); c.append(h, box); return c; };
    d.append(sec("CPU за сутки, %", cpuBox), sec("Входящий трафик за сутки, Мбит/с", rxBox));
    const acts = el("div", "drawer-acts");
    const dl = el("a", "btn", "Скачать журнал CSV"); dl.href = "/api/logs/" + encodeURIComponent(name);
    acts.append(dl);
    d.append(acts);
    close.focus();
    try {
      const r = await fetch("/api/history/" + encodeURIComponent(name) + "?hours=24", {cache: "no-store"});
      if (!r.ok) throw new Error("HTTP " + r.status);
      const h = await r.json();
      if (drawerFor !== name) return;
      drawChart(cpuBox, {title: "CPU", kind: "line", unit: "%", series: [{name: "CPU", points: h.series.cpu}]});
      drawChart(rxBox, {title: "RX", kind: "line", unit: "Мбит/с", series: [{name: "RX", points: h.series.rx}]});
    } catch (err) {
      cpuBox.append(el("p", "muted", "История недоступна: " + err.message));
    }
  }
  function closeDrawer() {
    drawerFor = null;
    const d = $("srvDrawer"); if (d) d.classList.add("hidden");
    const sh = $("srvShade"); if (sh) sh.classList.add("hidden");
    if (/^#servers\//.test(location.hash)) history.replaceState(null, "", "#servers");
  }

  /* ---------- поиск Ctrl+K ---------- */
  let palIdx = 0;
  function paletteItems(q) {
    q = q.trim().toLowerCase();
    const all = [];
    ((metrics && metrics.servers) || []).forEach((s) => {
      const exits = s.status !== "up" ? liveExitsVia(s.name) : [];
      all.push({group: "Серверы", title: s.name, sub: s.status === "up" ? `CPU ${Math.round(s.cpu_percent || 0)} % · диск ${diskPct(s)} %` : "SSH не отвечает" + (exits.length ? ", VPN-выход жив" : ""),
        st: s.status !== "up" ? "bad" : diskPct(s) >= 85 ? "warn" : "ok", href: "#servers/" + encodeURIComponent(s.name), hay: (s.name + " " + (s.host || "")).toLowerCase()});
    });
    ((overview && overview.projects) || []).forEach((p) => all.push({group: "Проекты", title: p.name, sub: p.stage || "", st: p.state, href: "#projects/" + p.id, hay: (p.name + " " + p.id + " " + (p.link || "")).toLowerCase()}));
    allCerts().forEach((c) => all.push({group: "Сертификаты", title: c.host, sub: c.error ? "ошибка проверки" : `истекает через ${c.days_left} дн`, st: certState(c), href: "#tls", hay: c.host.toLowerCase()}));
    [["Обзор", "#overview"], ["Все проекты", "#projects"], ["Таблица серверов", "#servers"], ["Сертификаты", "#tls"]].forEach(([t, h]) => all.push({group: "Разделы", title: t, sub: "", st: null, href: h, hay: t.toLowerCase()}));
    return (q ? all.filter((x) => x.hay.includes(q)) : all.filter((x) => x.group !== "Сертификаты")).slice(0, 12);
  }
  function renderPalette() {
    const list = $("palList"), q = $("palInput").value;
    const items = paletteItems(q);
    palIdx = Math.min(palIdx, Math.max(0, items.length - 1));
    list.textContent = "";
    let g = null;
    items.forEach((it, i) => {
      if (it.group !== g) { g = it.group; list.append(el("div", "pal-group", g)); }
      const a = el("a", "pal-item" + (i === palIdx ? " active" : "")); a.href = it.href;
      if (it.st) a.append(el("span", "sdot " + it.st));
      const t = el("span", "pal-title"); t.append(document.createTextNode(it.title)); if (it.sub) t.append(el("span", "pl", " · " + it.sub));
      a.append(t);
      a.addEventListener("click", closePalette);
      list.append(a);
    });
    if (!items.length) list.append(el("div", "pal-empty", "Ничего не найдено"));
  }
  function openPalette() {
    let p = $("palette");
    if (!p) {
      p = el("div", "palette hidden"); p.id = "palette";
      const box = el("div", "pal-box"); box.setAttribute("role", "dialog"); box.setAttribute("aria-label", "Поиск");
      const row = el("div", "pal-input");
      const inp = el("input"); inp.id = "palInput"; inp.setAttribute("placeholder", "Сервер, проект, домен…"); inp.setAttribute("aria-label", "Поиск"); inp.autocomplete = "off";
      row.append(inp, el("span", "kbd", "Esc"));
      const list = el("div", "pal-list"); list.id = "palList";
      box.append(row, list, el("div", "pal-foot", "↑↓ выбрать · Enter открыть · ищет по серверам, проектам и доменам"));
      p.append(box);
      p.addEventListener("click", (e) => { if (e.target === p) closePalette(); });
      inp.addEventListener("input", () => { palIdx = 0; renderPalette(); });
      inp.addEventListener("keydown", (e) => {
        const n = $("palList").querySelectorAll(".pal-item").length;
        if (e.key === "ArrowDown") { palIdx = Math.min(n - 1, palIdx + 1); renderPalette(); e.preventDefault(); }
        else if (e.key === "ArrowUp") { palIdx = Math.max(0, palIdx - 1); renderPalette(); e.preventDefault(); }
        else if (e.key === "Enter") { const a = $("palList").querySelectorAll(".pal-item")[palIdx]; if (a) { location.hash = a.getAttribute("href"); closePalette(); } e.preventDefault(); }
      });
      document.body.append(p);
    }
    p.classList.remove("hidden");
    $("palInput").value = ""; palIdx = 0; renderPalette();
    $("palInput").focus();
  }
  function closePalette() { const p = $("palette"); if (p) p.classList.add("hidden"); }
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target && e.target.tagName) || "");
    if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "л")) { e.preventDefault(); openPalette(); }
    else if (e.key === "/" && !typing) { e.preventDefault(); openPalette(); }
    else if (e.key === "Escape") { closePalette(); if (drawerFor) closeDrawer(); }
  });

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
    (an.matrices || []).forEach((mx) => blocks.push(matrixCard(mx, (serversTableOf(an) || {}).rows)));
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
      /* обзору нужны подробные документы проектов с доходом по месяцам (там же матрица связности) */
      const want = ((overview && overview.projects) || []).filter((p) => p.analytics && (p.analytics.kpis || []).some((k) => k.id === "revenue_month"));
      const got = await Promise.all(want.map((p) => fetch("/api/projects/" + p.id, {cache: "no-store"}).then((r) => r.ok ? r.json() : null).catch(() => null)));
      const next = {};
      want.forEach((p, i) => { if (got[i]) next[p.id] = got[i]; });
      details = next;
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
    const m = location.hash.match(/^#(overview|projects|servers|tls)(?:\/(.+))?$/);
    if (!m) return {view: "overview", id: null, server: null};
    const tail = m[2] ? decodeURIComponent(m[2]) : null;
    return {view: m[1], id: m[1] === "projects" && /^[a-z0-9_-]+$/.test(tail || "") ? tail : null, server: m[1] === "servers" ? tail : null};
  }
  function paint() {
    VIEWS.forEach((v) => $(v + "View").classList.toggle("hidden", v !== current.view));
    renderRail();
    if (current.view === "overview") renderOverview();
    else if (current.view === "projects") { if (current.id) renderProject(current.id); else renderProjects(); }
    else if (current.view === "servers") { renderServersSummary(); if (current.server && (drawerFor !== current.server || !drawerHasData)) openDrawer(current.server); }
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
  window.addEventListener("hashchange", () => {
    const was = current.view;
    route(!/^#servers\//.test(location.hash) || was !== "servers");
    if (!/^#servers\//.test(location.hash) && drawerFor) closeDrawer();
  });
  /* клик по имени сервера в таблице — карточка; двойной клик app.js оставляет для переименования */
  let clickT = null;
  $("rows").addEventListener("click", (e) => {
    const span = e.target.closest(".editable-name");
    if (!span) return;
    clearTimeout(clickT);
    clickT = setTimeout(() => { location.hash = "#servers/" + encodeURIComponent(span.dataset.server); }, 260);
  });
  $("rows").addEventListener("dblclick", () => clearTimeout(clickT));
  $("railSearch").addEventListener("click", openPalette);
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
