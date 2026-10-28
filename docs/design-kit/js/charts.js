/* Автономный модуль графиков и плиток из views.js (копия без привязки к API панели).
   Подключение: <script src="js/charts.js"></script> → window.InfoUI = {el, svg, nf, fmtValue, kpiStat, stat, chip, drawChart, isLong}.
   drawChart(box, chart, {spark}) рисует SVG в элементе box; формат chart — analytics-schema.md (kind: line|bar, series[].points [[x, y]]). */
(function () {
  "use strict";
  const SVG = "http://www.w3.org/2000/svg";
  const STATE = {ok: "норма", warn: "замечания", bad: "проблема"};
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
  const ago = (min) => {
    if (min == null) return "";
    if (min < 1) return "только что";
    const d = Math.floor(min / 1440), h = Math.floor(min % 1440 / 60), m = Math.round(min % 60);
    if (d) return d + " дн" + (h ? " " + h + " ч" : "") + " назад";
    if (h) return h + " ч" + (m ? " " + m + " мин" : "") + " назад";
    return m + " мин назад";
  };
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

  window.InfoUI = {el, svg, nf, fmtValue, kpiStat, stat, chip, drawChart, isLong};
})();
