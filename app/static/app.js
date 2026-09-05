/* =========  i18n  ========= */
const I = {
  ru: {
    title: "Server Info Dashboard",
    loading: "Загрузка...",
    collecting: "Сбор метрик... Первый запуск может занять несколько секунд",
    collecting_long: "Сбор метрик занимает больше времени, чем обычно...",
    updated: "Обновлено",
    interval: "Интервал",
    add_server: "+ Добавить сервер",
    bot_btn: "Бот уведомлений",
    save_btn: "Сохранить",
    col_server: "Сервер",
    col_host: "Host",
    col_status: "Статус",
    col_ping: "Ping",
    col_cpu: "CPU %",
    col_ram: "RAM",
    col_disk: "Диск",
    col_30d: "30 дней",
    col_1d: "За день",
    col_uptime: "Uptime",
    col_iface: "Интерфейс",
    col_error: "Ошибка",
    col_actions: "Действия",
    delete_btn: "X",
    confirm_delete: "Удалить сервер",
    confirm_delete_body: "SSH-ключ также будет удалён.",
    confirm_hide_body: "Строка будет скрыта из таблицы.",
    info_btn: "Info",
    log_btn: "L",
    tip_log: "Скачать логи",
    tip_no_err: "Ошибок соединения нет",
    tip_iface: "Интерфейс",
    tip_delete: "Удаление сервера",
    confirm_yes: "Да, удалить",
    confirm_no: "Отмена",
    server_added: "Сервер добавлен",
    server_deleted: "удалён",
    saving: "Сохраняю...",
    setting_up: "Настройка сервера...",
    deleting: "Удаляю...",
    renamed: "Переименован",
    error_prefix: "Ошибка",
    error_update: "Ошибка обновления",
    bootstrap_label: "Авто-настройка через root",
    generate_key: "Сгенерировать SSH-ключ",
    ph_name: "имя сервера",
    ph_host: "host / IP",
    ph_user: "monitor user",
    ph_port: "port",
    ph_iface: "interface (опц.)",
    ph_client_key: "client_key path (опц.)",
    ph_root_user: "root user",
    ph_root_pass: "root password",
    ph_public_key: "public key / SHA256 (опц.)",
    ph_cpu_threshold: "CPU порог (%)",
    ph_ping_threshold: "Ping порог (мс)",
    ph_disk_threshold: "Диск порог (%)",
    ph_rx_threshold: "RX порог (Mbps)",
    ph_tx_threshold: "TX порог (Mbps)",
    ph_delay: "Задержка (циклов)",
    bot_token_set: "Токен задан (оставьте пустым чтобы сохранить)",
    bot_enable: "Включить бота",
    bot_notify_down: "Уведомлять при DOWN",
    bot_save: "Сохранить бота",
    bot_saved: "Бот сохранён",
    sec_btn: "Безопасность",
    ssh_normal: "SSH: обычный",
    ssh_persistent: "SSH: persistent",
    ssh_tip_normal: "Новое подключение каждый цикл (OK для больших интервалов)",
    ssh_tip_persistent: "Постоянное соединение (экономит ресурсы при частом опросе)",
    sec_save: "Сохранить",
    sec_saved: "Настройки сохранены",
    sec_pw_mismatch: "Пароли не совпадают",
    sec_pw_set: "Пароль задан",
    sec_pw_not_set: "Пароль не задан",
    sec_setup_hint: "Пароль не задан. Введите токен установки из журнала службы: journalctl -u servers-info-dash",
    sec_load_failed: "не удалось загрузить настройки безопасности",
    ph_sec_setup_token: "Токен установки из журнала службы",
    ph_sec_cur_pw: "Текущий пароль",
    ph_sec_pw: "Новый пароль (мин. 8 символов, пусто = не менять)",
    ph_sec_pw2: "Повторите пароль",
    ph_sec_nets: "192.168.1.0/24, 10.0.0.5 (через запятую)",
    sec_history_title: "Последние входы",
    sec_col_time: "Время",
    sec_col_ip: "IP",
    sec_col_country: "Страна",
    sec_col_ua: "Система",
    login_title: "Server Info Dashboard",
    login_btn: "Войти",
    login_blocked: "Заблокировано",
    login_wrong: "Неверный пароль",
    login_remaining: "Осталось попыток",
    logout_btn: "Выход",
    sec_reset_hint: "Сброс: удалить password_hash в config/auth.yaml",
    login_code_sent: "Код отправлен в Telegram",
    login_code_btn: "Подтвердить",
    login_code_wrong: "Неверный код",
    login_expired: "Время вышло, войдите заново",
    login_code_unsent: "Не удалось отправить код в Telegram",
    ph_login_code: "Код из Telegram",
    sec_2fa: "Двухфакторный вход: код в Telegram",
    sec_2fa_need_bot: "Сначала настройте Telegram-бота (токен и chat ID)",
    sec_2fa_reset_hint: "Отключить без доступа: two_factor: false в config/auth.yaml",
    sec_tokens_title: "API-токены (только чтение, без 2FA)",
    sec_tokens_none: "нет",
    sec_token_create: "Создать токен",
    sec_token_revoke: "Отозвать",
    sec_token_need_pw: "Введите текущий пароль в поле выше",
    sec_token_shown_once: "Токен показан один раз, сохраните его. Заголовок: Authorization: Bearer …",
    ph_sec_token_name: "Имя токена (например, neder32)",
  },
  en: {
    title: "Server Info Dashboard",
    loading: "Loading...",
    collecting: "Collecting metrics... First run may take a few seconds",
    collecting_long: "Collecting metrics is taking longer than usual...",
    updated: "Updated",
    interval: "Interval",
    add_server: "+ Add server",
    bot_btn: "Notification bot",
    save_btn: "Save",
    col_server: "Server",
    col_host: "Host",
    col_status: "Status",
    col_ping: "Ping",
    col_cpu: "CPU %",
    col_ram: "RAM",
    col_disk: "Disk",
    col_30d: "30 days",
    col_1d: "1 day",
    col_uptime: "Uptime",
    col_iface: "Interface",
    col_error: "Error",
    col_actions: "Actions",
    delete_btn: "X",
    confirm_delete: "Delete server",
    confirm_delete_body: "SSH key will also be removed.",
    confirm_hide_body: "Row will be hidden from table.",
    info_btn: "Info",
    log_btn: "L",
    tip_log: "Download logs",
    tip_no_err: "No connection errors",
    tip_iface: "Interface",
    tip_delete: "Delete server",
    confirm_yes: "Yes, delete",
    confirm_no: "Cancel",
    server_added: "Server added",
    server_deleted: "deleted",
    saving: "Saving...",
    setting_up: "Setting up server...",
    deleting: "Deleting...",
    renamed: "Renamed",
    error_prefix: "Error",
    error_update: "Update error",
    bootstrap_label: "Auto-setup via root",
    generate_key: "Generate SSH key",
    ph_name: "server name",
    ph_host: "host / IP",
    ph_user: "monitor user",
    ph_port: "port",
    ph_iface: "interface (opt.)",
    ph_client_key: "client_key path (opt.)",
    ph_root_user: "root user",
    ph_root_pass: "root password",
    ph_public_key: "public key / SHA256 (opt.)",
    ph_cpu_threshold: "CPU threshold (%)",
    ph_ping_threshold: "Ping threshold (ms)",
    ph_disk_threshold: "Disk threshold (%)",
    ph_rx_threshold: "RX threshold (Mbps)",
    ph_tx_threshold: "TX threshold (Mbps)",
    ph_delay: "Delay (cycles)",
    bot_token_set: "Token set (leave empty to keep)",
    bot_enable: "Enable bot",
    bot_notify_down: "Notify on DOWN",
    bot_save: "Save bot",
    bot_saved: "Bot saved",
    sec_btn: "Security",
    ssh_normal: "SSH: normal",
    ssh_persistent: "SSH: persistent",
    ssh_tip_normal: "New connection each cycle (OK for large intervals)",
    ssh_tip_persistent: "Keep-alive connection (saves resources on frequent polls)",
    sec_save: "Save",
    sec_saved: "Settings saved",
    sec_pw_mismatch: "Passwords don't match",
    sec_pw_set: "Password is set",
    sec_pw_not_set: "No password set",
    sec_setup_hint: "No password set. Enter the setup token from the service log: journalctl -u servers-info-dash",
    sec_load_failed: "could not load security settings",
    ph_sec_setup_token: "Setup token from the service log",
    ph_sec_cur_pw: "Current password",
    ph_sec_pw: "New password (min 8 chars, empty = keep)",
    ph_sec_pw2: "Confirm password",
    ph_sec_nets: "192.168.1.0/24, 10.0.0.5 (comma-separated)",
    sec_history_title: "Recent logins",
    sec_col_time: "Time",
    sec_col_ip: "IP",
    sec_col_country: "Country",
    sec_col_ua: "System",
    login_title: "Server Info Dashboard",
    login_btn: "Login",
    login_blocked: "Blocked",
    login_wrong: "Wrong password",
    login_remaining: "Attempts left",
    logout_btn: "Logout",
    sec_reset_hint: "Reset: delete password_hash in config/auth.yaml",
    login_code_sent: "Code sent to Telegram",
    login_code_btn: "Confirm",
    login_code_wrong: "Wrong code",
    login_expired: "Timed out, sign in again",
    login_code_unsent: "Could not send the code via Telegram",
    ph_login_code: "Code from Telegram",
    sec_2fa: "Two-factor login: code via Telegram",
    sec_2fa_need_bot: "Configure the Telegram bot first (token and chat ID)",
    sec_2fa_reset_hint: "Locked out? set two_factor: false in config/auth.yaml",
    sec_tokens_title: "API tokens (read-only, no 2FA)",
    sec_tokens_none: "none",
    sec_token_create: "Create token",
    sec_token_revoke: "Revoke",
    sec_token_need_pw: "Enter the current password above",
    sec_token_shown_once: "Shown once, store it now. Header: Authorization: Bearer …",
    ph_sec_token_name: "Token name (e.g. neder32)",
  },
};

let lang = localStorage.getItem("lang") || "ru";
/* login step flag; read by the i18n pass below, so it lives up here */
let awaitingCode = false;

function t(key) { return I[lang][key] || key; }

let _sshPersistent = false;
function _syncSshBtn(val) {
  _sshPersistent = !!val;
  const btn = document.getElementById("sshModeBtn");
  if (!btn) return;
  if (_sshPersistent) {
    btn.textContent = t("ssh_persistent");
    btn.title = t("ssh_tip_persistent");
  } else {
    btn.textContent = t("ssh_normal");
    btn.title = t("ssh_tip_normal");
  }
}

function applyLang() {
  document.querySelectorAll("[data-i]").forEach(el => {
    el.textContent = t(el.dataset.i);
  });
  document.getElementById("toggleAdd").textContent = t("add_server");
  document.getElementById("toggleBot").textContent = t("bot_btn");
  document.getElementById("toggleSec").textContent = t("sec_btn");
  document.getElementById("langToggle").textContent = lang === "ru" ? "EN" : "RU";
  /* placeholders */
  const ph = {
    srvName: "ph_name", host: "ph_host",
    user: "ph_user", port: "ph_port",
    iface: "ph_iface", clientKey: "ph_client_key",
    rootUser: "ph_root_user",
    rootPassword: "ph_root_pass",
    publicKey: "ph_public_key",
    botCpuThreshold: "ph_cpu_threshold",
    botPingThreshold: "ph_ping_threshold",
    botDiskThreshold: "ph_disk_threshold",
    botRxThreshold: "ph_rx_threshold",
    botTxThreshold: "ph_tx_threshold",
    botDelay: "ph_delay",
    secCurrentPassword: "ph_sec_cur_pw",
    secPassword: "ph_sec_pw",
    secPasswordConfirm: "ph_sec_pw2",
    secNetworks: "ph_sec_nets",
    secSetupToken: "ph_sec_setup_token",
    loginCode: "ph_login_code",
    secTokenName: "ph_sec_token_name",
  };
  $("loginBtn").textContent = t(awaitingCode ? "login_code_btn" : "login_btn");
  for (const [id, key] of Object.entries(ph)) {
    const el = document.getElementById(id);
    if (el) el.placeholder = t(key);
  }
  if (lastMeta) showMeta(lastMeta);
  renderTable();
  if (typeof _syncSshBtn === "function") _syncSshBtn(_sshPersistent);
}

/* =========  refs  ========= */
const $ = (id) => document.getElementById(id);
const rows      = $("rows");
const meta      = $("meta");
const addForm   = $("addForm");
const toggleAdd = $("toggleAdd");
const botForm   = $("botForm");
const toggleBot = $("toggleBot");
const formMsg   = $("formMsg");
const botMsg    = $("botMsg");
const bsToggle  = $("bootstrapWithRoot");
const bsFields  = document.querySelectorAll(".bootstrap-only");
const genToggle = $("generateKey");
const pkFields  = document.querySelectorAll(".pubkey-manual");
const themeBtn  = $("themeToggle");
const langBtn   = $("langToggle");
const colorPick = $("colorPicker");
const overlay   = $("confirmOverlay");
const confText  = $("confirmText");
const confYes   = $("confirmYes");
const confNo    = $("confirmNo");
const infoBtn   = $("infoBtn");
const logoutBtn = $("logoutBtn");
const secPanel  = $("secPanel");
const toggleSec = $("toggleSec");
const secMsg    = $("secMsg");
const loginOvl  = $("loginOverlay");

let intervalMs = 5000;
let serverData = [];
let sortKey = null;
let sortAsc = true;
let lastMeta = null;
let showLocal = localStorage.getItem("showLocal") !== "false";

/* =========  helpers  ========= */
const fmt = (v, d) =>
  v == null ? "\u2014" : Number(v).toFixed(d);

function traffic30dText(v) {
  if (v == null) return "\u2014";
  const gbValue = Number(v);
  if (gbValue > 1024) {
    const tb = (gbValue / 1024).toFixed(2);
    const unitTb = lang === "ru" ? " Тб" : " TB";
    return tb + unitTb;
  }
  if (gbValue < 1) {
    const mb = Math.round(gbValue * 1024);
    const unitMb = lang === "ru" ? " Мб" : " MB";
    return mb + unitMb;
  }
  const gb = gbValue.toFixed(2);
  const unitGb = lang === "ru" ? " Гб" : " GB";
  return gb + unitGb;
}

const esc = (v) => {
  if (v == null) return "";
  return String(v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
};


/* CPU colour: green(0%) → yellow(50%) → red(100%) */
function cpuColor(pct) {
  if (pct == null) return "var(--muted)";
  const p = Math.max(0, Math.min(100, pct));
  let r, g;
  if (p <= 50) {
    r = Math.round(255 * (p / 50));
    g = 200;
  } else {
    r = 255;
    g = Math.round(200 * (1 - (p - 50) / 50));
  }
  return "rgb(" + r + "," + g + ",60)";
}

/* =========  theme + colour  ========= */
const root = document.documentElement;

function applyTheme() {
  const dark = localStorage.getItem("theme") !== "light";
  root.classList.toggle("light", !dark);
  themeBtn.textContent = dark ? "\uD83C\uDF19" : "\u2600\uFE0F";
}

const colorTrigger = $("colorTrigger");
const colorDD = $("colorDropdown");

const colorGrads = {
  blue:"linear-gradient(135deg,#3b82f6,#1d4ed8)",
  purple:"linear-gradient(135deg,#8b5cf6,#6d28d9)",
  emerald:"linear-gradient(135deg,#10b981,#047857)",
  rose:"linear-gradient(135deg,#f43f5e,#be123c)",
  amber:"linear-gradient(135deg,#f59e0b,#b45309)",
  cyan:"linear-gradient(135deg,#06b6d4,#0e7490)",
};

function applyColor() {
  const c = localStorage.getItem("accentColor") || "blue";
  const keep = [];
  root.classList.forEach(cls => {
    if (!cls.startsWith("clr-")) keep.push(cls);
  });
  root.className = keep.join(" ");
  if (c !== "blue") root.classList.add("clr-" + c);
  colorPick.querySelectorAll(".cdot").forEach(d => {
    d.classList.toggle("active", d.dataset.c === c);
  });
  colorTrigger.style.background = "var(--muted)";
}

colorTrigger.addEventListener("click", (e) => {
  e.stopPropagation();
  colorDD.classList.toggle("open");
});

document.addEventListener("click", (e) => {
  if (!colorPick.contains(e.target)) colorDD.classList.remove("open");
});

themeBtn.addEventListener("click", () => {
  localStorage.setItem(
    "theme",
    root.classList.contains("light") ? "dark" : "light",
  );
  applyTheme();
});

colorPick.addEventListener("click", (e) => {
  const dot = e.target.closest(".cdot");
  if (!dot) return;
  localStorage.setItem("accentColor", dot.dataset.c);
  applyColor();
  colorDD.classList.remove("open");
});

langBtn.addEventListener("click", () => {
  lang = lang === "ru" ? "en" : "ru";
  localStorage.setItem("lang", lang);
  applyLang();
});

function updateInfoBtn() {
  infoBtn.classList.toggle("hidden", showLocal);
}

infoBtn.addEventListener("click", () => {
  showLocal = true;
  localStorage.setItem("showLocal", "true");
  updateInfoBtn();
  renderTable();
});

updateInfoBtn();

applyTheme();
applyColor();

/* =========  sorting  ========= */
function sorted(list) {
  if (!sortKey) return list;
  const arr = [...list];
  arr.sort((a, b) => {
    let va, vb;
    if (sortKey === "disk") {
      va = a.disk_total_gb ? 1 - a.disk_free_gb / a.disk_total_gb : -1;
      vb = b.disk_total_gb ? 1 - b.disk_free_gb / b.disk_total_gb : -1;
    } else if (sortKey === "ram") {
      va = a.ram_total_gb ? a.ram_used_gb / a.ram_total_gb : -1;
      vb = b.ram_total_gb ? b.ram_used_gb / b.ram_total_gb : -1;
    } else {
      va = a[sortKey]; vb = b[sortKey];
    }
    if (va == null) va = sortAsc ? Infinity : -Infinity;
    if (vb == null) vb = sortAsc ? Infinity : -Infinity;
    if (typeof va === "string") return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    return sortAsc ? va - vb : vb - va;
  });
  return arr;
}

$("headerRow").addEventListener("click", (e) => {
  const th = e.target.closest("th[data-key]");
  if (!th) return;
  const k = th.dataset.key;
  if (sortKey === k) sortAsc = !sortAsc;
  else { sortKey = k; sortAsc = true; }
  renderArrows();
  renderTable();
});

function renderArrows() {
  document.querySelectorAll("#headerRow th[data-key]").forEach(th => {
    const a = th.querySelector(".arrow");
    a.textContent = th.dataset.key === sortKey
      ? (sortAsc ? " \u25B2" : " \u25BC") : "";
  });
}

/* =========  disk bar  ========= */
function diskHtml(item) {
  /* zero total would make the percentage NaN and emit width:NaN% */
  if (!item.disk_total_gb) return "\u2014";
  const f = item.disk_free_gb, tot = item.disk_total_gb;
  const pct = Math.min(100, Math.max(0, ((tot - f) / tot) * 100));
  let c = "var(--ok)";
  if (pct > 95) c = "var(--bad)";
  else if (pct > 70) c = "#f59e0b";
  return '<div class="disk-bar">' +
    '<div class="disk-track"><div class="disk-fill" style="width:' +
    pct.toFixed(0) + '%;background:' + c + '"></div></div>' +
    '<span class="disk-text">' + f + '/' + tot + ' GB</span></div>';
}

/* =========  ram bar  ========= */
function ramHtml(item) {
  /* zero total would make the percentage NaN and emit width:NaN% */
  if (!item.ram_total_gb) return "\u2014";
  const u = item.ram_used_gb, tot = item.ram_total_gb;
  const pct = Math.min(100, Math.max(0, (u / tot) * 100));
  let c = "var(--ok)";
  if (pct > 90) c = "var(--bad)";
  else if (pct > 70) c = "#f59e0b";
  return '<div class="disk-bar">' +
    '<div class="disk-track"><div class="disk-fill" style="width:' +
    pct.toFixed(0) + '%;background:' + c + '"></div></div>' +
    '<span class="disk-text">' + u + '/' + tot + ' GB</span></div>';
}

/* =========  row  ========= */
function rowTemplate(item) {
  const cls = item.status === "up" ? "up" : "down";
  const sn = esc(item.name);
  const cpuVal = fmt(item.cpu_percent, 2);
  const cpuStyle = item.cpu_percent != null
    ? ' style="color:' + cpuColor(item.cpu_percent) + ';font-weight:600"' : '';
  const isLocal = item.is_local;
  const localAttr = isLocal ? ' data-local="1"' : '';
  const nameCell = '<td><span class="editable-name" data-server="' +
    sn + '"' + localAttr + '>' + sn + '</span></td>';
  const ifaceVal = esc(item.interface || '\u2014');
  const hasErr = item.error ? true : false;
  const errCls = hasErr ? ' err-active' : '';
  const errTitle = hasErr ? esc(item.error) : t('tip_no_err');
  const ifaceTitle = t('tip_iface') + ': ' + ifaceVal;
  const logName = esc(item._origName || item.name);
  const actionsCell = '<td>' +
    '<button class="btn small err-tip' + errCls + '" type="button" title="' + errTitle + '">E</button> ' +
    '<button class="btn small iface-tip" type="button" title="' + ifaceTitle + '">I</button> ' +
    '<button class="btn small log-btn act-tip" type="button" data-server-name="' +
    logName + '" title="' + t('tip_log') + '">L</button> ' +
    '<button class="btn small delete-btn act-tip" type="button" data-server-name="' +
    sn + '"' + localAttr + ' title="' + t('tip_delete') + '">X</button></td>';
  return '<tr>' +
    nameCell +
    '<td>' + esc(item.host) + '</td>' +
    '<td><span class="status ' + cls + '">' + item.status.toUpperCase() + '</span></td>' +
    '<td>' + (item.uptime_days != null ? item.uptime_days + 'd' : '\u2014') + '</td>' +
    '<td>' + fmt(item.ping_ms, 1) + '</td>' +
    '<td' + cpuStyle + '>' + cpuVal + '</td>' +
    '<td>' + ramHtml(item) + '</td>' +
    '<td>' + diskHtml(item) + '</td>' +
    '<td>' + fmt(item.rx_mbps, 2) + '</td>' +
    '<td>' + fmt(item.tx_mbps, 2) + '</td>' +
    '<td><span class="traffic-num">' + traffic30dText(item.traffic_1d_gb) + '</span></td>' +
    '<td><span class="traffic-num">' + traffic30dText(item.traffic_30d_gb) + '</span></td>' +
    actionsCell + '</tr>';
}

function renderTable() {
  let data = sorted(serverData);
  if (!showLocal) {
    data = data.filter(s => !s.is_local);
  }
  const cn = localStorage.getItem("localServerName");
  if (cn && showLocal) {
    data = data.map(s => s.is_local ? {...s, _origName: s.name, name: cn} : s);
  }
  rows.innerHTML = data.map(rowTemplate).join("");
}

function showMeta(data) {
  if (!data) return;
  const gen = new Date(data.generated_at).toLocaleString();
  meta.textContent = t("updated") + ": " + gen +
    " | " + t("interval") + ": " + data.refresh_interval_sec + "s";
}

/* =========  inline rename  ========= */
rows.addEventListener("dblclick", (e) => {
  const span = e.target.closest(".editable-name");
  if (!span) return;
  const oldN = span.dataset.server;
  const isLoc = span.dataset.local === "1";
  const inp = document.createElement("input");
  inp.className = "edit-input";
  inp.value = oldN;
  span.replaceWith(inp);
  inp.focus(); inp.select();
  let done = false;
  async function commit() {
    if (done) return; done = true;
    const nw = inp.value.trim();
    if (!nw || nw === oldN) { renderTable(); return; }
    if (isLoc) {
      localStorage.setItem("localServerName", nw);
      formMsg.textContent = t("renamed") + ": " + oldN + " \u2192 " + nw;
      formMsg.className = "msg ok";
      renderTable();
      return;
    }
    try {
      const r = await fetch("/api/servers/" + encodeURIComponent(oldN), {
        method: "PATCH",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({new_name: nw}),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || "HTTP " + r.status);
      formMsg.textContent = t("renamed") + ": " + oldN + " \u2192 " + nw;
      formMsg.className = "msg ok";
      const it = serverData.find(s => s.name === oldN);
      if (it) it.name = nw;
    } catch (err) {
      formMsg.textContent = t("error_prefix") + ": " + err.message;
      formMsg.className = "msg bad";
    }
    renderTable();
  }
  inp.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") commit();
    if (ev.key === "Escape") {
      /* renderTable removes the input, which fires blur -> commit;
         without this, cancelling renames the server anyway */
      done = true;
      renderTable();
    }
  });
  inp.addEventListener("blur", commit);
});

/* =========  toggle forms  ========= */
toggleAdd.addEventListener("click", () => {
  addForm.classList.toggle("hidden");
  botForm.classList.add("hidden");
  secPanel.classList.add("hidden");
  formMsg.textContent = ""; formMsg.className = "msg";
});
toggleBot.addEventListener("click", async () => {
  botForm.classList.toggle("hidden");
  addForm.classList.add("hidden");
  secPanel.classList.add("hidden");
  if (!botForm.classList.contains("hidden")) {
    try {
      const r = await fetch("/api/bot");
      const d = await r.json();
      $('botEnabled').checked = d.enabled;
      $('botToken').value = '';
      if (d.token_set) {
        $('botToken').placeholder = t('bot_token_set');
      } else {
        $('botToken').placeholder = 'Telegram bot token';
      }
      $('botChatId').value = d.chat_id || '';
      $('botNotifyDown').checked = d.notify_down;
      $('botCpuThreshold').value = d.notify_cpu_threshold ?? '';
      $('botPingThreshold').value = d.notify_ping_threshold ?? '';
      $('botDiskThreshold').value = d.notify_disk_threshold ?? '';
      $('botRxThreshold').value = d.notify_rx_threshold ?? '';
      $('botTxThreshold').value = d.notify_tx_threshold ?? '';
      $('botDelay').value = d.notify_delay ?? 1;
    } catch(_) {}
  }
});
bsToggle.addEventListener("change", () => {
  const on = bsToggle.checked;
  bsFields.forEach(f => f.classList.toggle("hidden", !on));
  if (on && genToggle.checked) pkFields.forEach(f => f.classList.add("hidden"));
});
genToggle.addEventListener("change", () => {
  pkFields.forEach(f => f.classList.toggle("hidden", genToggle.checked));
});

/* =========  add server  ========= */
addForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const payload = {
    name: $("srvName").value,
    host: $("host").value,
    user: $("user").value,
    port: Number($("port").value || 22),
    interface: $("iface").value || null,
    client_key: $("clientKey").value || null,
    bootstrap_with_root: bsToggle.checked,
    root_user: $("rootUser").value || null,
    root_password: $("rootPassword").value || null,
    public_key: $("publicKey").value || null,
    generate_key: bsToggle.checked && genToggle.checked,
  };
  formMsg.textContent = payload.bootstrap_with_root ? t("setting_up") : t("saving");
  formMsg.className = "msg";
  try {
    const r = await fetch("/api/servers", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.detail || "HTTP " + r.status);
    formMsg.textContent = t("server_added");
    formMsg.className = "msg ok";
    addForm.reset();
    bsFields.forEach(f => f.classList.add("hidden"));
    $("port").value = "22";
    $("user").value = "monitor";
    await refresh();
  } catch (err) {
    formMsg.textContent = t("error_prefix") + ": " + err.message;
    formMsg.className = "msg bad";
  }
});

/* =========  save bot  ========= */
botForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const nv = (id) => { const v = $(id).value; return v === '' ? null : Number(v); };
  const payload = {
    enabled: $("botEnabled").checked,
    token: $("botToken").value,
    chat_id: $("botChatId").value,
    notify_down: $("botNotifyDown").checked,
    notify_cpu_threshold: nv("botCpuThreshold"),
    notify_ping_threshold: nv("botPingThreshold"),
    notify_disk_threshold: nv("botDiskThreshold"),
    notify_rx_threshold: nv("botRxThreshold"),
    notify_tx_threshold: nv("botTxThreshold"),
    notify_delay: Math.max(1, Number($('botDelay').value) || 1),
  };
  botMsg.textContent = t("saving"); botMsg.className = "msg";
  try {
    const r = await fetch("/api/bot", {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.detail || "HTTP " + r.status);
    botMsg.textContent = t("bot_saved"); botMsg.className = "msg ok";
  } catch (err) {
    botMsg.textContent = t("error_prefix") + ": " + err.message;
    botMsg.className = "msg bad";
  }
});

/* =========  download log  ========= */
rows.addEventListener("click", (ev) => {
  const btn = ev.target.closest(".log-btn");
  if (!btn) return;
  const sn = btn.dataset.serverName;
  if (!sn) return;
  const a = document.createElement("a");
  a.href = "/api/logs/" + encodeURIComponent(sn);
  a.download = "";
  document.body.appendChild(a);
  a.click();
  a.remove();
});

/* =========  delete with confirm overlay  ========= */
let pendingDelete = null;
let pendingDeleteLocal = false;
rows.addEventListener("click", (ev) => {
  const btn = ev.target.closest(".delete-btn");
  if (!btn) return;
  const sn = btn.dataset.serverName;
  if (!sn) return;
  pendingDelete = sn;
  pendingDeleteLocal = btn.dataset.local === "1";
  const bodyKey = pendingDeleteLocal
    ? "confirm_hide_body" : "confirm_delete_body";
  confText.innerHTML = '<b>' + t("confirm_delete") + " '" +
    esc(sn) + "'?</b><br>" + t(bodyKey);
  confYes.textContent = t("confirm_yes");
  confNo.textContent = t("confirm_no");
  overlay.classList.remove("hidden");
});

confNo.addEventListener("click", () => {
  overlay.classList.add("hidden");
  pendingDelete = null;
  pendingDeleteLocal = false;
});

overlay.addEventListener("click", (e) => {
  if (e.target === overlay) {
    overlay.classList.add("hidden");
    pendingDelete = null;
    pendingDeleteLocal = false;
  }
});

confYes.addEventListener("click", async () => {
  overlay.classList.add("hidden");
  const sn = pendingDelete;
  const isLoc = pendingDeleteLocal;
  pendingDelete = null;
  pendingDeleteLocal = false;
  if (!sn) return;
  if (isLoc) {
    showLocal = false;
    localStorage.setItem("showLocal", "false");
    formMsg.textContent = "'" + sn + "' " + t("server_deleted");
    formMsg.className = "msg ok";
    updateInfoBtn();
    renderTable();
    return;
  }
  formMsg.textContent = t("deleting"); formMsg.className = "msg";
  try {
    const r = await fetch("/api/servers/" + encodeURIComponent(sn), {method: "DELETE"});
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.detail || "HTTP " + r.status);
    formMsg.textContent = "'" + sn + "' " + t("server_deleted");
    formMsg.className = "msg ok";
    await refresh();
  } catch (err) {
    formMsg.textContent = t("error_prefix") + ": " + err.message;
    formMsg.className = "msg bad";
  }
});

/* =========  refresh  ========= */
/* Applied even while the collector is not ready: otherwise a dead
   collector leaves the client polling at the 2s startup rate instead of
   the configured interval. */
function _syncInterval(data) {
  if (!data || !data.refresh_interval_sec) return;
  const selEl = $("intervalSelect");
  if (selEl && String(data.refresh_interval_sec) !== selEl.value) {
    selEl.value = String(data.refresh_interval_sec);
  }
  const next = data.refresh_interval_sec * 1000;
  if (next !== intervalMs) {
    intervalMs = next;
    clearInterval(window.__di);
    window.__di = setInterval(refresh, intervalMs);
  }
}

let _notReadyCount = 0;
let _refreshGen = 0;
async function refresh() {
  /* a slow cycle can still be in flight when the next tick fires; without
     a generation check a late reply overwrites a newer one and the
     figures visibly jump backwards */
  const gen = ++_refreshGen;
  try {
    const r = await fetch("/api/metrics", {cache: "no-store"});
    if (gen !== _refreshGen) return;
    if (!r.ok) {
      const err = new Error("HTTP " + r.status);
      err.status = r.status;
      throw err;
    }
    const data = await r.json();
    if (gen !== _refreshGen) return;
    _syncInterval(data);
    if (!data.ready) {
      _notReadyCount++;
      meta.textContent = _notReadyCount > 5 ? t("collecting_long") : t("collecting");
      if (data.servers && data.servers.length) {
        serverData = data.servers;
        renderTable();
      }
      return;
    }
    _notReadyCount = 0;
    serverData = data.servers;
    lastMeta = data;
    renderTable();
    showMeta(data);
    /* sync SSH mode button */
    _syncSshBtn(data.persistent_ssh);
    _markStale(false);
  } catch (err) {
    /* a monitoring dashboard showing yesterday's numbers as if they
       were live is worse than one that admits it lost the server */
    meta.textContent = t("error_update") + ": " + err.message;
    _markStale(true);
    if (err.status === 401) {
      checkAuth();
    }
  }
}

/* Dim the table while the figures on it are known to be out of date. */
function _markStale(stale) {
  const box = document.querySelector("table");
  if (box) box.classList.toggle("stale", stale);
}

/* =========  interval selector  ========= */
const intervalSel = $("intervalSelect");
intervalSel.addEventListener("change", async () => {
  const v = Number(intervalSel.value);
  try {
    const r = await fetch("/api/interval", {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({interval: v}),
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    intervalMs = v * 1000;
    clearInterval(window.__di);
    window.__di = setInterval(refresh, intervalMs);
  } catch (_) {}
});

/* =========  SSH mode toggle  ========= */
const sshBtn = $("sshModeBtn");

_syncSshBtn(false);

sshBtn.addEventListener("click", async () => {
  const next = !_sshPersistent;
  try {
    const r = await fetch("/api/ssh_mode", {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({persistent: next}),
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    _syncSshBtn(next);
  } catch (_) {}
});

applyLang();

/* =========  auth check  ========= */
let isAuthed = false;

async function checkAuth() {
  try {
    const r = await fetch("/api/auth/status");
    const d = await r.json();
    if (d.has_password && !d.logged_in) {
      loginOvl.classList.remove("hidden");
      isAuthed = false;
      logoutBtn.classList.add("hidden");
      return;
    }
    loginOvl.classList.add("hidden");
    isAuthed = true;
    logoutBtn.classList.toggle("hidden", !d.has_password);
  } catch(_) {
    /* the backend is unreachable, which says nothing about whether
       this browser is signed in — assuming it is shows a full UI whose
       every action then fails with 401 */
    meta.textContent = t("error_prefix") + ": " + t("sec_load_failed");
    _markStale(true);
  }
}

$("loginBtn").addEventListener("click", doLogin);
$("loginPassword").addEventListener("keydown", (e) => {
  if (e.key === "Enter") doLogin();
});
$("loginCode").addEventListener("keydown", (e) => {
  if (e.key === "Enter") doLogin();
});

/* second step of the login: the password was accepted and a one-time
   code went to Telegram; the same button now submits the code.
   Declared at the top: applyI18n() reads it before this point runs. */

function setLoginStep(code) {
  awaitingCode = code;
  $("loginPassword").classList.toggle("hidden", code);
  $("loginCode").classList.toggle("hidden", !code);
  $("loginHint").classList.toggle("hidden", !code);
  $("loginHint").textContent = code ? t("login_code_sent") : "";
  $("loginBtn").textContent = t(code ? "login_code_btn" : "login_btn");
  $("loginCode").value = "";
  if (code) $("loginCode").focus(); else $("loginPassword").focus();
}

async function doLogin() {
  const errEl = $("loginErr");
  errEl.textContent = "";
  let url, body;
  if (awaitingCode) {
    const code = $("loginCode").value.trim();
    if (!code) return;
    url = "/api/auth/verify"; body = {code};
  } else {
    const pw = $("loginPassword").value;
    if (!pw) return;
    url = "/api/auth/login"; body = {password: pw};
  }
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (r.ok && d.status === "2fa_required") {
      $("loginPassword").value = "";
      setLoginStep(true);
      return;
    }
    if (r.ok) {
      $("loginPassword").value = "";
      setLoginStep(false);
      loginOvl.classList.add("hidden");
      isAuthed = true;
      logoutBtn.classList.remove("hidden");
      refresh();
      return;
    }
    if (r.status === 429) {
      errEl.textContent = t("login_blocked") + ": " + d.detail;
      if (awaitingCode) setLoginStep(false);
    } else if (r.status === 403) {
      errEl.textContent = t(awaitingCode ? "login_code_wrong" : "login_wrong");
      if (d.remaining != null) {
        errEl.textContent += " (" + t("login_remaining") + ": " + d.remaining + ")";
      }
    } else if (r.status === 401 && awaitingCode) {
      setLoginStep(false);
      errEl.textContent = t("login_expired");
    } else if (r.status === 503 && !awaitingCode) {
      errEl.textContent = t("login_code_unsent");
    } else {
      errEl.textContent = d.detail || "Error";
    }
  } catch(e) {
    errEl.textContent = e.message;
  }
}

logoutBtn.addEventListener("click", async () => {
  try {
    await fetch("/api/auth/logout", {method: "POST"});
  } catch(_) {}
  isAuthed = false;
  logoutBtn.classList.add("hidden");
  loginOvl.classList.remove("hidden");
  $("loginPassword").value = "";
  setLoginStep(false);
  $("loginErr").textContent = "";
});

/* =========  security panel  ========= */
toggleSec.addEventListener("click", async () => {
  secPanel.classList.toggle("hidden");
  addForm.classList.add("hidden");
  botForm.classList.add("hidden");
  if (!secPanel.classList.contains("hidden")) {
    try {
      const r = await fetch("/api/auth/settings");
      const d = await r.json();
      $("secCurrentPassword").value = "";
      $("secPassword").value = "";
      $("secPasswordConfirm").value = "";
      $("secSetupToken").value = "";
      $("secNetworks").value = (d.allowed_networks || []).join(", ");
      /* first run: the setup token from the service log stands in for
         the current password, which does not exist yet */
      $("secSetupToken").classList.toggle("hidden", !!d.has_password);
      $("secCurrentPassword").classList.toggle("hidden", !d.has_password);
      const tf = $("secTwoFactor");
      tf.checked = !!d.two_factor;
      /* enabling needs a working bot; disabling must stay possible
         even if the bot was removed afterwards */
      tf.disabled = !d.has_password || (!d.bot_ready && !d.two_factor);
      tf.parentElement.title = tf.disabled && d.has_password ? t("sec_2fa_need_bot") : "";
      secMsg.textContent = d.has_password ? t("sec_pw_set") : t("sec_setup_hint");
      secMsg.className = d.has_password ? "msg ok" : "msg";
      renderTokens(d.api_tokens || []);
      $("secTokenOut").classList.add("hidden");
      // render history
      const hist = d.history || [];
      let h = '<table><thead><tr>' +
        '<th>' + t("sec_col_time") + '</th>' +
        '<th>' + t("sec_col_ip") + '</th>' +
        '<th>' + t("sec_col_country") + '</th>' +
        '<th>' + t("sec_col_ua") + '</th></tr></thead><tbody>';
      for (const e of hist.slice().reverse()) {
        h += '<tr><td>' + esc(e.time) + '</td>' +
          '<td>' + esc(e.ip) + '</td>' +
          '<td>' + esc(e.country) + '</td>' +
          '<td>' + esc(e.ua) + '</td></tr>';
      }
      h += '</tbody></table>';
      $("secHistory").innerHTML = '<div style="padding:6px 8px;font-weight:600;font-size:13px">' +
        t("sec_history_title") + '</div>' + h +
        '<div style="padding:4px 8px;font-size:11px;color:var(--muted)">' +
        t("sec_reset_hint") + ' · ' + t("sec_2fa_reset_hint") + '</div>';
    } catch(_) {
      /* leaving the fields in whatever state the markup defaults to
         would show a current-password box that cannot work on first
         run, with no explanation */
      secMsg.textContent = t("error_prefix") + ": " + t("sec_load_failed");
      secMsg.className = "msg bad";
    }
  }
});

/* API tokens: scripts poll /api/metrics with a bearer token instead of a
   password, so turning 2FA on does not break them */
function renderTokens(list) {
  const box = $("secTokens");
  let h = '<div style="font-weight:600;color:var(--text)">' + t("sec_tokens_title") + '</div>';
  if (!list.length) h += '<div>' + t("sec_tokens_none") + '</div>';
  for (const tk of list) {
    h += '<div class="tok"><b>' + esc(tk.name) + '</b><span>' + esc(tk.created) + '</span>' +
      '<button class="btn small" type="button" data-revoke="' + esc(tk.name) + '">' +
      t("sec_token_revoke") + '</button></div>';
  }
  box.innerHTML = h;
  box.querySelectorAll("button[data-revoke]").forEach(btn => {
    btn.addEventListener("click", async () => {
      try {
        const r = await fetch("/api/auth/tokens/" + encodeURIComponent(btn.dataset.revoke),
          {method: "DELETE"});
        const d = await r.json();
        if (!r.ok) throw new Error(d.detail || "Error");
        const s = await (await fetch("/api/auth/settings")).json();
        renderTokens(s.api_tokens || []);
      } catch(e) {
        secMsg.textContent = t("error_prefix") + ": " + e.message;
        secMsg.className = "msg bad";
      }
    });
  });
}

$("secTokenCreate").addEventListener("click", async () => {
  const name = $("secTokenName").value.trim();
  const curPw = $("secCurrentPassword").value;
  if (!name) return;
  if (!curPw) {
    secMsg.textContent = t("sec_token_need_pw");
    secMsg.className = "msg bad";
    return;
  }
  try {
    const r = await fetch("/api/auth/tokens", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({name, current_password: curPw}),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Error");
    const out = $("secTokenOut");
    out.innerHTML = '<div>' + t("sec_token_shown_once") + '</div><code>' + esc(d.token) + '</code>';
    out.classList.remove("hidden");
    $("secTokenName").value = "";
    secMsg.textContent = "";
    const s = await (await fetch("/api/auth/settings")).json();
    renderTokens(s.api_tokens || []);
  } catch(e) {
    secMsg.textContent = t("error_prefix") + ": " + e.message;
    secMsg.className = "msg bad";
  }
});

$("secSave").addEventListener("click", async () => {
  const curPw = $("secCurrentPassword").value;
  const pw = $("secPassword").value;
  const pw2 = $("secPasswordConfirm").value;
  if (pw && pw !== pw2) {
    secMsg.textContent = t("sec_pw_mismatch");
    secMsg.className = "msg bad";
    return;
  }
  const nets = $("secNetworks").value
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);
  const payload = {
    current_password: curPw || null,
    password: pw || null,
    allowed_networks: nets,
    setup_token: $("secSetupToken").value.trim() || null,
    two_factor: $("secTwoFactor").disabled ? null : $("secTwoFactor").checked,
  };
  secMsg.textContent = t("saving"); secMsg.className = "msg";
  try {
    const r = await fetch("/api/auth/settings", {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || "Error");
    secMsg.textContent = t("sec_saved");
    secMsg.className = "msg ok";
    $("secCurrentPassword").value = "";
    $("secPassword").value = "";
    $("secPasswordConfirm").value = "";
    $("secSetupToken").value = "";
    checkAuth();
  } catch(e) {
    secMsg.textContent = t("error_prefix") + ": " + e.message;
    secMsg.className = "msg bad";
  }
});

meta.textContent = t("loading");
checkAuth();
refresh();
window.__di = setInterval(refresh, 2000);
