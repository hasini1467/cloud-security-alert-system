"use strict";
/* Cloud Security Alert System - dashboard
   Uses the existing backend API: GET /api/status, GET /api/history, POST /api/scan */

const REFRESH_MS = 3000;      // how often the page asks the backend for data
const SCAN_INTERVAL_S = 120;                    // must match your EventBridge rate
const STALE_AFTER_S = 300;
const LOG_PAGE = 10;
const HISTORY_LIMIT = 50;     // the backend returns at most 50 rows

const TRIGGERS = {
  AUTO_POLL: "Auto scan", AUTOMATIC_POLL: "Auto scan",
  MANUAL_SCAN: "Manual scan", MANUAL: "Manual scan",
  SYSTEM_INIT: "System start",
};

const $ = id => document.getElementById(id);
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const state = {
  tz: "local", sound: false, filter: "all", visible: LOG_PAGE,
  status: null, history: [], failed: false, scanning: false, prevRisk: null,
};

/* ---------- preferences ---------- */
function loadPrefs() {
  try {
    state.tz = localStorage.getItem("tz") === "utc" ? "utc" : "local";
    state.sound = localStorage.getItem("sound") === "1";
  } catch (e) { /* storage unavailable: use defaults */ }
}
function savePref(key, value) { try { localStorage.setItem(key, value); } catch (e) { /* ignore */ } }

/* ---------- time helpers ---------- */
const parseTs = s => new Date(String(s).replace(" UTC", "Z").replace(" ", "T"));
const tzOpt = () => (state.tz === "utc" ? "UTC" : undefined);
const fmtTime = d => d.toLocaleTimeString([], { hour12: false, timeZone: tzOpt() });
const fmtDateTime = d => d.toLocaleString([], { hour12: false, year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: tzOpt() });

function ago(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return sec + " s ago";
  const m = Math.floor(sec / 60);
  if (m < 60) return m + " min ago";
  return Math.floor(m / 60) + " h " + (m % 60) + " min ago";
}
function dur(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + " s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + " min " + (s % 60) + " s";
  return Math.floor(m / 60) + " h " + (m % 60) + " min";
}

/* ---------- data helpers ---------- */
const isRisk = s => s === "SECURITY_RISK";
const isManual = r => /MANUAL/.test(r.trigger_type || "");
const trigLabel = t => TRIGGERS[t] || String(t || "Unknown").replace(/_/g, " ").toLowerCase();
const realScans = () => state.history.filter(r => r.trigger_type !== "SYSTEM_INIT"); // newest first

/* Group consecutive scans with the same result into periods (newest first). */
function groupRuns(scans, now) {
  const runs = [];
  for (const s of scans) {
    const ts = parseTs(s.timestamp);
    const last = runs[runs.length - 1];
    if (last && last.status === s.status) {
      last.count++; last.start = ts;
      if (isManual(s)) last.manual++;
    } else {
      runs.push({ status: s.status, start: ts, count: 1, manual: isManual(s) ? 1 : 0, findings: s.findings || [] });
    }
  }
  runs.forEach((r, i) => {
    r.ongoing = i === 0;
    r.end = i === 0 ? now : runs[i - 1].start;       // the moment the next (newer) period began
    r.durationMs = r.end - r.start;
    r.truncated = i === runs.length - 1 && state.history.length >= HISTORY_LIMIT;
  });
  return runs;
}

/* ---------- rendering ---------- */
function setBodyState() {
  const s = state.status;
  document.body.classList.remove("state-idle", "state-ok", "state-risk");
  document.body.classList.add(!s ? "state-idle" : isRisk(s.status) ? "state-risk" : "state-ok");
  const colour = !s ? "%23566074" : isRisk(s.status) ? "%23ef4444" : "%2334d399";
  const fav = $("favicon");
  if (fav) fav.href = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='13' fill='" + colour + "'/%3E%3C/svg%3E";
  document.title = !s ? "Cloud Security Alert System"
    : isRisk(s.status) ? "\uD83D\uDD34 ALERT - Cloud Security" : "\uD83D\uDFE2 Secure - Cloud Security";
}

function renderLamp() {
  const s = state.status;
  if (!s) return;
  const risk = isRisk(s.status);
  $("status-text").textContent = risk ? "Security alert" : "Secure";
  const n = s.total_buckets;
  $("status-sub").textContent = risk
    ? s.public_buckets + " public bucket" + (s.public_buckets === 1 ? "" : "s") + " detected"
    : n + " bucket" + (n === 1 ? "" : "s") + " scanned, none public";
  $("m-buckets").textContent = String(n);
  $("m-mode").textContent = (s.mode || "LIVE_AWS").replace(/_/g, " ").toLowerCase();
}

function renderAlert(runs) {
  const s = state.status;
  const panel = $("alert-panel");
  if (!s || !isRisk(s.status)) { panel.hidden = true; return; }
  panel.hidden = false;
  const count = s.public_buckets;
  $("alert-title").textContent = count + " public bucket" + (count === 1 ? "" : "s") + " detected";
  const run = runs[0];
  $("alert-since").textContent = run && run.status === s.status
    ? "Since " + fmtTime(run.start) + " (" + (run.truncated ? "at least " : "") + dur(Date.now() - run.start) + ")"
    : "";
  $("alert-list").innerHTML = (s.findings || []).map(f =>
    "<li><b>" + esc(f.bucket) + "</b><div class=\"tags\">" +
    (f.reasons || []).map(r => "<span class=\"tag\">" + esc(r) + "</span>").join("") + "</div></li>").join("");
}

function renderStats(runs) {
  const scans = realScans();
  const total = scans.length;
  const secure = scans.filter(r => !isRisk(r.status)).length;
  const incidents = runs.filter(r => isRisk(r.status));
  $("s-scans").textContent = String(total);
  const rate = $("s-rate");
  rate.textContent = total ? Math.round((secure / total) * 100) + "%" : "–";
  rate.className = "stat-value" + (total ? (secure === total ? " ok" : "") : "");
  const inc = $("s-incidents");
  inc.textContent = String(incidents.length);
  inc.className = "stat-value" + (incidents.length ? " risk" : " ok");
  const last = $("s-last");
  if (!incidents.length) { last.textContent = "None"; last.className = "stat-value ok"; }
  else if (incidents[0].ongoing) { last.textContent = "Active now"; last.className = "stat-value risk"; }
  else { last.textContent = ago((Date.now() - incidents[0].end) / 1000); last.className = "stat-value"; }
}

function renderStrip() {
  const scans = realScans().slice().reverse(); // oldest -> newest
  $("strip").innerHTML = scans.map(r => {
    const label = fmtTime(parseTs(r.timestamp)) + " - " + (isRisk(r.status) ? "risk" : "secure") + " - " + trigLabel(r.trigger_type);
    return "<span class=\"blk" + (isRisk(r.status) ? " risk" : "") + (isManual(r) ? " man" : "") + "\" title=\"" + esc(label) + "\"></span>";
  }).join("");
  if (scans.length) {
    const spanMs = parseTs(scans[scans.length - 1].timestamp) - parseTs(scans[0].timestamp);
    $("strip-caption").textContent = "Last " + scans.length + " scans (about " + dur(spanMs) + "), oldest on the left. Hover a block for details.";
  } else {
    $("strip-caption").textContent = "No scans yet.";
  }
}

function renderTimeline(runs) {
  const el = $("timeline");
  if (!runs.length) { el.innerHTML = "<li class=\"empty\">No scans recorded yet.</li>"; return; }
  el.innerHTML = runs.slice(0, 6).map(r => {
    const risk = isRisk(r.status);
    const names = risk ? r.findings.map(f => esc(f.bucket)).join(", ") : "";
    const range = fmtTime(r.start) + " \u2192 " + (r.ongoing ? "now" : fmtTime(r.end));
    const meta = [range, (r.truncated ? "at least " : "") + dur(r.durationMs), r.count + " scan" + (r.count === 1 ? "" : "s")];
    if (r.manual) meta.push(r.manual + " manual");
    return "<li class=\"tl" + (risk ? " risk" : "") + "\"><span class=\"tl-dot\" aria-hidden=\"true\">" + (risk ? "!" : "\u2713") + "</span><div>" +
      "<div class=\"tl-title\">" + (risk ? "Risk detected" : "Secure") + (r.ongoing ? " <span class=\"badge\">ongoing</span>" : "") + "</div>" +
      "<div class=\"tl-sub\">" + meta.join(" \u00B7 ") + (names ? "<br>Bucket: <span class=\"mono\">" + names + "</span>" : "") + "</div></div></li>";
  }).join("");
}

function filteredLog() {
  const all = realScans();
  if (state.filter === "risk") return all.filter(r => isRisk(r.status));
  if (state.filter === "manual") return all.filter(isManual);
  return all;
}

function renderLog() {
  const rows = filteredLog();
  $("th-time").textContent = state.tz === "utc" ? "Time (UTC)" : "Time (local)";
  const shown = rows.slice(0, state.visible);
  $("log-body").innerHTML = shown.length ? shown.map(r => {
    const risk = isRisk(r.status);
    const names = (r.findings || []).map(f => esc(f.bucket)).join(", ");
    return "<tr class=\"" + (risk ? "row-risk" : "") + "\"><td class=\"mono\">" + esc(fmtDateTime(parseTs(r.timestamp))) + "</td>" +
      "<td><span class=\"pill " + (risk ? "risk\">\u26A0 Risk" : "ok\">\u2713 Secure") + "</span></td>" +
      "<td>" + r.public_buckets + " of " + r.total_buckets + "</td>" +
      "<td><span class=\"pill trig\">" + esc(trigLabel(r.trigger_type)) + "</span></td>" +
      "<td>" + (names ? "<span class=\"mono\">" + names + "</span>" : "<span class=\"muted\">-</span>") + "</td></tr>";
  }).join("") : "<tr><td colspan=\"5\" class=\"empty\">Nothing matches this filter.</td></tr>";
  $("log-count").textContent = rows.length ? "Showing " + shown.length + " of " + rows.length + " scans" : "";
  $("log-more").hidden = rows.length <= state.visible;
}

function renderAll() {
  const runs = groupRuns(realScans(), Date.now());
  setBodyState();
  renderLamp();
  renderAlert(runs);
  renderStats(runs);
  renderStrip();
  renderTimeline(runs);
  renderLog();
  tick();
}

/* ---------- once-a-second updates (no network) ---------- */
function tick() {
  const s = state.status;
  const live = $("live"), liveText = $("live-text"), notice = $("notice");
  let level = "good", text = "Live \u00B7 scans every " + SCAN_INTERVAL_S + " s", note = "", noteClass = "";

  if (s) {
    const last = parseTs(s.scanned_at);
    const sinceSec = (Date.now() - last) / 1000;
    $("m-last").textContent = ago(sinceSec) + " \u00B7 " + fmtTime(last);
    const remaining = Math.ceil(SCAN_INTERVAL_S - sinceSec);
    $("m-next").textContent = remaining > 0 ? "in " + remaining + " s" : "any moment";
    if (sinceSec > STALE_AFTER_S) {
      level = "warn"; text = "No recent scan";
      note = "No new scan for " + Math.round(sinceSec) + " s. The scanner may have stopped or AWS access is failing - check the backend logs (docker logs security-alert-backend).";
      noteClass = "warn";
    }
  }
  if (state.failed) {
    level = "bad"; text = "Backend offline";
    note = "Cannot reach the backend. Retrying every few seconds - the data below may be out of date.";
    noteClass = "bad";
  }
  live.className = "live " + level;
  liveText.textContent = text;
  notice.hidden = !note;
  notice.className = "notice" + (noteClass ? " " + noteClass : "");
  notice.textContent = note;
}

/* ---------- alert sound ---------- */
let audioCtx = null;
function beep() {
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    [0, 0.25, 0.5].forEach(t => {
      const o = audioCtx.createOscillator(), g = audioCtx.createGain();
      o.type = "square"; o.frequency.value = 880; g.gain.value = 0.04;
      o.connect(g); g.connect(audioCtx.destination);
      o.start(audioCtx.currentTime + t); o.stop(audioCtx.currentTime + t + 0.15);
    });
  } catch (e) { /* audio not available */ }
}

/* ---------- toast ---------- */
let toastTimer = null;
function toast(message, kind) {
  const t = $("toast");
  t.textContent = message;
  t.className = "toast" + (kind ? " " + kind : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 4500);
}

/* ---------- network ---------- */
async function getJson(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error("Server returned " + res.status);
  return res.json();
}

async function load() {
  try {
    const [status, history] = await Promise.all([getJson("/api/status"), getJson("/api/history")]);
    const nowRisk = isRisk(status.status);
    if (state.prevRisk === false && nowRisk && state.sound) beep();   // only on a change to risk
    state.prevRisk = nowRisk;
    state.status = status;
    state.history = Array.isArray(history) ? history : [];
    state.failed = false;
  } catch (e) {
    state.failed = true;
  }
  renderAll();
}

async function scanNow() {
  if (state.scanning) return;
  state.scanning = true;
  setScanButton();
  try {
    const d = await getJson("/api/scan", { method: "POST" });
    if (isRisk(d.status)) toast("Scan complete: " + d.public_buckets + " public bucket(s) found", "bad");
    else toast("Scan complete: all buckets secure", "good");
    await load();
  } catch (e) {
    toast("Scan failed: " + e.message, "bad");
  } finally {
    state.scanning = false;
    setScanButton();
  }
}
function setScanButton() {
  const btn = $("scan-btn");
  btn.disabled = state.scanning;
  btn.classList.toggle("busy", state.scanning);
  $("scan-label").textContent = state.scanning ? "Scanning\u2026" : "Scan now";
}

/* ---------- wiring ---------- */
function syncControls() {
  document.querySelectorAll("[data-tz]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.tz === state.tz)));
  document.querySelectorAll("[data-filter]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.filter === state.filter)));
  const s = $("sound");
  s.setAttribute("aria-pressed", String(state.sound));
  s.textContent = "Alert sound: " + (state.sound ? "on" : "off");
}

function init() {
  loadPrefs();
  syncControls();
  setScanButton();

  document.querySelectorAll("[data-tz]").forEach(b => b.addEventListener("click", () => {
    state.tz = b.dataset.tz; savePref("tz", state.tz); syncControls(); renderAll();
  }));
  document.querySelectorAll("[data-filter]").forEach(b => b.addEventListener("click", () => {
    state.filter = b.dataset.filter; state.visible = LOG_PAGE; syncControls(); renderLog();
  }));
  $("log-more").addEventListener("click", () => { state.visible += LOG_PAGE; renderLog(); });
  $("sound").addEventListener("click", () => {
    state.sound = !state.sound; savePref("sound", state.sound ? "1" : "0"); syncControls();
    if (state.sound) beep();   // also unlocks audio, which browsers only allow after a click
  });
  $("scan-btn").addEventListener("click", scanNow);

  load();
  setInterval(load, REFRESH_MS);
  setInterval(tick, 1000);
}

init();
