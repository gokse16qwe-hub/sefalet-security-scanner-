/* Sefalet Console: panel arayüzü.
 *
 * Basit bir "tek sayfa uygulaması": Adres çubuğundaki #/... kısmına göre
 * (ör. #/raporlar) ilgili sayfa çizilir. Kütüphane kullanılmadı; her şey
 * düz JavaScript.
 *
 * GÜVENLİK: Sunucudan gelen her metin ekrana basılmadan önce esc() ile
 * kaçışlanır. Taranan sitelerden gelen veriler (başlıklar, kanıtlar) zararlı
 * HTML/JS içerebilir; esc() olmadan panelde XSS açığı oluşurdu.
 */
"use strict";

const TOKEN = document.querySelector('meta[name="sefalet-token"]').content;
const view = document.getElementById("view");
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Kritik", high: "Yüksek", medium: "Orta", low: "Düşük", info: "Bilgi" };
const CHECKS = ["tls", "headers", "dns", "ports"];
const CHECK_LABEL = { tls: "SSL/TLS", headers: "HTTP Başlıkları", dns: "DNS & E-posta", ports: "TCP Port" };
const CHECK_SUB = { tls: "Sertifika ve protokol", headers: "Güvenlik başlıkları, çerezler", dns: "SPF, DMARC, CAA, DNSSEC", ports: "Sınırlı servis kontrolü" };
const STATUS_DOT = { completed: "dot-ok", error: "dot-error", skipped: "dot-skip" };
const AUTH_SHORT = { dns_txt: "DNS TXT", http_file: "HTTP dosyası", declaration: "Beyan", lab: "Lab" };

let pollTimer = null;
let metaCache = null;  // /api/meta bir kez alınır; form yeniden çizilirken beklenmez

async function getMeta() {
  if (!metaCache) metaCache = await api("/api/meta");
  return metaCache;
}

// --- Yardımcılar ---------------------------------------------------------

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function fmtDate(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("tr-TR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

async function api(path, options = {}) {
  const headers = { "X-Sefalet-Token": TOKEN, ...(options.body ? { "Content-Type": "application/json" } : {}) };
  const response = await fetch(path, { ...options, headers });
  let data = null;
  try { data = await response.json(); } catch { /* gövde JSON değil */ }
  if (!response.ok) {
    const detail = data && data.detail;
    const error = new Error((detail && detail.message) || (typeof detail === "string" ? detail : `Hata (${response.status})`));
    error.status = response.status;
    error.detail = detail && typeof detail === "object" ? detail : {};
    throw error;
  }
  return data;
}

function toast(message, isError = false) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = `toast show${isError ? " error" : ""}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = "toast"; }, 3800);
}

function icon(name) {
  const paths = {
    radar: "M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8zm0-14a6 6 0 1 0 6 6 6 6 0 0 0-6-6zm0 10a4 4 0 1 1 4-4 4 4 0 0 1-4 4z",
    shield: "M12 1 3 5v6c0 5.6 3.8 10.7 9 12 5.2-1.3 9-6.4 9-12V5z",
    doc: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zm4 18H6V4h7v5h5z",
    pen: "M3 17.3V21h3.7l11-11-3.7-3.7zM20.7 7a1 1 0 0 0 0-1.4l-2.3-2.3a1 1 0 0 0-1.4 0l-1.8 1.8 3.7 3.7z",
    lab: "M7 2v2h1v6.4L3.3 18.8A2 2 0 0 0 5 22h14a2 2 0 0 0 1.7-3.2L16 10.4V4h1V2zm3 2h4v7l2.5 4.5h-9L10 11z",
    down: "M5 20h14v-2H5zM19 9h-4V3H9v6H5l7 7z",
    trash: "M6 19a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V7H6zM19 4h-3.5l-1-1h-5l-1 1H5v2h14z",
  };
  return `<svg viewBox="0 0 24 24"><path d="${paths[name]}"/></svg>`;
}

function gradeBox(grade, small = false) {
  const g = grade || "none";
  return `<span class="grade ${small ? "grade-sm" : ""} grade-${esc(g)}">${esc(grade || "–")}</span>`;
}

function sevBadge(sev, text) {
  return `<span class="badge sev-${esc(sev)}">${esc(text ?? SEV_LABEL[sev])}</span>`;
}

function sevBar(counts) {
  const total = SEVERITIES.reduce((a, s) => a + (counts[s] || 0), 0);
  const parts = SEVERITIES.filter((s) => counts[s]).map((s) =>
    `<span class="s-${s}" data-w="${(100 * counts[s]) / total}"></span>`).join("");
  return `<div class="sevbar">${parts}</div>`;
}

function miniCounts(counts) {
  const items = SEVERITIES.filter((s) => s !== "info" && counts[s]).map((s) => sevBadge(s, `${counts[s]} ${SEV_LABEL[s]}`));
  return items.length ? items.join("") : `<span class="tag">Ciddi bulgu yok</span>`;
}

// CSP satır içi stile izin vermediği için genişlikleri JS ile veriyoruz
function applyWidths(root = view) {
  root.querySelectorAll("[data-w]").forEach((el) => { el.style.width = `${el.dataset.w}%`; });
}

function gauge(score, grade) {
  const r = 46, c = 2 * Math.PI * r;
  const value = typeof score === "number" ? score : 0;
  const color = { A: "#2df59a", B: "#9cf54a", C: "#ffb020", D: "#ff7a2e", F: "#ff2e63" }[grade] || "#56627f";
  return `<div class="gauge"><svg viewBox="0 0 112 112">
      <circle class="gauge-track" cx="56" cy="56" r="${r}"/>
      <circle class="gauge-bar" cx="56" cy="56" r="${r}" stroke="${color}" stroke-dasharray="${c}"
        stroke-dashoffset="${c * (1 - value / 100)}" filter="drop-shadow(0 0 6px ${color})"/>
      <text class="gauge-text" x="56" y="60" text-anchor="middle">${typeof score === "number" ? score : "–"}</text>
      <text class="gauge-sub" x="56" y="77" text-anchor="middle">/ 100</text>
    </svg></div>`;
}

function setHeader(title, crumb) {
  document.getElementById("page-title").textContent = title;
  document.getElementById("crumb").textContent = `Sefalet / ${crumb || title}`;
  document.title = `${title} · Sefalet Console`;
}

function emptyState(title, text, action) {
  return `<div class="empty">${icon("radar")}<h3>${esc(title)}</h3><p>${esc(text)}</p>${action || ""}</div>`;
}

// --- Panel ---------------------------------------------------------------

async function renderPanel() {
  setHeader("Panel", "Genel Bakış");
  const s = await api("/api/summary");
  const latest = s.latest;
  const total = SEVERITIES.reduce((a, k) => a + s.totals[k], 0);
  const days = s.ssl_days_left;
  const sslClass = days == null ? "faint" : days < 0 ? "neon-bad" : days < 14 ? "neon-warn" : "neon-ok";

  const modules = CHECKS.map((name) => {
    const m = s.modules.find((x) => x.name === name);
    if (!m) {
      return `<div class="module"><span class="dot"></span><div class="label">${esc(CHECK_SUB[name])}</div>
        <div class="module-name">${esc(CHECK_LABEL[name])}</div><div class="module-num faint">–</div>
        <div class="module-msg">Henüz çalıştırılmadı</div></div>`;
    }
    const worst = m.worst ? sevBadge(m.worst) : "";
    return `<div class="module"><span class="dot ${STATUS_DOT[m.status]}"></span>
      <div class="label">${esc(CHECK_SUB[name])}</div>
      <div class="module-name">${esc(CHECK_LABEL[name])}</div>
      <div class="row"><div class="module-num">${m.status === "skipped" ? "–" : m.findings}<small>${m.status === "skipped" ? "" : "bulgu"}</small></div><span class="spacer"></span>${worst}</div>
      <div class="module-msg">${esc(m.status_label)}${m.status !== "completed" && m.message ? " · " + esc(m.message.slice(0, 70)) : ""}</div></div>`;
  }).join("");

  const recent = s.recent.length
    ? s.recent.map((r) => `
      <a class="scan-item" href="#/rapor/${esc(r.scan_id)}">
        ${gradeBox(r.grade, true)}
        <div><div class="title">${esc(r.target)}</div>
          <div class="meta">${esc(fmtDate(r.started_at))} · <span class="tag">${esc(AUTH_SHORT[r.auth_method] || r.auth_method)}</span></div></div>
        <div class="mini-counts">${miniCounts(r.counts)}</div>
      </a>`).join("")
    : emptyState("Henüz tarama yok", "İlk taramanızı başlatarak güvenlik durumunu görün.",
      `<a class="btn btn-primary" href="#/tarama">Tarama başlat</a>`);

  view.innerHTML = `
    <div class="grid grid-4">
      <div class="card stat card-glow">
        <div class="label">Güvenlik puanı</div>
        <div class="gauge-wrap">${gauge(latest?.score, latest?.grade)}
          <div><div class="muted">Genel not</div>${gradeBox(latest?.grade)}</div></div>
      </div>
      <div class="card stat">
        <div class="label">Toplam bulgu</div>
        <div class="stat-value neon-cyan">${total}</div>
        ${sevBar(s.totals)}
        <div class="sevlegend">${SEVERITIES.filter((k) => s.totals[k]).map((k) => `<span class="sev-${k}">${s.totals[k]} ${SEV_LABEL[k]}</span>`).join("") || '<span class="faint">Bulgu yok</span>'}</div>
      </div>
      <div class="card stat">
        <div class="label">SSL sertifikası</div>
        <div class="stat-value ${sslClass}">${days == null ? "–" : days}</div>
        <div class="stat-foot">${days == null ? "Son taramada TLS verisi yok" : days < 0 ? "gün önce süresi doldu" : "gün kaldı"}</div>
      </div>
      <div class="card stat">
        <div class="label">İzlenen hedef</div>
        <div class="stat-value">${s.targets}<small> hedef</small></div>
        <div class="stat-foot">${s.total_scans} tarama · ${s.active_jobs} aktif</div>
      </div>
    </div>

    <div class="grid grid-main mt">
      <div class="card">
        <div class="card-title"><div><h2>Modül durumu</h2><div class="sub">${latest ? `Son tarama: ${esc(latest.target)} · ${esc(fmtDate(latest.started_at))}` : "Henüz tarama yapılmadı"}</div></div>
          ${latest ? `<a class="btn btn-sm" href="#/rapor/${esc(latest.scan_id)}">Raporu aç →</a>` : ""}</div>
        <div class="grid modules">${modules}</div>
      </div>
      <div class="card">
        <div class="card-title"><div><h2>Tarama geçmişi</h2><div class="sub">Son taramalar</div></div>
          <a class="btn btn-sm" href="#/raporlar">Tümü</a></div>
        ${recent}
      </div>
    </div>`;
  applyWidths();
}

// --- Yeni tarama ---------------------------------------------------------

const scanForm = { target: "", mode: "verify", verify_method: "auto", declarant: "", accept: false, ports: false };

async function renderScan() {
  setHeader("Yeni Tarama", "Tarama Başlat");
  const meta = await getMeta();
  const mode = scanForm.mode;
  view.innerHTML = `
    <div class="grid grid-main">
      <form class="card card-glow" id="scan-form" autocomplete="off">
        <div class="card-title"><div><h2>Hedef</h2><div class="sub">Alan adı, URL veya IP adresi</div></div></div>
        <div class="field">
          <label for="target">Hedef adres</label>
          <input class="input" id="target" name="target" required placeholder="ör. ornek.com veya https://localhost:8443" value="${esc(scanForm.target)}">
        </div>

        <div class="field">
          <span class="label">Tarama izni</span>
          <div class="segmented" role="radiogroup">
            <button type="button" class="seg ${mode === "verify" ? "active" : ""}" data-mode="verify">${icon("shield")}Teknik doğrulama<small>DNS TXT / HTTP dosyası</small></button>
            <button type="button" class="seg ${mode === "declaration" ? "active" : ""}" data-mode="declaration">${icon("pen")}İzin beyanı<small>Yalnızca pasif kontroller</small></button>
            <button type="button" class="seg ${mode === "lab" ? "active" : ""}" data-mode="lab">${icon("lab")}Lab modu<small>Yerel / özel ağ</small></button>
          </div>
        </div>

        <div id="mode-extra"></div>

        <div class="field">
          <label class="switch">
            <input type="checkbox" id="ports" ${scanForm.ports ? "checked" : ""} ${mode === "declaration" ? "disabled" : ""}>
            <span class="track"></span>
            <span><b>Sınırlı TCP port kontrolü</b><small>21 sabit port, yalnızca bağlantı denemesi. Teknik doğrulama gerektirir. Varsayılan kapalı.</small></span>
          </label>
        </div>

        <div id="form-error"></div>
        <button class="btn btn-primary btn-wide" type="submit" id="start">${icon("radar")} Taramayı başlat</button>
      </form>

      <div class="stack">
        <div class="card">
          <div class="card-title"><h2>Neler kontrol edilir?</h2></div>
          <div class="steps">${CHECKS.map((c) => `<div class="step"><span class="dot dot-ok"></span><div><b>${esc(CHECK_LABEL[c])}</b><div class="faint">${esc(CHECK_SUB[c])}</div></div></div>`).join("")}</div>
        </div>
        <div class="notice">Bu araç saldırı, exploit veya parola denemesi <b>yapmaz</b>. Yalnızca sahibi olduğunuz
          veya açık izin aldığınız hedefleri tarayın.</div>
      </div>
    </div>`;

  const extra = view.querySelector("#mode-extra");
  if (mode === "verify") {
    extra.innerHTML = `<div class="field"><label for="vm">Doğrulama yöntemi</label>
      <select class="input" id="vm">
        <option value="auto" ${scanForm.verify_method === "auto" ? "selected" : ""}>Otomatik (önce DNS, sonra HTTP)</option>
        <option value="dns" ${scanForm.verify_method === "dns" ? "selected" : ""}>Yalnızca DNS TXT kaydı</option>
        <option value="http" ${scanForm.verify_method === "http" ? "selected" : ""}>Yalnızca HTTP dosyası</option>
      </select>
      <span class="hint">Doğrulama kaydını henüz eklemediyseniz <a href="#/dogrulama">Doğrulama</a> sayfasından talimat alın.</span></div>`;
  } else if (mode === "declaration") {
    extra.innerHTML = `<div class="field"><label for="declarant">Beyan eden (ad soyad)</label>
        <input class="input" id="declarant" placeholder="Ad Soyad" value="${esc(scanForm.declarant)}"></div>
      <div class="field"><div class="notice notice-warn">${esc(meta.declaration_text)}</div>
        <label class="checkbox"><input type="checkbox" id="accept" ${scanForm.accept ? "checked" : ""}> Yukarıdaki beyanı okudum ve kabul ediyorum.</label></div>`;
  } else {
    extra.innerHTML = `<div class="field"><div class="notice">Lab modu yalnızca <b>yerel/özel ağ</b> adreslerine
      (127.0.0.1, 10.x, 192.168.x…) izin verir. İnternetteki bir site bu modla taranamaz.</div></div>`;
  }

  const form = view.querySelector("#scan-form");
  const remember = () => {
    scanForm.target = form.querySelector("#target").value;
    scanForm.ports = form.querySelector("#ports").checked;
    const vm = form.querySelector("#vm"); if (vm) scanForm.verify_method = vm.value;
    const d = form.querySelector("#declarant"); if (d) scanForm.declarant = d.value;
    const a = form.querySelector("#accept"); if (a) scanForm.accept = a.checked;
  };
  form.querySelectorAll(".seg").forEach((b) => b.addEventListener("click", () => {
    remember(); scanForm.mode = b.dataset.mode;
    if (scanForm.mode === "declaration") scanForm.ports = false;
    renderScan();
  }));
  form.addEventListener("submit", async (e) => {
    e.preventDefault(); remember();
    const errorBox = form.querySelector("#form-error");
    errorBox.innerHTML = "";
    const button = form.querySelector("#start");
    button.disabled = true; button.innerHTML = `<span class="spinner"></span> Doğrulanıyor...`;
    try {
      const res = await api("/api/scans", { method: "POST", body: JSON.stringify({
        target: scanForm.target, mode: scanForm.mode, verify_method: scanForm.verify_method,
        declarant: scanForm.declarant, accept_declaration: scanForm.accept, enable_port_scan: scanForm.ports }) });
      toast(`Tarama başladı · ${res.authorization}`);
      location.hash = `#/tarama/${res.job_id}`;  // ilerleme ekranının kendi adresi
    } catch (err) {
      button.disabled = false; button.innerHTML = `${icon("radar")} Taramayı başlat`;
      errorBox.innerHTML = authErrorBox(err);
    }
  });
}

function authErrorBox(err) {
  const d = err.detail || {};
  const list = (d.errors || []).map((x) => `<li>${esc(x)}</li>`).join("");
  const record = d.value ? `
    <div class="field mt-sm"><span class="label">DNS TXT kaydı</span>
      <div class="codebox">_sefalet-verify.${esc(d.hostname)}  TXT  "${esc(d.value)}"</div></div>
    <div class="field"><span class="label">veya HTTP dosyası</span>
      <div class="codebox">https://${esc(d.hostname)}/.well-known/sefalet-verify.txt → ${esc(d.value)}</div></div>` : "";
  return `<div class="field"><div class="notice notice-error"><b>${esc(err.message)}</b>${list ? `<ul>${list}</ul>` : ""}</div>${record}</div>`;
}

async function renderProgress(jobId) {
  setHeader("Taranıyor", "Tarama İlerlemesi");
  let first;
  try { first = await api(`/api/jobs/${encodeURIComponent(jobId)}`); } catch (err) {
    view.innerHTML = `<div class="card">${emptyState("Tarama işi bulunamadı", "Panel yeniden başlatıldıysa iş kaydı silinmiş olabilir. Tamamlanan taramalar Raporlar bölümündedir.", `<a class="btn" href="#/raporlar">Raporlar</a>`)}</div>`;
    return;
  }
  const withPorts = first.enable_port_scan;
  const steps = CHECKS.map((c) => `<div class="step" data-step="${c}">
      <span class="dot"></span><div><b>${esc(CHECK_LABEL[c])}</b><div class="faint">${esc(CHECK_SUB[c])}</div></div>
      <span class="state faint">${c === "ports" && !withPorts ? "kapalı" : "bekliyor"}</span></div>`).join("");
  view.innerHTML = `<div class="grid grid-main"><div class="card card-glow">
      <div class="card-title"><div><h2 id="job-title">Tarama sürüyor…</h2><div class="sub">${esc(first.target)}</div></div><span class="spinner" id="job-spin"></span></div>
      <div class="steps">${steps}</div><div id="job-result"></div></div>
      <div class="notice">Tarama arka planda çalışır. Bu sayfadan ayrılsanız bile tamamlandığında
      <a href="#/raporlar">Raporlar</a> bölümünde görünür.</div></div>`;

  clearInterval(pollTimer);
  const tick = async () => {
    let job;
    try { job = await api(`/api/jobs/${encodeURIComponent(jobId)}`); } catch (err) { clearInterval(pollTimer); toast(err.message, true); return; }
    CHECKS.forEach((c) => {
      const el = view.querySelector(`[data-step="${c}"]`);
      if (!el) return;
      const dot = el.querySelector(".dot"), state = el.querySelector(".state");
      if (job.completed_steps.includes(c)) { el.className = "step done"; dot.className = "dot dot-ok"; state.textContent = "tamamlandı"; }
      else if (job.current_step === c) { el.className = "step running"; dot.className = "dot dot-run"; state.textContent = "çalışıyor…"; }
    });
    if (job.status === "done" || job.status === "error") {
      clearInterval(pollTimer);
      const spin = view.querySelector("#job-spin"); if (spin) spin.remove();
      const title = view.querySelector("#job-title");
      const result = view.querySelector("#job-result");
      if (job.status === "done") {
        title.textContent = "Tarama tamamlandı";
        result.innerHTML = `<div class="row mt"><a class="btn btn-primary" href="#/rapor/${esc(job.scan_id)}">Raporu görüntüle →</a></div>`;
        refreshStatus();
      } else {
        title.textContent = "Tarama başarısız";
        result.innerHTML = `<div class="notice notice-error mt">${esc(job.error)}</div>`;
      }
    }
  };
  tick();
  pollTimer = setInterval(tick, 700);
}

// --- Raporlar ------------------------------------------------------------

async function renderReports() {
  setHeader("Raporlar", "Tarama Geçmişi");
  const scans = await api("/api/scans");
  if (!scans.length) {
    view.innerHTML = `<div class="card">${emptyState("Rapor yok", "Tamamlanan taramalar burada listelenir.",
      `<a class="btn btn-primary" href="#/tarama">Tarama başlat</a>`)}</div>`;
    return;
  }
  view.innerHTML = `<div class="card"><table class="table">
    <thead><tr><th>Not</th><th>Hedef</th><th>Tarih</th><th>Puan</th><th>Bulgular</th><th>İzin</th><th></th></tr></thead>
    <tbody>${scans.map((s) => `<tr class="click" data-id="${esc(s.scan_id)}">
      <td>${gradeBox(s.grade, true)}</td>
      <td><b>${esc(s.target)}</b>${s.complete ? "" : ' <span class="tag">eksik</span>'}</td>
      <td class="muted">${esc(fmtDate(s.started_at))}</td>
      <td class="mono">${esc(s.score ?? "-")}/100</td>
      <td><div class="mini-counts">${miniCounts(s.counts)}</div></td>
      <td><span class="tag">${esc(AUTH_SHORT[s.auth_method] || s.auth_method)}</span></td>
      <td><div class="row">
        <a class="btn btn-sm" href="/api/scans/${esc(s.scan_id)}/pdf" data-stop>PDF</a>
        <a class="btn btn-sm" href="/api/scans/${esc(s.scan_id)}/json" data-stop>JSON</a></div></td>
    </tr>`).join("")}</tbody></table></div>`;
  view.querySelectorAll("tr.click").forEach((tr) => tr.addEventListener("click", (e) => {
    if (e.target.closest("[data-stop]")) return;
    location.hash = `#/rapor/${tr.dataset.id}`;
  }));
}

function detailValue(v) {
  if (v === null || v === undefined) return "sorgulanamadı";
  if (typeof v === "boolean") return v ? "etkin" : "etkin değil";
  if (Array.isArray(v)) return v.length ? v.join(", ") : "yok";
  if (typeof v === "object") return Object.entries(v).map(([k, x]) => `${k}: ${x}`).join(", ");
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}T/.test(v)) return fmtDate(v);
  return String(v);
}

const DETAIL_LABELS = {
  subject: "Sertifika sahibi", issuer: "Sağlayıcı", not_after: "Bitiş", days_left: "Kalan gün", key: "Anahtar",
  signature_algorithm: "İmza", protocol: "Protokol", cipher: "Şifre takımı", legacy_protocols: "Eski protokoller",
  san: "Kapsanan adlar", a: "A", aaaa: "AAAA", ns: "NS", mx: "MX", spf: "SPF", dmarc: "DMARC", caa: "CAA",
  dnssec: "DNSSEC", failed_queries: "Başarısız sorgular", ip: "IP", ports: "Port durumları", open: "Açık portlar",
  email_domain: "E-posta alanı", issuer_organization: "Sağlayıcı kurum", not_before: "Başlangıç",
  serial: "Seri no", chain_check: "Zincir kontrolü",
};

async function renderReport(id) {
  setHeader("Rapor", "Rapor Ayrıntısı");
  let scan;
  try { scan = await api(`/api/scans/${encodeURIComponent(id)}`); } catch (err) {
    view.innerHTML = `<div class="card">${emptyState("Rapor bulunamadı", err.message, `<a class="btn" href="#/raporlar">Raporlara dön</a>`)}</div>`;
    return;
  }
  setHeader(scan.target, "Rapor Ayrıntısı");
  const findings = scan.findings_sorted;
  const sum = scan.summary;
  let active = "all";

  const tabs = () => [["all", "Tümü", findings.length], ...CHECKS.map((c) => [c, CHECK_LABEL[c], findings.filter((f) => f.check === c).length])]
    .map(([key, label, n]) => `<button class="tab ${active === key ? "active" : ""}" data-tab="${key}">${esc(label)}<span class="count">${n}</span></button>`).join("");

  const findingHtml = (f) => `
    <details class="finding">
      <summary class="sev-${esc(f.severity)}"><span class="bar"></span>
        <span class="fid">${esc(f.id)}</span>
        <span class="ftitle">${esc(f.title)}</span>
        <span class="row">${f.confidence === "probable" ? '<span class="tag tag-probable">Olası</span>' : ""}${sevBadge(f.severity, f.severity_label)}</span>
      </summary>
      <div class="body">
        <div><h4>Kanıt</h4><div class="evidence">${esc(f.evidence)}</div></div>
        ${f.description ? `<div><h4>Açıklama</h4><p>${esc(f.description)}</p></div>` : ""}
        ${f.recommendation ? `<div><h4>Öneri</h4><p>${esc(f.recommendation)}</p></div>` : ""}
        <div class="row"><span class="tag">${esc(f.category)}</span><span class="tag ${f.confidence === "probable" ? "tag-probable" : ""}">${esc(f.confidence_label)}</span>
          ${(f.references || []).map((r) => `<span class="faint mono">${esc(r)}</span>`).join(" ")}</div>
        ${f.confidence === "probable" ? '<div class="notice notice-warn">Bu bulgu doğrulanmamıştır; kesin güvenlik açığı olarak değerlendirilmemelidir. Manuel doğrulama önerilir.</div>' : ""}
      </div>
    </details>`;

  const drawFindings = () => {
    const list = active === "all" ? findings : findings.filter((f) => f.check === active);
    view.querySelector("#tabs").innerHTML = tabs();
    view.querySelector("#findings").innerHTML = list.length ? list.map(findingHtml).join("")
      : `<div class="empty"><h3>Bu bölümde bulgu yok</h3></div>`;
    view.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => { active = t.dataset.tab; drawFindings(); }));
  };

  const checks = scan.checks.map((c) => `
    <div class="step"><span class="dot ${STATUS_DOT[c.status]}"></span>
      <div><b>${esc(CHECK_LABEL[c.check_name] || c.check_name)}</b>${c.message ? `<div class="faint">${esc(c.message)}</div>` : ""}</div>
      <span class="state">${c.findings.length} bulgu</span></div>`).join("");

  const details = scan.checks.filter((c) => Object.keys(c.details || {}).length).map((c) => `
    <div class="card"><div class="card-title"><h2>${esc(CHECK_LABEL[c.check_name] || c.check_name)}</h2><span class="sub">teknik ayrıntılar</span></div>
      <dl class="kv">${Object.entries(c.details).map(([k, v]) => `<dt>${esc(DETAIL_LABELS[k] || k)}</dt><dd>${esc(detailValue(v))}</dd>`).join("")}</dl></div>`).join("");

  view.innerHTML = `
    <div class="card card-glow"><div class="report-head">
      ${gradeBox(sum.grade)}
      <div><h2>${esc(scan.target)}</h2>
        <div class="muted">${esc(fmtDate(scan.started_at))} · Puan <b class="mono">${esc(sum.score)}/100</b> · ${esc(scan.authorization.method === "lab" ? "Lab" : sum.auth_label)} · ${esc((scan.target_ips || []).join(", "))}</div></div>
      <span class="spacer"></span>
      <a class="btn" href="/api/scans/${esc(scan.scan_id)}/pdf">${icon("down")} PDF</a>
      <a class="btn" href="/api/scans/${esc(scan.scan_id)}/json">${icon("down")} JSON</a>
      <button class="btn btn-danger" id="delete">${icon("trash")} Sil</button>
    </div>
    <p class="mt-sm">${esc(scan.risk?.summary_tr || "")}</p>
    ${sevBar(sum.counts)}
    <div class="sevlegend">${SEVERITIES.map((k) => `<span class="sev-${k}">${sum.counts[k]} ${SEV_LABEL[k]}</span>`).join("")}</div>
    </div>

    <div class="grid grid-main mt">
      <div><div class="tabs" id="tabs"></div><div id="findings"></div></div>
      <div class="stack">
        <div class="card"><div class="card-title"><h2>Kontroller</h2></div><div class="steps">${checks}</div></div>
        <div class="card"><div class="card-title"><h2>Tarama izni</h2></div>
          <dl class="kv"><dt>Yöntem</dt><dd>${esc(sum.auth_label)}</dd><dt>Kayıt</dt><dd>${esc(scan.authorization.details)}</dd>
          <dt>Zaman</dt><dd>${esc(fmtDate(scan.authorization.verified_at))}</dd><dt>Kimlik</dt><dd>${esc(scan.scan_id)}</dd></dl></div>
        ${details}
      </div>
    </div>`;
  applyWidths();
  drawFindings();
  view.querySelector("#delete").addEventListener("click", async () => {
    if (!confirm(`${scan.target} taramasını silmek istiyor musunuz?`)) return;
    try { await api(`/api/scans/${scan.scan_id}`, { method: "DELETE" }); toast("Tarama silindi"); location.hash = "#/raporlar"; }
    catch (err) { toast(err.message, true); }
  });
}

// --- Doğrulama -----------------------------------------------------------

async function renderVerify() {
  setHeader("Doğrulama", "Sahiplik Doğrulama");
  view.innerHTML = `<div class="grid grid-main">
    <form class="card card-glow" id="token-form">
      <div class="card-title"><div><h2>Sahiplik doğrulama</h2><div class="sub">Teknik doğrulama, port kontrolü dahil tüm kontrolleri açar</div></div></div>
      <div class="field"><label for="t-target">Alan adı</label><input class="input" id="t-target" required placeholder="ornek.com"></div>
      <div class="row"><button class="btn btn-primary" type="submit">Talimat al</button>
        <button class="btn" type="button" id="regen">Yeni token üret</button></div>
      <div id="token-result" class="mt"></div>
    </form>
    <div class="stack">
      <div class="card"><div class="card-title"><h2>Nasıl çalışır?</h2></div>
        <div class="steps">
          <div class="step"><span class="dot dot-ok"></span><div><b>1. Token al</b><div class="faint">Her alan adı için rastgele bir değer üretilir.</div></div></div>
          <div class="step"><span class="dot dot-ok"></span><div><b>2. Kaydı ekle</b><div class="faint">DNS TXT kaydı veya sitedeki doğrulama dosyası.</div></div></div>
          <div class="step"><span class="dot dot-ok"></span><div><b>3. Tara</b><div class="faint">Tarama başlarken kayıt otomatik kontrol edilir.</div></div></div>
        </div></div>
      <div class="notice">DNS değişikliklerinin yayılması birkaç dakika ile birkaç saat sürebilir.</div>
    </div></div>`;
  const form = view.querySelector("#token-form");
  const run = async (regenerate) => {
    const target = form.querySelector("#t-target").value.trim();
    if (!target) { toast("Alan adı girin", true); return; }
    try {
      const r = await api("/api/token", { method: "POST", body: JSON.stringify({ target, regenerate }) });
      form.querySelector("#token-result").innerHTML = `
        <div class="field"><span class="label">Yöntem 1 · DNS TXT kaydı</span>
          <dl class="kv"><dt>Ad</dt><dd>${esc(r.dns_name)}</dd><dt>Tür</dt><dd>TXT</dd></dl>
          <div class="codebox">${esc(r.value)}</div></div>
        <div class="field"><span class="label">Yöntem 2 · HTTP dosyası</span>
          <dl class="kv"><dt>Adres</dt><dd>${esc(r.http_url)}</dd></dl>
          <div class="codebox">${esc(r.value)}</div></div>
        <a class="btn" href="#/tarama" id="go-scan">Bu hedefi tara →</a>`;
      form.querySelector("#go-scan").addEventListener("click", () => { scanForm.target = r.hostname; scanForm.mode = "verify"; });
      if (regenerate) toast("Yeni token üretildi. Eski kayıt artık geçersiz.");
    } catch (err) { toast(err.message, true); }
  };
  form.addEventListener("submit", (e) => { e.preventDefault(); run(false); });
  form.querySelector("#regen").addEventListener("click", () => run(true));
}

// --- Hakkında ------------------------------------------------------------

async function renderAbout() {
  setHeader("Hakkında", "Politika ve Sınırlamalar");
  const meta = await getMeta();
  view.innerHTML = `<div class="grid grid-2">
    <div class="card"><div class="card-title"><h2>Tarama izni politikası</h2></div>
      <table class="table"><thead><tr><th>Kontrol</th><th>Gerekli izin</th></tr></thead><tbody>
        <tr><td>Pasif: TLS, HTTP başlıkları, DNS</td><td>Teknik doğrulama <b>veya</b> izin beyanı</td></tr>
        <tr><td>Aktif: TCP port kontrolü</td><td><b>Yalnızca</b> teknik doğrulama + açıkça etkinleştirme</td></tr>
      </tbody></table>
      <div class="notice mt">${esc(meta.declaration_text)}</div></div>
    <div class="card"><div class="card-title"><h2>Güven düzeyleri</h2></div>
      <div class="steps">
        <div class="step"><span class="dot dot-ok"></span><div><b>Doğrulandı</b><div class="faint">Doğrudan gözlemlendi (ör. sertifika süresi dolmuş).</div></div></div>
        <div class="step"><span class="dot dot-run"></span><div><b>Olası</b><div class="faint">Belirti var; manuel doğrulama gerekir. Kesin açık değildir.</div></div></div>
        <div class="step"><span class="dot dot-skip"></span><div><b>Bilgi amaçlı</b><div class="faint">Sorun değil; bağlam bilgisi.</div></div></div>
      </div></div>
    <div class="card"><div class="card-title"><h2>Güvenlik önlemleri</h2></div>
      <div class="steps">
        <div class="step"><span class="dot dot-ok"></span>Panel yalnızca bu bilgisayardan (127.0.0.1) erişilebilir.</div>
        <div class="step"><span class="dot dot-ok"></span>Özel/iç ağ adresleri lab modu dışında reddedilir (SSRF koruması).</div>
        <div class="step"><span class="dot dot-ok"></span>Exploit, brute force, parola denemesi yapılmaz.</div>
        <div class="step"><span class="dot dot-ok"></span>Port kontrolü varsayılan kapalı; 21 sabit port, banner okuma yok.</div>
      </div></div>
    <div class="card"><div class="card-title"><h2>Sürüm</h2></div>
      <dl class="kv"><dt>Uygulama</dt><dd>Sefalet Security Scanner ${esc(meta.version)}</dd><dt>Komut satırı</dt><dd>sefalet scan / sefalet token</dd></dl></div>
  </div>`;
}

// --- Yönlendirme ---------------------------------------------------------

async function refreshStatus() {
  try {
    const s = await api("/api/summary");
    const pill = document.getElementById("status-pill");
    pill.className = `pill${s.active_jobs ? " busy" : ""}`;
    pill.innerHTML = s.active_jobs
      ? `<span class="dot dot-run"></span> ${s.active_jobs} aktif tarama`
      : `<span class="dot dot-ok"></span> Sistem aktif`;
  } catch { /* panel kapalıysa sessizce geç */ }
}

async function route() {
  clearInterval(pollTimer);
  const [, page = "panel", arg] = location.hash.split("/");
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active",
    a.dataset.route === page || (page === "rapor" && a.dataset.route === "raporlar")));
  const pages = { panel: renderPanel, tarama: renderScan, raporlar: renderReports, dogrulama: renderVerify, hakkinda: renderAbout };
  try {
    if (page === "rapor" && arg) await renderReport(arg);
    else if (page === "tarama" && arg) await renderProgress(arg);
    else await (pages[page] || renderPanel)();
  } catch (err) {
    view.innerHTML = `<div class="notice notice-error">${esc(err.message || "Beklenmeyen hata")}</div>`;
  }
  window.scrollTo(0, 0);
}

window.addEventListener("hashchange", route);
route();
refreshStatus();
setInterval(refreshStatus, 5000);
