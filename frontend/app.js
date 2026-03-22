const form = document.getElementById("lookup-form");
const input = document.getElementById("domain-input");
const submitBtn = document.getElementById("submit-btn");
const errorMsg = document.getElementById("error-msg");
const loader = document.getElementById("loader");
const results = document.getElementById("results");
const resultDomain = document.getElementById("result-domain");
const exportBtn  = document.getElementById("export-btn");
const watchCard  = document.getElementById("watch-card");
const watchEmail = document.getElementById("watch-email");
const watchBtn   = document.getElementById("watch-btn");
const watchMsg   = document.getElementById("watch-msg");

let lastResults = null;

// Collapsible cards
document.addEventListener("click", (e) => {
  const title = e.target.closest(".card-title");
  if (!title) return;
  const bodyId = title.dataset.target;
  const body = document.getElementById(bodyId);
  if (!body) return;
  const collapsed = body.classList.toggle("hidden");
  title.classList.toggle("collapsed", collapsed);
});

function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }

function setError(msg) {
  errorMsg.textContent = msg;
  show(errorMsg);
}

function clearError() { hide(errorMsg); }

function renderTable(tableEl, rows) {
  tableEl.innerHTML = "";
  if (!rows.length) {
    tableEl.innerHTML = `<tr><td colspan="2" style="color:var(--text-dim)">No data</td></tr>`;
    return;
  }
  rows.forEach(([key, val]) => {
    const tr = document.createElement("tr");
    const valStr = Array.isArray(val)
      ? val.map((v) => `<span class="tag">${escHtml(v)}</span>`).join("")
      : escHtml(String(val ?? "—"));
    tr.innerHTML = `<td>${escHtml(key)}</td><td>${valStr}</td>`;
    tableEl.appendChild(tr);
  });
}

function escHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderDns(dns) {
  const rows = Object.entries(dns).filter(([, v]) => v && v.length > 0);
  renderTable(document.getElementById("dns-table"), rows);
}

function renderWhois(w) {
  const rows = Object.entries(w).filter(([, v]) => v && v !== "None");
  renderTable(document.getElementById("whois-table"), rows);
}

function renderHeaders(h) {
  const rows = Object.entries(h);
  renderTable(document.getElementById("headers-table"), rows);
}

function renderSsl(ssl) {
  const banner = document.getElementById("ssl-expiry-banner");
  const tableEl = document.getElementById("ssl-table");
  banner.innerHTML = "";

  if (!ssl || !Object.keys(ssl).length) {
    tableEl.innerHTML = `<tr><td colspan="2" style="color:var(--text-dim)">No SSL data</td></tr>`;
    return;
  }

  // Expiry banner
  const days = parseInt(ssl.days_remaining, 10);
  if (!isNaN(days)) {
    let cls = "ssl-ok", msg = `Valid for ${days} more days`;
    if (days < 0)  { cls = "ssl-expired"; msg = `EXPIRED ${Math.abs(days)} days ago`; }
    else if (days < 14) { cls = "ssl-critical"; msg = `CRITICAL — expires in ${days} days`; }
    else if (days < 30) { cls = "ssl-warn";     msg = `Warning — expires in ${days} days`; }
    banner.innerHTML = `<div class="ssl-banner ${cls}">${msg}</div>`;
  }

  // Render all rows except days_remaining / expired (shown in banner)
  const skip = new Set(["days_remaining", "expired"]);
  const rows = Object.entries(ssl).filter(([k, v]) => !skip.has(k) && v != null && v !== "");
  renderTable(tableEl, rows);
}

const TECH_CATEGORY_LABELS = {
  cdn:          "CDN",
  web_server:   "Web Server",
  cms:          "CMS / Platform",
  language:     "Language / Runtime",
  js_framework: "JS Framework",
  analytics:    "Analytics",
  waf:          "WAF / Security",
  hosting:      "Hosting",
};

const TECH_CATEGORY_COLORS = {
  cdn:          "tech-cdn",
  web_server:   "tech-server",
  cms:          "tech-cms",
  language:     "tech-lang",
  js_framework: "tech-js",
  analytics:    "tech-analytics",
  waf:          "tech-waf",
  hosting:      "tech-hosting",
};

function renderTechStack(tech) {
  const container = document.getElementById("techstack-content");
  container.innerHTML = "";

  const entries = Object.entries(tech || {}).filter(([, v]) => Array.isArray(v) && v.length);
  if (!entries.length) {
    container.innerHTML = `<p style="color:var(--text-dim);font-size:0.82rem">No technologies detected.</p>`;
    return;
  }

  entries.forEach(([cat, techs]) => {
    const row = document.createElement("div");
    row.className = "tech-row";

    const label = document.createElement("span");
    label.className = "tech-label";
    label.textContent = TECH_CATEGORY_LABELS[cat] || cat;

    const pills = document.createElement("div");
    pills.className = "tech-pills";
    techs.forEach((t) => {
      const span = document.createElement("span");
      span.className = `tech-pill ${TECH_CATEGORY_COLORS[cat] || "tech-other"}`;
      span.textContent = t;
      pills.appendChild(span);
    });

    row.appendChild(label);
    row.appendChild(pills);
    container.appendChild(row);
  });
}

function renderIpReputation(ipRep) {
  const container = document.getElementById("iprep-content");
  container.innerHTML = "";

  if (!ipRep || !ipRep.length) {
    container.innerHTML = `<p style="color:var(--text-dim);font-size:0.82rem">No IP data available.</p>`;
    return;
  }

  ipRep.forEach((host) => {
    const block = document.createElement("div");
    block.className = "ip-block";

    // Reputation badges
    const badges = [];
    if (host.is_proxy)   badges.push(`<span class="rep-badge rep-danger">Proxy / VPN</span>`);
    if (host.is_hosting) badges.push(`<span class="rep-badge rep-warn">Hosting / DC</span>`);
    if (!host.is_proxy && !host.is_hosting)
                         badges.push(`<span class="rep-badge rep-ok">Residential / ISP</span>`);

    // DNSBL badges
    const bl = host.blacklists || {};
    Object.entries(bl).forEach(([name, status]) => {
      const cls = status === "listed" ? "rep-danger" : status === "clean" ? "rep-ok" : "rep-neutral";
      badges.push(`<span class="rep-badge ${cls}">${escHtml(name)}: ${escHtml(status)}</span>`);
    });

    // Geo rows (skip internal flags shown as badges)
    const skipKeys = new Set(["ip","is_proxy","is_hosting","is_mobile","blacklists","country_code"]);
    const rows = Object.entries(host)
      .filter(([k, v]) => !skipKeys.has(k) && v != null && v !== "" && v !== false)
      .map(([k, v]) => `<tr><td>${escHtml(k)}</td><td>${escHtml(String(v))}</td></tr>`)
      .join("");

    block.innerHTML = `
      <div class="ip-header">
        <span class="ip-address">${escHtml(host.ip)}</span>
        <span class="ip-country">${host.country_code ? escHtml(host.country_code) : ""}</span>
        <div class="ip-badges">${badges.join("")}</div>
      </div>
      <table class="ip-table">${rows}</table>`;
    container.appendChild(block);
  });
}

function renderCt(ct) {
  const summary = document.getElementById("ct-summary");
  const tagsEl  = document.getElementById("ct-tags");
  tagsEl.innerHTML = "";

  if (!ct || (!ct.subdomains && !ct.total)) {
    summary.textContent = "No Certificate Transparency data available.";
    return;
  }

  const total = ct.total ?? 0;
  summary.textContent = `${total} unique subdomain${total !== 1 ? "s" : ""} discovered via CT logs.`;

  (ct.subdomains || []).forEach((sub) => {
    const span = document.createElement("span");
    span.className = "tag";
    span.textContent = sub;
    tagsEl.appendChild(span);
  });
}

function renderBreaches(breaches) {
  const container = document.getElementById("breaches-content");
  container.innerHTML = "";

  if (!breaches || !breaches.length) {
    container.innerHTML = `<p style="color:var(--text-dim);font-size:0.82rem">No known breaches found for this domain.</p>`;
    return;
  }

  const totalRecords = breaches.reduce((s, b) => s + (b.pwn_count || 0), 0);
  const summary = document.createElement("div");
  summary.className = "breach-summary";
  summary.innerHTML = `<span class="breach-count">${breaches.length} breach${breaches.length !== 1 ? "es" : ""} found</span> — <span class="breach-total">${totalRecords.toLocaleString()} total records exposed</span>`;
  container.appendChild(summary);

  breaches.forEach((b) => {
    const card = document.createElement("div");
    card.className = "breach-card";

    const count = b.pwn_count ? b.pwn_count.toLocaleString() : "?";
    const countClass = b.pwn_count > 1_000_000 ? "breach-count-high" : b.pwn_count > 100_000 ? "breach-count-med" : "breach-count-low";

    const badges = [];
    if (!b.is_verified) badges.push(`<span class="breach-badge badge-unverified">Unverified</span>`);
    if (b.is_sensitive) badges.push(`<span class="breach-badge badge-sensitive">Sensitive</span>`);

    const pills = (b.data_classes || []).map(d =>
      `<span class="breach-pill">${escHtml(d)}</span>`
    ).join("");

    card.innerHTML = `
      <div class="breach-header">
        <span class="breach-name">${escHtml(b.name)}</span>
        <span class="${countClass}">${count} records</span>
        <span class="breach-date">${escHtml(b.breach_date || "")}</span>
        ${badges.join("")}
      </div>
      ${pills ? `<div class="breach-pills">${pills}</div>` : ""}`;
    container.appendChild(card);
  });
}

function renderTakeover(findings) {
  const container = document.getElementById("takeover-content");
  container.innerHTML = "";

  const actionable = (findings || []).filter(f => f.status !== "check_failed");

  if (!actionable.length) {
    container.innerHTML = `<p style="color:var(--text-dim);font-size:0.82rem">No takeover vulnerabilities detected.</p>`;
    return;
  }

  actionable.forEach((f) => {
    const row = document.createElement("div");
    row.className = "takeover-row";

    const sevClass = f.severity === "high" ? "sev-high" : f.severity === "medium" ? "sev-medium" : "sev-info";
    const badge = `<span class="sev-badge ${sevClass}">${escHtml(f.severity.toUpperCase())}</span>`;
    const cname = f.cname ? `<span class="takeover-cname">${escHtml(f.cname)}</span>` : "";
    const service = f.service ? `<span class="takeover-service">${escHtml(f.service)}</span>` : "";

    row.innerHTML = `
      <div class="takeover-header">
        ${badge}
        <span class="takeover-sub">${escHtml(f.subdomain)}</span>
        ${service}
      </div>
      ${cname ? `<div class="takeover-detail">CNAME → ${cname}</div>` : ""}
      <div class="takeover-detail">${escHtml(f.detail)}</div>`;
    container.appendChild(row);
  });
}

function renderErrors(errors) {
  const section = document.getElementById("section-errors");
  if (!Object.keys(errors).length) { hide(section); return; }
  show(section);
  const rows = Object.entries(errors);
  renderTable(document.getElementById("errors-table"), rows);
}

exportBtn.addEventListener("click", async () => {
  if (!lastResults) return;
  exportBtn.disabled = true;
  exportBtn.textContent = "Generating PDF…";

  try {
    const res = await fetch("/api/export-pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(lastResults),
    });

    if (!res.ok) {
      const err = await res.json();
      alert("PDF generation failed: " + (err.detail || "unknown error"));
      return;
    }

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `osint-report-${lastResults.domain}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Network error during PDF export.");
  } finally {
    exportBtn.disabled = false;
    exportBtn.textContent = "\u21D9 Export Professional PDF";
  }
});

watchBtn.addEventListener("click", async () => {
  const email = watchEmail.value.trim();
  if (!email) { showWatchMsg("Please enter your email address.", "error"); return; }
  if (!lastResults) return;

  watchBtn.disabled = true;
  watchBtn.textContent = "Saving…";
  hideWatchMsg();

  try {
    const res = await fetch("/api/watch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: lastResults.domain, email }),
    });
    const data = await res.json();
    if (!res.ok) {
      showWatchMsg(data.detail || "Failed to set up monitoring.", "error");
    } else {
      showWatchMsg(data.warning || data.message, data.warning ? "warn" : "ok");
      watchBtn.textContent = "Watching";
      watchBtn.disabled = true;
    }
  } catch {
    showWatchMsg("Network error. Please try again.", "error");
    watchBtn.disabled = false;
    watchBtn.textContent = "Watch Domain";
  } finally {
    if (!watchBtn.disabled || watchMsg.classList.contains("msg-error")) {
      watchBtn.disabled = false;
      if (watchBtn.textContent === "Saving…") watchBtn.textContent = "Watch Domain";
    }
  }
});

function showWatchMsg(text, type) {
  watchMsg.textContent = text;
  watchMsg.className = `watch-msg msg-${type}`;
}

function hideWatchMsg() {
  watchMsg.textContent = "";
  watchMsg.className = "watch-msg hidden";
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearError();
  hide(results);
  hideWatchMsg();
  watchEmail.value = "";
  watchBtn.disabled = false;
  watchBtn.textContent = "Watch Domain";

  const domain = input.value.trim();
  if (!domain) { setError("Please enter a domain."); return; }

  submitBtn.disabled = true;
  show(loader);

  try {
    const res = await fetch("/api/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });

    const data = await res.json();

    if (!res.ok) {
      setError(data.detail || "Server error. Please try again.");
      return;
    }

    lastResults = data;
    resultDomain.textContent = data.domain;
    renderDns(data.dns || {});
    renderWhois(data.whois || {});
    renderSsl(data.ssl || {});
    renderTechStack(data.tech_stack || {});
    renderIpReputation(data.ip_reputation || []);
    renderCt(data.ct || {});
    renderHeaders(data.headers || {});
    renderBreaches(data.breaches || []);
    renderTakeover(data.takeover || []);
    renderErrors(data.errors || {});

    show(results);
  } catch (err) {
    setError("Network error — is the server running?");
  } finally {
    submitBtn.disabled = false;
    hide(loader);
  }
});
