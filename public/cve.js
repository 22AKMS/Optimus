const cveId = String(document.body.dataset.cveId || "").trim().toUpperCase();
let currentCve = null;

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }
  return payload;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function severityClass(severity) {
  return `severity-${String(severity || "unknown").toLowerCase()}`;
}

function formatDate(value) {
  if (!value) return "Unknown date";
  return new Date(value).toLocaleString();
}

function scoreLabel(score) {
  return score === null || score === undefined ? "N/A" : Number(score).toFixed(1);
}

function safeUrl(url) {
  const value = String(url || "").trim();
  return /^https?:\/\//i.test(value) ? value : "#";
}

function renderHero(data) {
  const hero = document.getElementById("cveHero");
  const watchDisabled = !data.primary_product_id;

  hero.innerHTML = `
    <div class="stack">
      <div class="section-title-row compact-row">
        <div>
          <p class="eyebrow">${escapeHtml(data.primary_vendor || "Unknown vendor")}</p>
          <h1>${escapeHtml(data.id)}</h1>
          <p class="muted compact">${escapeHtml(data.primary_product || "Unknown product")} · ${escapeHtml(data.vuln_status || "Unknown status")}</p>
        </div>
        <span class="badge ${severityClass(data.severity)}">${escapeHtml(data.severity || "UNKNOWN")}</span>
      </div>
      <p>${escapeHtml(data.description)}</p>
      <div class="badge-row left-align">
        <span class="badge">CVSS ${escapeHtml(scoreLabel(data.cvss_base_score))}</span>
        <span class="badge">${escapeHtml(data.cvss_version || "CVSS N/A")}</span>
        ${data.cwe_id ? `<span class="badge">${escapeHtml(data.cwe_id)}</span>` : ""}
        ${data.has_kev ? '<span class="badge severity-critical">Known Exploited</span>' : ""}
      </div>
      <div class="meta-grid">
        <div class="panel subtle-panel">
          <strong>Published</strong>
          <p class="muted compact">${escapeHtml(formatDate(data.published_at))}</p>
        </div>
        <div class="panel subtle-panel">
          <strong>Modified</strong>
          <p class="muted compact">${escapeHtml(formatDate(data.last_modified_at))}</p>
        </div>
        <div class="panel subtle-panel">
          <strong>Attack Vector</strong>
          <p class="muted compact">${escapeHtml(data.attack_vector || "Unknown")}</p>
        </div>
        <div class="panel subtle-panel">
          <strong>CWE</strong>
          <p class="muted compact">${escapeHtml(data.cwe_name || data.cwe_id || "Not listed")}</p>
        </div>
      </div>
      <div class="action-row left-align">
        <button id="saveButton" class="${data.saved ? "secondary" : ""}">${data.saved ? "Remove Saved CVE" : "Save CVE"}</button>
        <button id="watchButton" class="${data.primary_product_watched ? "secondary" : ""}" ${watchDisabled ? "disabled" : ""}>${data.primary_product_watched ? "Unwatch Product" : "Watch Product"}</button>
      </div>
    </div>
  `;

  document.getElementById("saveButton").addEventListener("click", () => toggleSaved(data.saved).catch(showError));
  if (!watchDisabled) {
    document.getElementById("watchButton").addEventListener("click", () => toggleWatch(data.primary_product_watched).catch(showError));
  }
}

function renderProducts(products) {
  const target = document.getElementById("productsList");
  if (!products.length) {
    target.innerHTML = '<div class="empty-state">No affected software entries were normalized for this CVE.</div>';
    return;
  }

  target.innerHTML = products.map((product) => `
    <article class="mini-card">
      <strong>${escapeHtml(product.vendor_name)} · ${escapeHtml(product.product_name)}</strong>
      <p class="muted compact">${escapeHtml(product.cpe_uri || product.canonical_cpe_uri || "No CPE URI")}</p>
      <div class="badge-row left-align">
        ${product.version_start_including ? `<span class="badge">Start ≥ ${escapeHtml(product.version_start_including)}</span>` : ""}
        ${product.version_start_excluding ? `<span class="badge">Start > ${escapeHtml(product.version_start_excluding)}</span>` : ""}
        ${product.version_end_including ? `<span class="badge">End ≤ ${escapeHtml(product.version_end_including)}</span>` : ""}
        ${product.version_end_excluding ? `<span class="badge">End < ${escapeHtml(product.version_end_excluding)}</span>` : ""}
      </div>
    </article>
  `).join("");
}

function renderReferences(references) {
  const target = document.getElementById("referencesList");
  if (!references.length) {
    target.innerHTML = '<div class="empty-state">No references were provided in the current NVD payload.</div>';
    return;
  }

  target.innerHTML = references.map((reference) => `
    <article class="mini-card">
      <a class="inline-link" href="${escapeHtml(safeUrl(reference.url))}" target="_blank" rel="noreferrer noopener">${escapeHtml(reference.url)}</a>
      <p class="muted compact">${escapeHtml(reference.source || "Unknown source")}</p>
      <div class="badge-row left-align">
        ${(reference.tags || []).map((tag) => `<span class="badge">${escapeHtml(tag)}</span>`).join("")}
      </div>
    </article>
  `).join("");
}

function renderRelated(items) {
  const target = document.getElementById("relatedCves");
  if (!items.length) {
    target.innerHTML = '<div class="empty-state">No related CVEs were found for the same CWE or affected product.</div>';
    return;
  }

  target.innerHTML = items.map((item) => `
    <a class="card-link mini-card" href="/cves/${encodeURIComponent(item.id)}">
      <div class="section-title-row compact-row">
        <strong>${escapeHtml(item.id)}</strong>
        <span class="badge ${severityClass(item.severity)}">${escapeHtml(item.severity || "UNKNOWN")}</span>
      </div>
      <div class="muted compact">${escapeHtml(item.primary_vendor || "Unknown vendor")} · ${escapeHtml(item.primary_product || "Unknown product")}</div>
      <div class="badge-row left-align">
        <span class="badge">CVSS ${escapeHtml(scoreLabel(item.cvss_base_score))}</span>
        <span class="badge">${escapeHtml(new Date(item.published_at).toLocaleDateString())}</span>
      </div>
    </a>
  `).join("");
}

function showMessage(message) {
  document.getElementById("actionMessage").textContent = message;
}

function showError(error) {
  showMessage(error.message || String(error));
}

async function toggleSaved(isSaved) {
  await fetchJson(`/api/cves/${encodeURIComponent(cveId)}/saved`, { method: isSaved ? "DELETE" : "POST" });
  showMessage(isSaved ? "Removed from saved CVEs." : "Saved CVE.");
  await loadCve();
}

async function toggleWatch(isWatched) {
  if (!currentCve?.primary_product_id) {
    return;
  }

  if (isWatched) {
    await fetchJson(`/api/cves/${encodeURIComponent(cveId)}/watch-product/${currentCve.primary_product_id}`, { method: "DELETE" });
    showMessage("Removed watched product.");
  } else {
    await fetchJson(`/api/cves/${encodeURIComponent(cveId)}/watch-product`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ product_id: currentCve.primary_product_id })
    });
    showMessage("Product added to watchlist.");
  }

  await loadCve();
}

async function loadCve() {
  const data = await fetchJson(`/api/cves/${encodeURIComponent(cveId)}`);
  currentCve = data;
  renderHero(data);
  renderProducts(data.products || []);
  renderReferences(data.references || []);
  renderRelated(data.related_cves || []);
}

window.addEventListener("DOMContentLoaded", () => {
  loadCve().catch(showError);
});
