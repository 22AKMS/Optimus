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
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function excerpt(text, size = 190) {
  const value = String(text || "").trim();
  if (value.length <= size) return value;
  return `${value.slice(0, size).trim()}…`;
}

function severityClass(severity) {
  return `severity-${String(severity || "unknown").toLowerCase()}`;
}

function formatDate(value) {
  if (!value) return "Unknown date";
  return new Date(value).toLocaleDateString();
}

function scoreLabel(score) {
  return score === null || score === undefined ? "N/A" : Number(score).toFixed(1);
}

function cveCard(cve) {
  return `
    <article class="item-card">
      <div class="item-card-body stack tight">
        <div>
          <div class="section-title-row compact-row">
            <h3>${escapeHtml(cve.id)}</h3>
            <span class="badge ${severityClass(cve.severity)}">${escapeHtml(cve.severity || "UNKNOWN")}</span>
          </div>
          <p class="muted compact">${escapeHtml(cve.primary_vendor || "Unknown vendor")} · ${escapeHtml(cve.primary_product || "Unknown product")}</p>
        </div>
        <p>${escapeHtml(excerpt(cve.description))}</p>
        <div class="badge-row left-align">
          <span class="badge">CVSS ${escapeHtml(scoreLabel(cve.cvss_base_score))}</span>
          <span class="badge">${escapeHtml(formatDate(cve.published_at))}</span>
        </div>
        <a class="inline-link" href="/cves/${encodeURIComponent(cve.id)}">Open details →</a>
      </div>
    </article>
  `;
}

async function loadWatchlist() {
  const data = await fetchJson('/api/watchlist');
  const count = document.getElementById('watchlistCount');
  const grid = document.getElementById('watchlistGrid');
  const watched = document.getElementById('watchedProductsList');

  count.textContent = `${data.count || 0} saved`;

  if (!data.items || !data.items.length) {
    grid.innerHTML = '<div class="panel empty-state">No saved CVEs yet. Save a CVE from its detail page and it will show up here.</div>';
  } else {
    grid.innerHTML = data.items.map(cveCard).join('');
  }

  if (!data.watched_products || !data.watched_products.length) {
    watched.innerHTML = '<div class="empty-state">No watched products yet.</div>';
    return;
  }

  watched.innerHTML = data.watched_products.map((product) => `
    <article class="mini-card">
      <strong>${escapeHtml(product.vendor_name || 'Unknown vendor')} · ${escapeHtml(product.product_name || 'Unknown product')}</strong>
      <p class="muted compact">Product ID ${escapeHtml(product.product_id)}</p>
    </article>
  `).join('');
}

window.addEventListener('DOMContentLoaded', () => {
  loadWatchlist().catch((error) => {
    document.getElementById('watchlistGrid').innerHTML = `<div class="panel empty-state">${escapeHtml(error.message || String(error))}</div>`;
  });
});
