const state = {
  cves: [],
  severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
  years: []
};

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

function statCard(label, value, detail = "") {
  return `
    <article class="panel stat-card">
      <p class="eyebrow">${escapeHtml(label)}</p>
      <strong class="stat-value">${escapeHtml(value)}</strong>
      ${detail ? `<p class="muted compact">${escapeHtml(detail)}</p>` : ""}
    </article>
  `;
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
          <span class="badge">${escapeHtml(String(cve.year || ""))}</span>
          ${cve.has_kev ? '<span class="badge severity-critical">KEV</span>' : ""}
        </div>
        <p class="muted compact">Published ${escapeHtml(formatDate(cve.published_at))}</p>
        <a class="inline-link" href="/cves/${encodeURIComponent(cve.id)}">Open details →</a>
      </div>
    </article>
  `;
}

function highSeverityCard(cve) {
  return `
    <a class="card-link mini-card" href="/cves/${encodeURIComponent(cve.id)}">
      <div class="section-title-row compact-row">
        <strong>${escapeHtml(cve.id)}</strong>
        <span class="badge ${severityClass(cve.severity)}">${escapeHtml(cve.severity || "UNKNOWN")}</span>
      </div>
      <div class="muted compact">${escapeHtml(cve.primary_vendor || "Unknown vendor")} · ${escapeHtml(cve.primary_product || "Unknown product")}</div>
      <div class="badge-row left-align">
        <span class="badge">CVSS ${escapeHtml(scoreLabel(cve.cvss_base_score))}</span>
        <span class="badge">${escapeHtml(formatDate(cve.published_at))}</span>
      </div>
    </a>
  `;
}

function renderOverview(payload) {
  const overview = payload.overview || {};
  const latestRun = payload.latest_run || null;
  const grid = document.getElementById("overviewGrid");
  const cards = [
    statCard("Total CVEs", overview.total_cves || 0, `${overview.recent_cves || 0} published in the last 30 days`),
    statCard("Critical CVEs", overview.critical_cves || 0, `${overview.high_cves || 0} high severity CVEs`),
    statCard("Known Exploited", overview.kev_cves || 0, "CISA KEV-matched items"),
    statCard("Average CVSS", scoreLabel(overview.avg_cvss), `Highest score ${scoreLabel(overview.max_cvss)}`),
    statCard("Latest Publish Date", overview.latest_published_at ? formatDate(overview.latest_published_at) : "No data", latestRun ? `Last sync: ${latestRun.status}` : "Run syncRecentCves after deploy"),
    statCard("Latest NVD Update", overview.latest_modified_at ? formatDate(overview.latest_modified_at) : "No data", "Most recently modified CVE in the catalog")
  ];
  grid.innerHTML = cards.join("");
}

function renderFilters(selectedSeverity = "", selectedYear = "") {
  const severitySelect = document.getElementById("severitySelect");
  severitySelect.innerHTML = '<option value="">All severities</option>' + state.severities
    .map((severity) => `<option value="${escapeHtml(severity)}">${escapeHtml(severity)}</option>`)
    .join("");
  if (selectedSeverity) {
    severitySelect.value = selectedSeverity;
  }

  const yearSelect = document.getElementById("yearSelect");
  yearSelect.innerHTML = '<option value="">All years</option>' + state.years
    .map((year) => `<option value="${year}">${year}</option>`)
    .join("");
  if (selectedYear) {
    yearSelect.value = String(selectedYear);
  }
}

function renderCves() {
  const grid = document.getElementById("cveGrid");
  const count = document.getElementById("cveCount");
  count.textContent = `${state.cves.length} result(s)`;

  if (!state.cves.length) {
    grid.innerHTML = '<div class="panel empty-state">No CVEs matched your filters. Try a broader search or run a fresh NVD sync.</div>';
    return;
  }

  grid.innerHTML = state.cves.map(cveCard).join("");
}

async function loadCves() {
  const search = document.getElementById("searchInput").value.trim();
  const product = document.getElementById("productInput").value.trim();
  const severity = document.getElementById("severitySelect").value;
  const year = document.getElementById("yearSelect").value;
  const sort = document.getElementById("sortSelect").value;
  const params = new URLSearchParams();

  if (search) params.set("search", search);
  if (product) params.set("product", product);
  if (severity) params.set("severity", severity);
  if (year) params.set("year", year);
  if (sort) params.set("sort", sort);

  const data = await fetchJson(`/api/cves?${params.toString()}`);
  state.cves = data.items || [];
  state.severities = data.severities || state.severities;
  state.years = data.years || [];
  renderFilters(severity, year);
  renderCves();
}

async function loadHighSeverity() {
  const data = await fetchJson("/api/high-severity");
  const target = document.getElementById("highSeverityList");

  if (!data.items || !data.items.length) {
    target.innerHTML = '<div class="empty-state">No high-severity CVEs yet.</div>';
    return;
  }

  target.innerHTML = data.items.map(highSeverityCard).join("");
}

async function loadOverview() {
  const data = await fetchJson("/api/analytics/overview");
  renderOverview(data);
}

document.getElementById("searchButton").addEventListener("click", () => {
  loadCves().catch(console.error);
});

for (const inputId of ["searchInput", "productInput"]) {
  document.getElementById(inputId).addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      loadCves().catch(console.error);
    }
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  await loadOverview();
  await loadCves();
  await loadHighSeverity();
});
