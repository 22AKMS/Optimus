const state = {
  cves: [],
  severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"],
  years: [],
  pagination: {
    page: 1,
    limit: 40,
    page_count: 1,
    total_items: 0,
    has_prev: false,
    has_next: false
  }
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

function isKnownValue(value) {
  const normalized = String(value || "").trim();
  return normalized && !/^unknown\b/i.test(normalized);
}

function humanizeMetric(value) {
  const normalized = String(value || "").trim();
  if (!normalized) return "";
  return normalized
    .toLowerCase()
    .split(/[\s_]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function interactionLabel(value) {
  const normalized = String(value || "").trim().toUpperCase();
  if (!normalized) return "";
  if (normalized === "NONE") return "No user interaction";
  if (normalized === "REQUIRED") return "User interaction required";
  return `${humanizeMetric(normalized)} user interaction`;
}

function exploitSummary(cve) {
  const parts = [];
  if (cve.has_kev) parts.push("Known exploited");
  if (isKnownValue(cve.cwe_id)) parts.push(String(cve.cwe_id).trim().toUpperCase());
  if (isKnownValue(cve.attack_vector)) parts.push(humanizeMetric(cve.attack_vector));
  const interaction = interactionLabel(cve.user_interaction);
  if (interaction) parts.push(interaction);
  if (!parts.length && isKnownValue(cve.vuln_status)) {
    parts.push(humanizeMetric(cve.vuln_status));
  }
  return parts.slice(0, 3).join(" · ") || "Structured product data pending";
}

function targetLabel(cve) {
  const parts = [cve.primary_vendor, cve.primary_product]
    .map((value) => String(value || "").trim())
    .filter(isKnownValue);

  if (parts.length === 2) return `${parts[0]} · ${parts[1]}`;
  if (parts.length === 1) return parts[0];
  return exploitSummary(cve);
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
  const severity = cve.severity || "UNKNOWN";
  return `
    <article class="item-card">
      <div class="item-card-body stack tight">
        <div>
          <div class="cve-card-header">
            <h3 class="cve-card-title">${escapeHtml(cve.id)}</h3>
            <span class="badge cve-card-badge ${severityClass(severity)}">${escapeHtml(severity)}</span>
          </div>
          <p class="muted compact">${escapeHtml(targetLabel(cve))}</p>
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
  const severity = cve.severity || "UNKNOWN";
  return `
    <a class="card-link mini-card" href="/cves/${encodeURIComponent(cve.id)}">
      <div class="cve-card-header">
        <strong class="cve-card-title">${escapeHtml(cve.id)}</strong>
        <span class="badge cve-card-badge ${severityClass(severity)}">${escapeHtml(severity)}</span>
      </div>
      <div class="muted compact">${escapeHtml(targetLabel(cve))}</div>
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
  const { page, limit, total_items: totalItems } = state.pagination;
  const start = totalItems ? ((page - 1) * limit) + 1 : 0;
  const end = totalItems ? Math.min(page * limit, totalItems) : 0;
  count.textContent = totalItems ? `${start}-${end} of ${totalItems}` : "0 results";

  if (!state.cves.length) {
    grid.innerHTML = '<div class="panel empty-state">No CVEs matched your filters. Try a broader search or run a fresh NVD sync.</div>';
    return;
  }

  grid.innerHTML = state.cves.map(cveCard).join("");
}

function currentQueryState() {
  return {
    search: document.getElementById("searchInput").value.trim(),
    product: document.getElementById("productInput").value.trim(),
    severity: document.getElementById("severitySelect").value,
    year: document.getElementById("yearSelect").value,
    sort: document.getElementById("sortSelect").value,
    direction: document.getElementById("directionSelect").value,
    normalized_only: document.getElementById("normalizedOnlyToggle").checked ? "1" : ""
  };
}

function syncUrl(page = state.pagination.page || 1) {
  const params = new URLSearchParams();
  const filters = currentQueryState();

  for (const [key, value] of Object.entries(filters)) {
    if (value) params.set(key, value);
  }

  if (page > 1) params.set("page", String(page));
  const query = params.toString();
  const target = query ? `/?${query}` : "/";
  window.history.replaceState({}, "", target);
}

function readInitialFilters() {
  const params = new URLSearchParams(window.location.search);
  const get = (name, fallback = "") => params.get(name) || fallback;

  document.getElementById("searchInput").value = get("search");
  document.getElementById("productInput").value = get("product");
  document.getElementById("sortSelect").value = get("sort", "newest");
  document.getElementById("directionSelect").value = get("direction", "desc");
  document.getElementById("normalizedOnlyToggle").checked = ["1", "true", "yes", "on"].includes(get("normalized_only").toLowerCase());

  return {
    severity: get("severity"),
    year: get("year"),
    page: Math.max(Number(get("page", "1")), 1)
  };
}

function renderPagination() {
  const pagination = document.getElementById("paginationControls");
  const { page, page_count: pageCount, has_prev: hasPrev, has_next: hasNext, total_items: totalItems } = state.pagination;

  if (!totalItems || pageCount <= 1) {
    pagination.innerHTML = "";
    return;
  }

  const pages = new Set([1, pageCount, page - 1, page, page + 1].filter((value) => value >= 1 && value <= pageCount));
  const orderedPages = Array.from(pages).sort((left, right) => left - right);
  const buttons = [];
  let previous = 0;

  for (const value of orderedPages) {
    if (previous && value - previous > 1) {
      buttons.push('<span class="pagination-ellipsis">…</span>');
    }
    buttons.push(`
      <button type="button" class="pagination-button ${value === page ? 'active' : ''}" data-page="${value}">${value}</button>
    `);
    previous = value;
  }

  pagination.innerHTML = `
    <div class="pagination-summary muted">Page ${page} of ${pageCount}</div>
    <div class="pagination-row">
      <button type="button" class="pagination-button" data-page="${page - 1}" ${hasPrev ? "" : "disabled"}>← Previous</button>
      ${buttons.join("")}
      <button type="button" class="pagination-button" data-page="${page + 1}" ${hasNext ? "" : "disabled"}>Next →</button>
    </div>
  `;

  pagination.querySelectorAll("button[data-page]").forEach((button) => {
    button.addEventListener("click", () => {
      const targetPage = Number(button.dataset.page || page);
      loadCves(targetPage).catch(console.error);
      window.scrollTo({ top: document.getElementById("cveGrid").offsetTop - 140, behavior: "smooth" });
    });
  });
}

async function loadCves(page = 1) {
  const filters = currentQueryState();
  const params = new URLSearchParams();

  if (filters.search) params.set("search", filters.search);
  if (filters.product) params.set("product", filters.product);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.year) params.set("year", filters.year);
  if (filters.sort) params.set("sort", filters.sort);
  if (filters.direction) params.set("direction", filters.direction);
  if (filters.normalized_only) params.set("normalized_only", filters.normalized_only);
  params.set("page", String(page));
  params.set("limit", String(state.pagination.limit));

  const data = await fetchJson(`/api/cves?${params.toString()}`);
  state.cves = data.items || [];
  state.severities = data.severities || state.severities;
  state.years = data.years || [];
  state.pagination = data.pagination || state.pagination;
  renderFilters(filters.severity, filters.year);
  renderCves();
  renderPagination();
  syncUrl(state.pagination.page || page);
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
  loadCves(1).catch(console.error);
});

for (const inputId of ["searchInput", "productInput"]) {
  document.getElementById(inputId).addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      loadCves(1).catch(console.error);
    }
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  const initial = readInitialFilters();
  await loadOverview();
  await loadCves(initial.page || 1);
  await loadHighSeverity();
});
