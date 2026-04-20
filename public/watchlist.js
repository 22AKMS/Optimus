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
  return `${value.slice(0, size).trim()}...`;
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
  return parts.slice(0, 3).join(" / ") || "Structured product data pending";
}

function targetLabel(cve) {
  const parts = [cve.primary_vendor, cve.primary_product]
    .map((value) => String(value || "").trim())
    .filter(isKnownValue);

  if (parts.length === 2) return `${parts[0]} / ${parts[1]}`;
  if (parts.length === 1) return parts[0];
  return exploitSummary(cve);
}

function cveCard(cve) {
  return `
    <article class="item-card">
      <div class="item-card-body stack tight">
        <div>
          <div class="cve-card-header">
            <h3 class="cve-card-title">${escapeHtml(cve.id)}</h3>
            <span class="badge cve-card-badge ${severityClass(cve.severity)}">${escapeHtml(cve.severity || "UNKNOWN")}</span>
          </div>
          <p class="muted compact">${escapeHtml(targetLabel(cve))}</p>
        </div>
        <p>${escapeHtml(excerpt(cve.description))}</p>
        <div class="badge-row left-align">
          <span class="badge">CVSS ${escapeHtml(scoreLabel(cve.cvss_base_score))}</span>
          <span class="badge">${escapeHtml(formatDate(cve.published_at))}</span>
        </div>
        <a class="inline-link" href="/cves/${encodeURIComponent(cve.id)}">Open details -></a>
      </div>
    </article>
  `;
}

async function loadWatchlist() {
  const data = await fetchJson("/api/watchlist");
  const count = document.getElementById("watchlistCount");
  const grid = document.getElementById("watchlistGrid");

  count.textContent = `${data.count || 0} saved`;

  if (!data.items || !data.items.length) {
    grid.innerHTML = '<div class="panel empty-state">No saved CVEs yet. Save a CVE from its detail page and it will show up here.</div>';
    return;
  }

  grid.innerHTML = data.items.map(cveCard).join("");
}

window.addEventListener("DOMContentLoaded", () => {
  loadWatchlist().catch((error) => {
    const message = escapeHtml(error.message || String(error));
    document.getElementById("watchlistGrid").innerHTML = `<div class="panel empty-state">${message}</div>`;
  });
});
