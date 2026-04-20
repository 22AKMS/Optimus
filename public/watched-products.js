let toastTimer = null;

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

function formatDateTime(value) {
  if (!value) return "Unknown";
  return new Date(value).toLocaleString();
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

function showToast(message, variant = "success") {
  const toast = document.getElementById("actionToast");
  if (!toast) return;
  toast.textContent = message;
  toast.className = `toast show ${variant}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.className = "toast";
  }, 2600);
}

function watchedFeedCard(cve) {
  return `
    <article class="item-card watched-feed-card ${cve.is_new ? "is-new" : ""}">
      <div class="item-card-body stack tight">
        <div class="stack tight">
          <div class="watch-card-title-row">
            <div class="cve-card-header">
              <h3 class="cve-card-title">${escapeHtml(cve.id)}</h3>
              <span class="badge cve-card-badge ${severityClass(cve.severity)}">${escapeHtml(cve.severity || "UNKNOWN")}</span>
            </div>
            ${cve.is_new ? '<span class="pill severity-critical">New</span>' : ""}
          </div>
          <p class="muted compact">${escapeHtml(targetLabel(cve))}</p>
        </div>
        <p>${escapeHtml(excerpt(cve.description))}</p>
        <div class="badge-row left-align">
          <span class="badge">CVSS ${escapeHtml(scoreLabel(cve.cvss_base_score))}</span>
          <span class="badge">Published ${escapeHtml(formatDate(cve.published_at))}</span>
          <span class="badge">Updated ${escapeHtml(formatDate(cve.activity_at || cve.last_modified_at))}</span>
          ${cve.has_kev ? '<span class="badge severity-critical">Known Exploited</span>' : ""}
        </div>
        <div class="watch-match-list">
          ${(cve.matched_products || []).map((product) => `
            <span class="badge ${product.is_new ? "match-badge-new" : ""}">
              ${escapeHtml(product.vendor_name || "Unknown vendor")} / ${escapeHtml(product.product_name || "Unknown product")}
              ${product.is_new ? " / New" : ""}
            </span>
          `).join("")}
        </div>
        <a class="inline-link" href="/cves/${encodeURIComponent(cve.id)}">Open details -></a>
      </div>
    </article>
  `;
}

function watchedProductCard(product) {
  return `
    <article class="mini-card watch-product-shell">
      <div class="product-card-head">
        <div class="product-card-copy stack tight">
          <strong>${escapeHtml(product.vendor_name || "Unknown vendor")} / ${escapeHtml(product.product_name || "Unknown product")}</strong>
          <p class="muted compact">Product ID ${escapeHtml(product.product_id)}</p>
        </div>
        <button
          type="button"
          class="product-watch-button secondary"
          data-unwatch-product-id="${escapeHtml(product.product_id)}"
        >
          Unwatch
        </button>
      </div>
      <div class="badge-row left-align">
        <span class="badge">${escapeHtml(product.matching_cve_count || 0)} matching CVEs</span>
        ${product.new_cve_count ? `<span class="badge severity-critical">${escapeHtml(product.new_cve_count)} new</span>` : ""}
        <span class="badge">Last checked ${escapeHtml(formatDateTime(product.last_viewed_at))}</span>
        ${product.latest_activity_at ? `<span class="badge">Latest activity ${escapeHtml(formatDate(product.latest_activity_at))}</span>` : ""}
      </div>
    </article>
  `;
}

async function markWatchedProductsViewed() {
  await fetchJson("/api/watched-products/mark-viewed", { method: "POST" });
}

async function removeWatchedProduct(productId) {
  await fetchJson(`/api/watched-products/${encodeURIComponent(productId)}`, { method: "DELETE" });
  showToast("Removed watched product.");
  await loadWatchedProducts();
}

function renderWatchedFeedSection(data) {
  const count = document.getElementById("watchedFeedCount");
  const grid = document.getElementById("watchedFeed");
  const total = Number(data.watched_feed_count || 0);
  const visible = Array.isArray(data.watched_feed) ? data.watched_feed.length : 0;
  const newCount = Number(data.watched_feed_new_count || 0);

  if (!data.watched_products || !data.watched_products.length) {
    count.textContent = "0 tracked";
    grid.innerHTML = '<div class="panel empty-state">Watch a product from a CVE detail page to track matching vulnerabilities here.</div>';
    return;
  }

  if (total > visible) {
    count.textContent = `Showing ${visible} of ${total}${newCount ? ` / ${newCount} new` : ""}`;
  } else {
    count.textContent = `${total} matching CVEs${newCount ? ` / ${newCount} new` : ""}`;
  }

  if (!visible) {
    grid.innerHTML = '<div class="panel empty-state">No matching vulnerable CVEs were found for watched products yet.</div>';
    return;
  }

  grid.innerHTML = data.watched_feed.map(watchedFeedCard).join("");
}

function renderWatchedProductsSection(data) {
  const count = document.getElementById("watchedProductsCount");
  const watched = document.getElementById("watchedProductsList");
  const products = data.watched_products || [];

  count.textContent = `${products.length} products`;

  if (!products.length) {
    watched.innerHTML = '<div class="empty-state">No watched products yet.</div>';
    return;
  }

  watched.innerHTML = products.map(watchedProductCard).join("");
  watched.querySelectorAll("[data-unwatch-product-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const productId = Number(button.dataset.unwatchProductId || 0);
      removeWatchedProduct(productId).catch((error) => {
        showToast(error.message || String(error), "error");
      });
    });
  });
}

async function loadWatchedProducts() {
  const data = await fetchJson("/api/watched-products/feed");
  renderWatchedFeedSection(data);
  renderWatchedProductsSection(data);

  if ((data.watched_products || []).length) {
    markWatchedProductsViewed().catch(() => {});
  }
}

window.addEventListener("DOMContentLoaded", () => {
  loadWatchedProducts().catch((error) => {
    const message = escapeHtml(error.message || String(error));
    document.getElementById("watchedFeed").innerHTML = `<div class="panel empty-state">${message}</div>`;
    document.getElementById("watchedProductsList").innerHTML = `<div class="empty-state">${message}</div>`;
  });
});
