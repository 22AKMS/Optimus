const path = require("path");
const dotenv = require("dotenv");

dotenv.config({ path: path.join(__dirname, "..", ".env") });

const { pool } = require("../lib/db");
const { refreshAnalyticsTables } = require("../lib/analytics");

const API_BASE = process.env.NVD_API_BASE || "https://services.nvd.nist.gov/rest/json/cves/2.0";
const API_KEY = process.env.NVD_API_KEY || "";

function parseArgs(argv) {
  const args = {};
  for (const entry of argv) {
    if (!entry.startsWith("--")) continue;
    const [rawKey, rawValue] = entry.slice(2).split("=");
    args[rawKey] = rawValue === undefined ? true : rawValue;
  }
  return args;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function firstEnglishDescription(descriptions = []) {
  return descriptions.find((item) => item.lang === "en")?.value || descriptions[0]?.value || "No description provided.";
}

function firstMetric(metrics = {}) {
  const groups = [metrics.cvssMetricV40, metrics.cvssMetricV31, metrics.cvssMetricV30, metrics.cvssMetricV2];
  for (const group of groups) {
    if (!Array.isArray(group) || !group.length) continue;
    return group.find((item) => String(item.type || "").toLowerCase() === "primary") || group[0];
  }
  return null;
}

function firstWeakness(weaknesses = []) {
  for (const weakness of weaknesses) {
    for (const description of weakness.description || []) {
      if (description.lang === "en" && description.value) {
        return description.value;
      }
    }
  }
  return null;
}

function collectCpeMatches(input, bucket = []) {
  if (!input) return bucket;
  if (Array.isArray(input)) {
    for (const item of input) {
      collectCpeMatches(item, bucket);
    }
    return bucket;
  }
  if (typeof input !== "object") {
    return bucket;
  }

  const criteria = input.criteria || input.cpe23Uri || "";
  if (criteria) {
    bucket.push(input);
  }

  for (const value of Object.values(input)) {
    if (value && typeof value === "object") {
      collectCpeMatches(value, bucket);
    }
  }
  return bucket;
}

function cleanCpePart(value, fallback) {
  const cleaned = String(value || "").trim().replace(/_/g, " ");
  if (!cleaned || cleaned === "*" || cleaned === "-") return fallback;
  return cleaned;
}

function parseCpeParts(cpeUri) {
  const parts = String(cpeUri || "").split(":");
  return {
    vendor: cleanCpePart(parts[3], "Unknown vendor"),
    product: cleanCpePart(parts[4], "Unknown product")
  };
}

function normalizeSeverity(value, score) {
  const direct = String(value || "").trim().toUpperCase();
  if (direct) return direct;
  if (score === null || score === undefined || Number.isNaN(Number(score))) return null;
  const numeric = Number(score);
  if (numeric >= 9.0) return "CRITICAL";
  if (numeric >= 7.0) return "HIGH";
  if (numeric >= 4.0) return "MEDIUM";
  if (numeric > 0) return "LOW";
  if (numeric === 0) return "NONE";
  return null;
}

function parseCveRecord(wrapper) {
  const cve = wrapper.cve || wrapper;
  const metric = firstMetric(cve.metrics || {});
  const cvssData = metric?.cvssData || {};
  const weaknessName = firstWeakness(cve.weaknesses || []);
  const weaknessIdMatch = String(weaknessName || "").match(/CWE-\d+/i);
  const cpeMatches = collectCpeMatches(cve.configurations || []);
  const productMap = new Map();

  for (const match of cpeMatches) {
    const vulnerable = match.vulnerable !== false;
    const cpeUri = match.criteria || match.cpe23Uri || "";
    if (!vulnerable || !cpeUri) continue;
    const parts = parseCpeParts(cpeUri);
    const key = `${parts.vendor}::${parts.product}::${cpeUri}`;
    if (!productMap.has(key)) {
      productMap.set(key, {
        vendor_name: parts.vendor,
        product_name: parts.product,
        cpe_uri: cpeUri,
        match_criteria_id: match.matchCriteriaId || null,
        version_start_including: match.versionStartIncluding || null,
        version_start_excluding: match.versionStartExcluding || null,
        version_end_including: match.versionEndIncluding || null,
        version_end_excluding: match.versionEndExcluding || null,
        is_vulnerable: true
      });
    }
  }

  const references = [];
  for (const ref of cve.references || []) {
    if (!ref.url) continue;
    references.push({
      url: ref.url,
      source: ref.source || null,
      tags: Array.isArray(ref.tags) ? ref.tags : []
    });
  }

  const score = cvssData.baseScore ?? null;
  const severity = normalizeSeverity(metric?.baseSeverity || cvssData.baseSeverity || wrapper.cve?.metrics?.cvssMetricV2?.[0]?.baseSeverity, score);
  const publishedAt = cve.published || new Date().toISOString();

  return {
    id: cve.id,
    source_identifier: cve.sourceIdentifier || null,
    published_at: publishedAt,
    last_modified_at: cve.lastModified || publishedAt,
    vuln_status: cve.vulnStatus || null,
    description: firstEnglishDescription(cve.descriptions || []),
    cvss_version: cvssData.version || null,
    cvss_base_score: score,
    severity,
    attack_vector: cvssData.attackVector || null,
    attack_complexity: cvssData.attackComplexity || null,
    privileges_required: cvssData.privilegesRequired || null,
    user_interaction: cvssData.userInteraction || null,
    scope: cvssData.scope || null,
    confidentiality_impact: cvssData.confidentialityImpact || null,
    integrity_impact: cvssData.integrityImpact || null,
    availability_impact: cvssData.availabilityImpact || null,
    exploitability_score: metric?.exploitabilityScore ?? null,
    impact_score: metric?.impactScore ?? null,
    cwe_id: weaknessIdMatch ? weaknessIdMatch[0].toUpperCase() : null,
    cwe_name: weaknessName,
    has_kev: Boolean(cve.cisaExploitAdd),
    year: new Date(publishedAt).getUTCFullYear(),
    raw_json: cve,
    products: Array.from(productMap.values()),
    references
  };
}
function buildWindowParams({ windowType, startIso, endIso }) {
  if (windowType === "modified") {
    return {
      startKey: "lastModStartDate",
      endKey: "lastModEndDate"
    };
  }

  return {
    startKey: "pubStartDate",
    endKey: "pubEndDate"
  };
}

async function fetchPage({ headers, windowType, startIso, endIso, startIndex = 0, resultsPerPage = null }) {
  const url = new URL(API_BASE);
  const keys = buildWindowParams({ windowType, startIso, endIso });
  url.searchParams.set(keys.startKey, startIso);
  url.searchParams.set(keys.endKey, endIso);
  url.searchParams.set("startIndex", String(startIndex));
  if (resultsPerPage) {
    url.searchParams.set("resultsPerPage", String(resultsPerPage));
  }

  const response = await fetch(url, { headers });
  if (!response.ok) {
    const payload = await response.text();
    throw new Error(`NVD request failed (${response.status}): ${payload}`);
  }

  return response.json();
}

async function fetchWindow({ startIso, endIso, windowType = "published", maxRecords = 300, maxPages = 10, delayMs = 6500 }) {
  const headers = { "Accept": "application/json" };
  if (API_KEY) {
    headers.apiKey = API_KEY;
  }

  const firstPayload = await fetchPage({ headers, windowType, startIso, endIso, startIndex: 0 });
  const firstVulnerabilities = Array.isArray(firstPayload.vulnerabilities) ? firstPayload.vulnerabilities : [];
  const pageSize = Number(firstPayload.resultsPerPage || firstVulnerabilities.length || 0) || 1;
  const totalResults = Number(firstPayload.totalResults || firstVulnerabilities.length || 0);
  const allRecords = [];
  let page = 0;
  let startIndex = totalResults > 0 ? Math.floor((Math.max(totalResults, 1) - 1) / pageSize) * pageSize : 0;

  while (page < maxPages && allRecords.length < maxRecords) {
    const payload = startIndex === 0 ? firstPayload : await fetchPage({ headers, windowType, startIso, endIso, startIndex, resultsPerPage: pageSize });
    const vulnerabilities = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : [];

    for (const item of vulnerabilities.slice().reverse()) {
      if (allRecords.length >= maxRecords) {
        break;
      }
      allRecords.push(parseCveRecord(item));
    }

    page += 1;
    if (!vulnerabilities.length || startIndex === 0 || allRecords.length >= maxRecords) {
      break;
    }

    startIndex = Math.max(0, startIndex - pageSize);
    await sleep(delayMs);
  }

  return allRecords;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const now = new Date();
  const requestedDays = Number(args.days || 30);
  const days = Math.min(Math.max(requestedDays, 1), 30);
  const endIso = args['end-date'] || now.toISOString();
  const startIso = args['start-date'] || new Date(now.getTime() - (days * 24 * 60 * 60 * 1000)).toISOString();
  const windowType = String(args['window-type'] || process.env.DEFAULT_SYNC_WINDOW_TYPE || 'published').trim().toLowerCase() === 'modified' ? 'modified' : 'published';
  const rawMaxRecords = Number(args['max-records'] ?? 300);
  const maxRecords = rawMaxRecords === 0 ? Number.POSITIVE_INFINITY : rawMaxRecords;
  const maxPages = rawMaxRecords === 0 ? Number.POSITIVE_INFINITY : Number(args['max-pages'] || 10);
  const delayMs = Math.max(Number(args['delay-ms'] || 6500), 6000);

  const runStart = await pool.query(`
    INSERT INTO ingest_runs (status, note)
    VALUES ('running', $1)
    RETURNING id
  `, [`Syncing NVD CVEs using ${windowType} window from ${startIso} to ${endIso}`]);
  const runId = runStart.rows[0].id;

  try {
    const records = await fetchWindow({ startIso, endIso, windowType, maxRecords, maxPages, delayMs });
    const client = await pool.connect();
    try {
      for (const record of records) {
        await client.query("BEGIN");
        try {
          await upsertCveRecord(client, record);
          await client.query("COMMIT");
        } catch (error) {
          await client.query("ROLLBACK");
          throw error;
        }
      }
    } finally {
      client.release();
    }

    await refreshAnalyticsTables();

    await pool.query(`
      UPDATE ingest_runs
      SET finished_at = NOW(), status = 'success', cve_count = $2, note = $3
      WHERE id = $1
    `, [runId, records.length, `Synced ${records.length} CVEs using ${windowType} window.`]);

    console.log(`Synced ${records.length} CVEs using ${windowType} window from ${startIso} to ${endIso}.`);
  } catch (error) {
    await pool.query(`
      UPDATE ingest_runs
      SET finished_at = NOW(), status = 'failed', note = $2
      WHERE id = $1
    `, [runId, error.message]);
    throw error;
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
