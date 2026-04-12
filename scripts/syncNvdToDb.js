const path = require("path");
try {
  const dotenv = require("dotenv");
  dotenv.config({ path: path.join(__dirname, "..", ".env") });
} catch (_err) {
  // dotenv is optional here; install_gcloud.sh passes env vars directly.
}

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

async function upsertCveRecord(client, record) {
  await client.query(`
    INSERT INTO cves (
      id, source_identifier, published_at, last_modified_at, vuln_status, description,
      cvss_version, cvss_base_score, severity, attack_vector, attack_complexity,
      privileges_required, user_interaction, scope, confidentiality_impact,
      integrity_impact, availability_impact, exploitability_score, impact_score,
      cwe_id, cwe_name, reference_count, product_count, has_kev, year, raw_json, updated_at
    ) VALUES (
      $1, $2, $3, $4, $5, $6,
      $7, $8, $9, $10, $11,
      $12, $13, $14, $15,
      $16, $17, $18, $19,
      $20, $21, $22, $23, $24, $25, $26::jsonb, NOW()
    )
    ON CONFLICT (id) DO UPDATE SET
      source_identifier = EXCLUDED.source_identifier,
      published_at = EXCLUDED.published_at,
      last_modified_at = EXCLUDED.last_modified_at,
      vuln_status = EXCLUDED.vuln_status,
      description = EXCLUDED.description,
      cvss_version = EXCLUDED.cvss_version,
      cvss_base_score = EXCLUDED.cvss_base_score,
      severity = EXCLUDED.severity,
      attack_vector = EXCLUDED.attack_vector,
      attack_complexity = EXCLUDED.attack_complexity,
      privileges_required = EXCLUDED.privileges_required,
      user_interaction = EXCLUDED.user_interaction,
      scope = EXCLUDED.scope,
      confidentiality_impact = EXCLUDED.confidentiality_impact,
      integrity_impact = EXCLUDED.integrity_impact,
      availability_impact = EXCLUDED.availability_impact,
      exploitability_score = EXCLUDED.exploitability_score,
      impact_score = EXCLUDED.impact_score,
      cwe_id = EXCLUDED.cwe_id,
      cwe_name = EXCLUDED.cwe_name,
      reference_count = EXCLUDED.reference_count,
      product_count = EXCLUDED.product_count,
      has_kev = EXCLUDED.has_kev,
      year = EXCLUDED.year,
      raw_json = EXCLUDED.raw_json,
      updated_at = NOW()
  `, [
    record.id,
    record.source_identifier,
    record.published_at,
    record.last_modified_at,
    record.vuln_status,
    record.description,
    record.cvss_version,
    record.cvss_base_score,
    record.severity,
    record.attack_vector,
    record.attack_complexity,
    record.privileges_required,
    record.user_interaction,
    record.scope,
    record.confidentiality_impact,
    record.integrity_impact,
    record.availability_impact,
    record.exploitability_score,
    record.impact_score,
    record.cwe_id,
    record.cwe_name,
    record.references.length,
    record.products.length,
    record.has_kev,
    record.year,
    JSON.stringify(record.raw_json)
  ]);

  await client.query("DELETE FROM cve_products WHERE cve_id = $1", [record.id]);
  await client.query("DELETE FROM cve_references WHERE cve_id = $1", [record.id]);

  for (const product of record.products) {
    const vendorResult = await client.query(`
      INSERT INTO vendors (name)
      VALUES ($1)
      ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
      RETURNING id
    `, [product.vendor_name]);
    const vendorId = vendorResult.rows[0].id;

    const productResult = await client.query(`
      INSERT INTO products (vendor_id, name, cpe_uri)
      VALUES ($1, $2, $3)
      ON CONFLICT (vendor_id, name) DO UPDATE SET cpe_uri = EXCLUDED.cpe_uri
      RETURNING id
    `, [vendorId, product.product_name, product.cpe_uri]);
    const productId = productResult.rows[0].id;

    await client.query(`
      INSERT INTO cve_products (
        cve_id, product_id, match_criteria_id, cpe_uri,
        version_start_including, version_start_excluding,
        version_end_including, version_end_excluding, is_vulnerable
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (cve_id, product_id) DO UPDATE SET
        match_criteria_id = EXCLUDED.match_criteria_id,
        cpe_uri = EXCLUDED.cpe_uri,
        version_start_including = EXCLUDED.version_start_including,
        version_start_excluding = EXCLUDED.version_start_excluding,
        version_end_including = EXCLUDED.version_end_including,
        version_end_excluding = EXCLUDED.version_end_excluding,
        is_vulnerable = EXCLUDED.is_vulnerable
    `, [
      record.id,
      productId,
      product.match_criteria_id,
      product.cpe_uri,
      product.version_start_including,
      product.version_start_excluding,
      product.version_end_including,
      product.version_end_excluding,
      product.is_vulnerable
    ]);
  }

  for (const ref of record.references) {
    await client.query(`
      INSERT INTO cve_references (cve_id, url, source, tags)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (cve_id, url) DO UPDATE SET source = EXCLUDED.source, tags = EXCLUDED.tags
    `, [record.id, ref.url, ref.source, ref.tags]);
  }

  await client.query(`
    UPDATE cves
    SET
      reference_count = (SELECT COUNT(*) FROM cve_references WHERE cve_id = $1),
      product_count = (SELECT COUNT(*) FROM cve_products WHERE cve_id = $1),
      updated_at = NOW()
    WHERE id = $1
  `, [record.id]);
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
