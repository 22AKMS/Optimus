const { Pool } = require("pg");

const API_BASE = process.env.NVD_API_BASE || "https://services.nvd.nist.gov/rest/json/cves/2.0";
const API_KEY = process.env.NVD_API_KEY || "";
const NVD_RESULTS_PER_PAGE = Math.max(Number(process.env.NVD_RESULTS_PER_PAGE || 2000) || 2000, 1);
const NVD_FETCH_TIMEOUT_MS = Math.max(Number(process.env.NVD_FETCH_TIMEOUT_MS || 120000) || 120000, 1000);
const NVD_MAX_FETCH_RETRIES = Math.max(Number(process.env.NVD_MAX_FETCH_RETRIES || 3) || 3, 1);
const DEFAULT_DELAY_WITH_KEY_MS = Math.max(Number(process.env.NVD_DELAY_WITH_KEY_MS || 750) || 750, 0);
const DEFAULT_DELAY_WITHOUT_KEY_MS = Math.max(Number(process.env.NVD_DELAY_WITHOUT_KEY_MS || 6500) || 6500, 0);
const UPSERT_BATCH_SIZE = Math.max(Number(process.env.CVE_UPSERT_BATCH_SIZE || 50) || 50, 1);

function buildConfig() {
  const host = process.env.DB_HOST || (process.env.INSTANCE_CONNECTION_NAME ? `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}` : "127.0.0.1");
  return {
    host,
    port: Number(process.env.DB_PORT || 5432),
    database: process.env.DB_NAME || "cve_analyzer",
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD || "postgres",
    ssl: false
  };
}

const pool = new Pool(buildConfig());

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parsePositiveInteger(value, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(Math.floor(numeric), 1);
}

function parseNonNegativeInteger(value, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(Math.floor(numeric), 0);
}

function resolveDelayMs(value) {
  const minimum = API_KEY ? DEFAULT_DELAY_WITH_KEY_MS : DEFAULT_DELAY_WITHOUT_KEY_MS;
  if (value === undefined || value === null || value === "") {
    return minimum;
  }
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return minimum;
  }
  return Math.max(Math.floor(numeric), minimum);
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

function isRetryableStatus(status) {
  return status === 429 || status >= 500;
}

function isRetryableFetchError(error) {
  return error?.name === "AbortError"
    || error?.name === "TimeoutError"
    || error?.code === "ECONNRESET"
    || error?.code === "ETIMEDOUT"
    || error?.code === "UND_ERR_CONNECT_TIMEOUT"
    || error?.code === "UND_ERR_HEADERS_TIMEOUT"
    || error?.code === "UND_ERR_BODY_TIMEOUT";
}

function retryDelayMs(attempt) {
  const baseDelay = API_KEY ? 1200 : DEFAULT_DELAY_WITHOUT_KEY_MS;
  return baseDelay * (attempt + 1);
}

async function fetchPage({ headers, windowType, startIso, endIso, startIndex = 0, resultsPerPage = NVD_RESULTS_PER_PAGE }) {
  const url = new URL(API_BASE);
  const keys = buildWindowParams({ windowType, startIso, endIso });
  url.searchParams.set(keys.startKey, startIso);
  url.searchParams.set(keys.endKey, endIso);
  url.searchParams.set("startIndex", String(startIndex));
  url.searchParams.set("resultsPerPage", String(resultsPerPage || NVD_RESULTS_PER_PAGE));

  for (let attempt = 0; attempt < NVD_MAX_FETCH_RETRIES; attempt += 1) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), NVD_FETCH_TIMEOUT_MS);

    try {
      const response = await fetch(url, { headers, signal: controller.signal });
      if (!response.ok) {
        const payload = await response.text();
        if (attempt < NVD_MAX_FETCH_RETRIES - 1 && isRetryableStatus(response.status)) {
          await sleep(retryDelayMs(attempt));
          continue;
        }
        throw new Error(`NVD request failed (${response.status}): ${payload}`);
      }

      return response.json();
    } catch (error) {
      if (attempt < NVD_MAX_FETCH_RETRIES - 1 && isRetryableFetchError(error)) {
        await sleep(retryDelayMs(attempt));
        continue;
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  throw new Error(`NVD request failed after ${NVD_MAX_FETCH_RETRIES} attempts.`);
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

  const referenceMap = new Map();
  for (const ref of cve.references || []) {
    if (!ref.url) continue;
    if (!referenceMap.has(ref.url)) {
      referenceMap.set(ref.url, {
        url: ref.url,
        source: ref.source || null,
        tags: Array.isArray(ref.tags) ? ref.tags : []
      });
    }
  }
  const references = Array.from(referenceMap.values());

  const score = cvssData.baseScore ?? null;
  const severity = normalizeSeverity(metric?.baseSeverity || cvssData.baseSeverity, score);
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
async function refreshAnalytics(client) {
  await client.query(`
    UPDATE cves
    SET trending_score = ROUND((
      COALESCE(cvss_base_score, 0) * 10
      + CASE severity
          WHEN 'CRITICAL' THEN 60
          WHEN 'HIGH' THEN 48
          WHEN 'MEDIUM' THEN 36
          WHEN 'LOW' THEN 24
          WHEN 'NONE' THEN 12
          ELSE 0
        END
      + CASE WHEN has_kev THEN 18 ELSE 0 END
      + GREATEST(0, 30 - LEAST(30, EXTRACT(DAY FROM (NOW() - published_at))))
    )::numeric, 2)
  `);

  await client.query("TRUNCATE analytics_daily_severity");
  await client.query(`
    INSERT INTO analytics_daily_severity (published_date, severity, cve_count, max_cvss, avg_cvss)
    SELECT
      published_at::date,
      COALESCE(severity, 'UNKNOWN'),
      COUNT(*)::int,
      MAX(cvss_base_score),
      ROUND(AVG(cvss_base_score)::numeric, 2)
    FROM cves
    GROUP BY published_at::date, COALESCE(severity, 'UNKNOWN')
  `);

  await client.query("TRUNCATE analytics_vendor_year");
  await client.query(`
    INSERT INTO analytics_vendor_year (year, vendor_name, severity, cve_count, critical_count, avg_cvss)
    SELECT
      c.year,
      v.name,
      COALESCE(c.severity, 'UNKNOWN'),
      COUNT(DISTINCT c.id)::int,
      COUNT(DISTINCT c.id) FILTER (WHERE c.severity = 'CRITICAL')::int,
      ROUND(AVG(c.cvss_base_score)::numeric, 2)
    FROM cves c
    JOIN cve_products cp ON cp.cve_id = c.id
    JOIN products p ON p.id = cp.product_id
    JOIN vendors v ON v.id = p.vendor_id
    GROUP BY c.year, v.name, COALESCE(c.severity, 'UNKNOWN')
  `);

  await client.query("TRUNCATE looker_daily_severity");
  await client.query(`
    INSERT INTO looker_daily_severity (published_date, severity, cve_count, max_cvss, avg_cvss)
    SELECT published_date, severity, cve_count, max_cvss, avg_cvss
    FROM analytics_daily_severity
    `);

  await client.query("TRUNCATE looker_vendor_year");
  await client.query(`
    INSERT INTO looker_vendor_year (year, vendor_name, severity, cve_count, critical_count, avg_cvss)
    SELECT year, vendor_name, severity, cve_count, critical_count, avg_cvss
    FROM analytics_vendor_year
    `);

  await client.query("TRUNCATE looker_summary_metrics");
  await client.query(`
    INSERT INTO looker_summary_metrics (singleton_key, total_cves, critical_cves, normalized_software_cves, average_cvss, latest_publish_date, latest_nvd_update)
    SELECT
      1,
      COUNT(*)::INTEGER,
      SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END)::INTEGER,
      SUM(CASE WHEN product_count > 0 THEN 1 ELSE 0 END)::INTEGER,
      ROUND(AVG(cvss_base_score)::numeric, 2),
      MAX(published_at)::date,
      MAX(last_modified_at)::date
    FROM cves
    `);

  await client.query("TRUNCATE looker_cve_overview");
  await client.query(`
    INSERT INTO looker_cve_overview (
      cve_id, published_date, last_modified_date, year, severity, cvss_base_score, trending_score, has_kev,
      cwe_id, cwe_name, primary_vendor, primary_product, reference_count, product_count, description
    )
    SELECT
      c.id AS cve_id,
      c.published_at::date AS published_date,
      c.last_modified_at::date AS last_modified_date,
      c.year,
      c.severity,
      c.cvss_base_score,
      c.trending_score,
      c.has_kev,
      c.cwe_id,
      c.cwe_name,
      COALESCE(primary_match.vendor_name, 'Unknown') AS primary_vendor,
      COALESCE(primary_match.product_name, 'Unknown') AS primary_product,
      c.reference_count,
      c.product_count,
      c.description
    FROM cves c
    LEFT JOIN LATERAL (
      SELECT v.name AS vendor_name, p.name AS product_name
      FROM cve_products cp
      JOIN products p ON p.id = cp.product_id
      JOIN vendors v ON v.id = p.vendor_id
      WHERE cp.cve_id = c.id
      ORDER BY v.name ASC, p.name ASC
      LIMIT 1
    ) primary_match ON TRUE
    `);

  await client.query("TRUNCATE looker_cve_explorer");
  await client.query(`
    INSERT INTO looker_cve_explorer (
      cve_id, published_at, last_modified_at, year, severity, cvss_base_score, trending_score, has_kev,
      cwe_id, cwe_name, primary_vendor, primary_product, has_normalized_software, product_count, reference_count, description
    )
    SELECT
      c.id AS cve_id,
      c.published_at,
      c.last_modified_at,
      c.year,
      c.severity,
      c.cvss_base_score,
      c.trending_score,
      c.has_kev,
      c.cwe_id,
      c.cwe_name,
      COALESCE(primary_match.vendor_name, 'Unknown') AS primary_vendor,
      COALESCE(primary_match.product_name, 'Unknown') AS primary_product,
      (c.product_count > 0) AS has_normalized_software,
      c.product_count,
      c.reference_count,
      c.description
    FROM cves c
    LEFT JOIN LATERAL (
      SELECT v.name AS vendor_name, p.name AS product_name
      FROM cve_products cp
      JOIN products p ON p.id = cp.product_id
      JOIN vendors v ON v.id = p.vendor_id
      WHERE cp.cve_id = c.id
      ORDER BY v.name ASC, p.name ASC
      LIMIT 1
    ) primary_match ON TRUE
    `);

}

async function getVendorId(client, vendorName, lookupCache) {
  if (lookupCache.vendorIds.has(vendorName)) {
    return lookupCache.vendorIds.get(vendorName);
  }

  const vendorResult = await client.query(`
    INSERT INTO vendors (name)
    VALUES ($1)
    ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
    RETURNING id
  `, [vendorName]);
  const vendorId = vendorResult.rows[0].id;
  lookupCache.vendorIds.set(vendorName, vendorId);
  return vendorId;
}

async function getProductId(client, vendorId, product, lookupCache) {
  const cacheKey = `${vendorId}::${product.product_name}`;
  const cached = lookupCache.productIds.get(cacheKey);
  if (cached && cached.cpeUri === product.cpe_uri) {
    return cached.id;
  }

  const productResult = await client.query(`
    INSERT INTO products (vendor_id, name, cpe_uri)
    VALUES ($1, $2, $3)
    ON CONFLICT (vendor_id, name) DO UPDATE SET cpe_uri = EXCLUDED.cpe_uri
    RETURNING id
  `, [vendorId, product.product_name, product.cpe_uri]);
  const productId = productResult.rows[0].id;
  lookupCache.productIds.set(cacheKey, { id: productId, cpeUri: product.cpe_uri });
  return productId;
}

async function upsertCveRecord(client, record, lookupCache) {
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
    const vendorId = await getVendorId(client, product.vendor_name, lookupCache);
    const productId = await getProductId(client, vendorId, product, lookupCache);

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
}

async function persistRecords(client, records) {
  const lookupCache = {
    vendorIds: new Map(),
    productIds: new Map()
  };

  for (let index = 0; index < records.length; index += UPSERT_BATCH_SIZE) {
    const batch = records.slice(index, index + UPSERT_BATCH_SIZE);
    await client.query("BEGIN");
    try {
      for (const record of batch) {
        await upsertCveRecord(client, record, lookupCache);
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    }
  }
}

exports.syncRecentCves = async (req, res) => {
  const days = parsePositiveInteger(req.body?.days || req.query.days || process.env.DEFAULT_SYNC_WINDOW_DAYS || 7, 7);
  const rawMaxRecords = parseNonNegativeInteger(req.body?.max_records ?? req.query.max_records ?? process.env.DEFAULT_SYNC_MAX_RECORDS ?? 0, 0);
  const unlimitedWindow = rawMaxRecords === 0;
  const maxRecords = unlimitedWindow ? Number.POSITIVE_INFINITY : rawMaxRecords;
  const requestedMaxPages = parsePositiveInteger(req.body?.max_pages || req.query.max_pages || 10, 10);
  const maxPages = unlimitedWindow ? Number.POSITIVE_INFINITY : requestedMaxPages;
  const delayMs = resolveDelayMs(req.body?.delay_ms || req.query.delay_ms);
  const requestedWindowType = String(req.body?.window_type || req.query.window_type || process.env.DEFAULT_SYNC_WINDOW_TYPE || "published").trim().toLowerCase();
  const windowType = requestedWindowType === "modified" ? "modified" : "published";

  const now = new Date();
  const endIso = req.body?.end_date || req.query.end_date || now.toISOString();
  const startIso = req.body?.start_date || req.query.start_date || new Date(now.getTime() - (days * 24 * 60 * 60 * 1000)).toISOString();
  const headers = { "Accept": "application/json" };
  if (API_KEY) headers.apiKey = API_KEY;

  const runResult = await pool.query(`
    INSERT INTO ingest_runs (status, note)
    VALUES ('running', $1)
    RETURNING id
  `, [`Syncing NVD CVEs using ${windowType} window from ${startIso} to ${endIso}${unlimitedWindow ? " (full window)" : ""}`]);
  const runId = runResult.rows[0].id;

  try {
    const firstPayload = await fetchPage({ headers, windowType, startIso, endIso, startIndex: 0, resultsPerPage: NVD_RESULTS_PER_PAGE });
    const firstVulnerabilities = Array.isArray(firstPayload.vulnerabilities) ? firstPayload.vulnerabilities : [];
    const pageSize = Number(firstPayload.resultsPerPage || firstVulnerabilities.length || 1);
    const totalResults = Number(firstPayload.totalResults || firstVulnerabilities.length || 0);
    let startIndex = totalResults > 0 ? Math.floor((Math.max(totalResults, 1) - 1) / pageSize) * pageSize : 0;
    let page = 0;
    const records = [];

    while (page < maxPages && records.length < maxRecords) {
      const payload = startIndex === 0 ? firstPayload : await fetchPage({ headers, windowType, startIso, endIso, startIndex, resultsPerPage: pageSize });
      const vulnerabilities = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : [];

      for (const item of vulnerabilities.slice().reverse()) {
        if (records.length >= maxRecords) break;
        records.push(parseCveRecord(item));
      }

      page += 1;
      if (!vulnerabilities.length || startIndex === 0 || records.length >= maxRecords) {
        break;
      }
      startIndex = Math.max(0, startIndex - pageSize);
      await sleep(delayMs);
    }

    const client = await pool.connect();
    try {
      await persistRecords(client, records);

      await client.query("BEGIN");
      try {
        await refreshAnalytics(client);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    } finally {
      client.release();
    }

    await pool.query(`
      UPDATE ingest_runs
      SET finished_at = NOW(), status = 'success', cve_count = $2, note = $3
      WHERE id = $1
    `, [runId, records.length, `Synced ${records.length} CVEs${unlimitedWindow ? " from the full selected day window" : ""}.`]);

    res.json({ ok: true, synced: records.length, start_date: startIso, end_date: endIso, full_window: unlimitedWindow, days });
  } catch (error) {
    await pool.query(`
      UPDATE ingest_runs
      SET finished_at = NOW(), status = 'failed', note = $2
      WHERE id = $1
    `, [runId, error.message]);
    res.status(500).json({ error: error.message });
  }
};
