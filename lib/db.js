const { Pool } = require("pg");

function getDbConfig() {
  const host = process.env.DB_HOST || (process.env.INSTANCE_CONNECTION_NAME ? `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}` : "127.0.0.1");

  return {
    host,
    port: Number(process.env.DB_PORT || 5432),
    database: process.env.DB_NAME || "cve_analyzer",
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD || "postgres",
    max: 10,
    idleTimeoutMillis: 30000,
    ssl: false
  };
}

const pool = new Pool(getDbConfig());

function severityOrderSql(columnName = "severity") {
  return `CASE ${columnName}
    WHEN 'CRITICAL' THEN 5
    WHEN 'HIGH' THEN 4
    WHEN 'MEDIUM' THEN 3
    WHEN 'LOW' THEN 2
    WHEN 'NONE' THEN 1
    ELSE 0
  END`;
}

async function query(text, params = []) {
  return pool.query(text, params);
}

async function getCveById(cveId) {
  const { rows } = await query(`
    SELECT
      c.*,
      primary_match.vendor_name AS primary_vendor,
      primary_match.product_name AS primary_product,
      primary_match.product_id AS primary_product_id
    FROM cves c
    LEFT JOIN LATERAL (
      SELECT
        v.name AS vendor_name,
        p.name AS product_name,
        p.id AS product_id
      FROM cve_products cp
      JOIN products p ON p.id = cp.product_id
      JOIN vendors v ON v.id = p.vendor_id
      WHERE cp.cve_id = c.id
      ORDER BY v.name ASC, p.name ASC
      LIMIT 1
    ) primary_match ON TRUE
    WHERE c.id = $1
  `, [cveId]);

  return rows[0] || null;
}

function serializeCve(row) {
  return {
    id: row.id,
    source_identifier: row.source_identifier,
    published_at: row.published_at,
    last_modified_at: row.last_modified_at,
    vuln_status: row.vuln_status,
    description: row.description,
    cvss_version: row.cvss_version,
    cvss_base_score: row.cvss_base_score === null ? null : Number(row.cvss_base_score),
    severity: row.severity,
    attack_vector: row.attack_vector,
    attack_complexity: row.attack_complexity,
    privileges_required: row.privileges_required,
    user_interaction: row.user_interaction,
    scope: row.scope,
    confidentiality_impact: row.confidentiality_impact,
    integrity_impact: row.integrity_impact,
    availability_impact: row.availability_impact,
    exploitability_score: row.exploitability_score === null ? null : Number(row.exploitability_score),
    impact_score: row.impact_score === null ? null : Number(row.impact_score),
    cwe_id: row.cwe_id,
    cwe_name: row.cwe_name,
    reference_count: Number(row.reference_count || 0),
    product_count: Number(row.product_count || 0),
    has_kev: Boolean(row.has_kev),
    year: Number(row.year || 0),
    trending_score: row.trending_score === null ? 0 : Number(row.trending_score),
    primary_vendor: row.primary_vendor,
    primary_product: row.primary_product,
    primary_product_id: row.primary_product_id === null || row.primary_product_id === undefined ? null : Number(row.primary_product_id)
  };
}

module.exports = {
  pool,
  query,
  serializeCve,
  getCveById,
  getDbConfig,
  severityOrderSql
};
