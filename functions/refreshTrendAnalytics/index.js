const { Pool } = require("pg");

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

function parsePositiveInteger(value, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(Math.floor(numeric), 1);
}

function recentWindowPredicate(columnSql, placeholderIndex) {
  return `
    ${columnSql} >= NOW() - ($${placeholderIndex}::int * INTERVAL '1 day')
    AND ${columnSql} <= NOW()
  `;
}

exports.refreshTrendAnalytics = async (req, res) => {
  const windowDays = parsePositiveInteger(req.body?.days || req.query.days || process.env.DEFAULT_SYNC_WINDOW_DAYS || 30, 30);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

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
      WHERE ${recentWindowPredicate("published_at", 1)}
      GROUP BY published_at::date, COALESCE(severity, 'UNKNOWN')
    `, [windowDays]);

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
      WHERE ${recentWindowPredicate("c.published_at", 1)}
      GROUP BY c.year, v.name, COALESCE(c.severity, 'UNKNOWN')
    `, [windowDays]);

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
      WHERE ${recentWindowPredicate("published_at", 1)}
    `, [windowDays]);

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
      WHERE ${recentWindowPredicate("c.published_at", 1)}
    `, [windowDays]);

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
      WHERE ${recentWindowPredicate("c.published_at", 1)}
    `, [windowDays]);

    await client.query("COMMIT");
    res.json({ ok: true, window_days: windowDays });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
};
