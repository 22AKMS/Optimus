const { pool, severityOrderSql } = require("./db");

async function refreshAnalyticsTables() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    await client.query(`
      UPDATE cves
      SET trending_score = ROUND((
        COALESCE(cvss_base_score, 0) * 10
        + (${severityOrderSql("severity")} * 12)
        + CASE
            WHEN has_kev THEN 18
            ELSE 0
          END
        + GREATEST(0, 30 - LEAST(30, EXTRACT(DAY FROM (NOW() - published_at))))
      )::numeric, 2)
    `);

    await client.query("TRUNCATE analytics_daily_severity");
    await client.query(`
      INSERT INTO analytics_daily_severity (published_date, severity, cve_count, max_cvss, avg_cvss)
      SELECT
        published_at::date AS published_date,
        COALESCE(severity, 'UNKNOWN') AS severity,
        COUNT(*)::int AS cve_count,
        MAX(cvss_base_score) AS max_cvss,
        ROUND(AVG(cvss_base_score)::numeric, 2) AS avg_cvss
      FROM cves
      GROUP BY published_at::date, COALESCE(severity, 'UNKNOWN')
    `);

    await client.query("TRUNCATE analytics_vendor_year");
    await client.query(`
      INSERT INTO analytics_vendor_year (year, vendor_name, severity, cve_count, critical_count, avg_cvss)
      SELECT
        c.year,
        v.name AS vendor_name,
        COALESCE(c.severity, 'UNKNOWN') AS severity,
        COUNT(DISTINCT c.id)::int AS cve_count,
        COUNT(DISTINCT c.id) FILTER (WHERE c.severity = 'CRITICAL')::int AS critical_count,
        ROUND(AVG(c.cvss_base_score)::numeric, 2) AS avg_cvss
      FROM cves c
      JOIN cve_products cp ON cp.cve_id = c.id
      JOIN products p ON p.id = cp.product_id
      JOIN vendors v ON v.id = p.vendor_id
      GROUP BY c.year, v.name, COALESCE(c.severity, 'UNKNOWN')
    `);

    await client.query("COMMIT");
    return { ok: true };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { refreshAnalyticsTables };
