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

exports.refreshTrendAnalytics = async (req, res) => {
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

    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
};
