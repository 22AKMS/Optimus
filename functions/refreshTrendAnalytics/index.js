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

const lookerOverviewViewSql = `
  CREATE VIEW looker_cve_overview AS
  SELECT
    c.id AS cve_id,
    c.published_at,
    c.published_at::date AS published_date,
    c.last_modified_at,
    c.last_modified_at::date AS last_modified_date,
    c.year,
    COALESCE(c.severity, 'UNKNOWN') AS severity,
    c.cvss_base_score,
    c.trending_score,
    c.has_kev,
    c.cwe_id,
    c.cwe_name,
    COALESCE(primary_match.vendor_name, 'Unknown') AS primary_vendor,
    COALESCE(primary_match.product_name, 'Unknown') AS primary_product,
    (c.product_count > 0) AS has_mapped_products,
    c.reference_count,
    c.product_count,
    1::integer AS cve_count,
    CASE WHEN COALESCE(c.severity, 'UNKNOWN') = 'CRITICAL' THEN 1 ELSE 0 END::integer AS critical_cve_count,
    CASE WHEN COALESCE(c.severity, 'UNKNOWN') = 'HIGH' THEN 1 ELSE 0 END::integer AS high_cve_count,
    CASE WHEN c.has_kev THEN 1 ELSE 0 END::integer AS known_exploit_count,
    CASE WHEN c.product_count > 0 THEN 1 ELSE 0 END::integer AS mapped_product_cve_count,
    1::integer AS total_cves,
    CASE WHEN COALESCE(c.severity, 'UNKNOWN') = 'CRITICAL' THEN 1 ELSE 0 END::integer AS total_critical_cves,
    CASE WHEN COALESCE(c.severity, 'UNKNOWN') = 'HIGH' THEN 1 ELSE 0 END::integer AS total_high_cves,
    CASE WHEN c.has_kev THEN 1 ELSE 0 END::integer AS total_known_exploits,
    CASE WHEN c.product_count > 0 THEN 1 ELSE 0 END::integer AS total_mapped_products,
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
`;

async function rebuildLookerOverviewView(client) {
  await client.query(`
    DO $$
    DECLARE rec record;
    BEGIN
      FOR rec IN
        SELECT c.relname, c.relkind
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname IN (
            'looker_cve_overview',
            'looker_daily_severity',
            'looker_vendor_year',
            'looker_summary_metrics',
            'looker_cve_explorer'
          )
          AND c.relkind IN ('r', 'p', 'v', 'm')
      LOOP
        EXECUTE format(
          'DROP %s IF EXISTS public.%I CASCADE',
          CASE
            WHEN rec.relkind = 'm' THEN 'MATERIALIZED VIEW'
            WHEN rec.relkind = 'v' THEN 'VIEW'
            ELSE 'TABLE'
          END,
          rec.relname
        );
      END LOOP;
    END $$
  `);
  await client.query(lookerOverviewViewSql);
  await client.query(`
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'looker_reader') THEN
        GRANT SELECT ON public.looker_cve_overview TO looker_reader;
      END IF;
    END $$
  `);

  const countResult = await client.query(`
    SELECT
      (SELECT COUNT(*)::int FROM cves) AS source_count,
      (SELECT COUNT(*)::int FROM looker_cve_overview) AS overview_count
  `);
  const counts = countResult.rows[0] || {};
  if (Number(counts.source_count || 0) !== Number(counts.overview_count || 0)) {
    throw new Error(`looker_cve_overview count mismatch: source=${counts.source_count}, overview=${counts.overview_count}`);
  }
  return counts;
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

    const lookerCounts = await rebuildLookerOverviewView(client);

    await client.query("COMMIT");
    res.json({ ok: true, window_days: windowDays, looker_counts: lookerCounts });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
};
