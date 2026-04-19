const path = require("path");
const express = require("express");
const dotenv = require("dotenv");

dotenv.config({ path: path.join(__dirname, ".env") });

const { query, serializeCve, getCveById, severityOrderSql, normalizedSeveritySql } = require("./lib/db");
const { UserStateStore } = require("./lib/firestoreStore");

const app = express();
const port = Number(process.env.PORT || 8080);
const defaultUserId = process.env.APP_USER_ID || "demo-user";
const appName = process.env.APP_NAME || "Optimus - A CVE Analysis Optimizer";
const sourceNotice = process.env.SOURCE_NOTICE || "This product uses data from the NVD API but is not endorsed or certified by the NVD.";
const sharedLookerStudioUrl = String(process.env.SHARED_LOOKER_STUDIO_URL || "").trim();
const store = new UserStateStore();
const MS_PER_DAY = 24 * 60 * 60 * 1000;

function parseSyncWindowDays(run) {
  const note = String(run?.note || "").trim();
  if (!note) return null;

  const match = note.match(/from\s+(\S+)\s+to\s+(\S+)/i);
  if (!match) return null;

  const start = Date.parse(match[1]);
  const end = Date.parse(match[2]);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    return null;
  }

  return Math.max(1, Math.round((end - start) / MS_PER_DAY));
}

function viewContext(extra = {}) {
  return {
    appUserId: defaultUserId,
    appName,
    sourceNotice,
    sharedLookerStudioUrl,
    ...extra
  };
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.json());
app.use("/static", express.static(path.join(__dirname, "public")));

app.get("/healthz", async (req, res) => {
  try {
    await query("SELECT 1");
    res.json({ ok: true, app: appName });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get("/", (req, res) => {
  res.render("index", viewContext());
});

app.get("/watchlist", (req, res) => {
  res.render("watchlist", viewContext());
});

app.get("/cves/:cveId", (req, res) => {
  res.render("cve", viewContext({
    cveId: String(req.params.cveId || "").trim().toUpperCase()
  }));
});

app.get("/api/analytics/overview", async (req, res) => {
  try {
    const [latestRunResult, latestSuccessfulRunResult] = await Promise.all([
      query(`
        SELECT started_at, finished_at, status, cve_count, note
        FROM ingest_runs
        ORDER BY started_at DESC
        LIMIT 1
      `),
      query(`
        SELECT started_at, finished_at, status, cve_count, note
        FROM ingest_runs
        WHERE status = 'success'
        ORDER BY started_at DESC
        LIMIT 1
      `)
    ]);

    const latestRun = latestRunResult.rows[0] || null;
    const latestSuccessfulRun = latestSuccessfulRunResult.rows[0] || null;
    const fallbackWindowDays = Number(process.env.DEFAULT_SYNC_WINDOW_DAYS || 30);
    const syncWindowDays = Math.min(
      Math.max(parseSyncWindowDays(latestSuccessfulRun || latestRun) || fallbackWindowDays, 1),
      3650
    );
    const severityExpr = normalizedSeveritySql("severity", "cvss_base_score");

    const overviewResult = await query(`
      SELECT
        COUNT(*)::int AS total_cves,
        COUNT(*) FILTER (WHERE ${severityExpr} = 'CRITICAL')::int AS critical_cves,
        COUNT(*) FILTER (WHERE ${severityExpr} = 'HIGH')::int AS high_cves,
        COUNT(*) FILTER (WHERE published_at >= NOW() - ($1::int * INTERVAL '1 day'))::int AS recent_cves,
        COUNT(*) FILTER (WHERE has_kev)::int AS kev_cves,
        COUNT(*) FILTER (WHERE product_count > 0)::int AS normalized_cves,
        MIN(published_at) AS oldest_published_at,
        MAX(last_modified_at) AS latest_modified_at
      FROM cves
    `, [syncWindowDays]);

    res.json({
      overview: overviewResult.rows[0],
      latest_run: latestRun,
      sync_window_days: syncWindowDays
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/cves", async (req, res) => {
  try {
    const search = String(req.query.search || "").trim();
    const severity = String(req.query.severity || "").trim().toUpperCase();
    const product = String(req.query.product || "").trim();
    const normalizedOnly = ["1", "true", "yes", "on"].includes(String(req.query.normalized_only || "").trim().toLowerCase());
    const yearRaw = String(req.query.year || "").trim();
    const sort = String(req.query.sort || "newest").trim();
    const sortDirection = String(req.query.direction || "desc").trim().toLowerCase() === "asc" ? "asc" : "desc";
    const limit = Math.min(Math.max(Number(req.query.limit || 40), 1), 100);
    const page = Math.max(Number(req.query.page || 1), 1);
    const offset = (page - 1) * limit;

    const clauses = [];
    const params = [];
    let i = 1;
    const severityExpr = normalizedSeveritySql("c.severity", "c.cvss_base_score");

    if (search) {
      clauses.push(`(
        c.id ILIKE $${i}
        OR c.description ILIKE $${i}
        OR COALESCE(c.cwe_id, '') ILIKE $${i}
        OR COALESCE(c.cwe_name, '') ILIKE $${i}
        OR EXISTS (
          SELECT 1
          FROM cve_products cp
          JOIN products p ON p.id = cp.product_id
          JOIN vendors v ON v.id = p.vendor_id
          WHERE cp.cve_id = c.id
            AND (p.name ILIKE $${i} OR v.name ILIKE $${i})
        )
      )`);
      params.push(`%${search}%`);
      i += 1;
    }

    if (severity) {
      clauses.push(`${severityExpr} = $${i}`);
      params.push(severity);
      i += 1;
    }

    const parsedYear = Number(yearRaw);
    if (yearRaw && Number.isInteger(parsedYear)) {
      clauses.push(`c.year = $${i}`);
      params.push(parsedYear);
      i += 1;
    }

    if (product) {
      clauses.push(`EXISTS (
        SELECT 1
        FROM cve_products cp
        JOIN products p ON p.id = cp.product_id
        JOIN vendors v ON v.id = p.vendor_id
        WHERE cp.cve_id = c.id
          AND (p.name ILIKE $${i} OR v.name ILIKE $${i})
      )`);
      params.push(`%${product}%`);
      i += 1;
    }

    if (normalizedOnly) {
      clauses.push(`c.product_count > 0`);
    }

    const orderByTemplates = {
      newest: {
        desc: "c.published_at DESC, c.cvss_base_score DESC NULLS LAST, c.id DESC",
        asc: "c.published_at ASC, c.cvss_base_score ASC NULLS FIRST, c.id ASC"
      },
      severity: {
        desc: `${severityOrderSql("c.severity", "c.cvss_base_score")} DESC, c.cvss_base_score DESC NULLS LAST, c.published_at DESC`,
        asc: `${severityOrderSql("c.severity", "c.cvss_base_score")} ASC, c.cvss_base_score ASC NULLS FIRST, c.published_at ASC`
      },
      modified: {
        desc: "c.last_modified_at DESC, c.published_at DESC, c.id DESC",
        asc: "c.last_modified_at ASC, c.published_at ASC, c.id ASC"
      },
      trending: {
        desc: "c.trending_score DESC, c.cvss_base_score DESC NULLS LAST, c.published_at DESC",
        asc: "c.trending_score ASC, c.cvss_base_score ASC NULLS FIRST, c.published_at ASC"
      }
    };

    const orderConfig = orderByTemplates[sort] || orderByTemplates.newest;
    const orderBy = orderConfig[sortDirection];
    const whereSql = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";

    const countResult = await query(`
      SELECT COUNT(*)::int AS total
      FROM cves c
      ${whereSql}
    `, params);
    const totalItems = Number(countResult.rows[0]?.total || 0);
    const pageCount = Math.max(Math.ceil(totalItems / limit), 1);
    const safePage = Math.min(page, pageCount);
    const safeOffset = (safePage - 1) * limit;

    const itemParams = [...params, limit, safeOffset];
    const itemsResult = await query(`
      SELECT
        c.*,
        ${severityExpr} AS display_severity,
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
      ${whereSql}
      ORDER BY ${orderBy}
      LIMIT $${itemParams.length - 1}
      OFFSET $${itemParams.length}
    `, itemParams);

    const yearsResult = await query(`
      SELECT DISTINCT year
      FROM cves
      ORDER BY year DESC
      LIMIT 20
    `);

    const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];

    res.json({
      items: itemsResult.rows.map(serializeCve),
      years: yearsResult.rows.map((row) => Number(row.year)).filter(Boolean),
      severities,
      pagination: {
        page: safePage,
        limit,
        page_count: pageCount,
        total_items: totalItems,
        has_prev: safePage > 1,
        has_next: safePage < pageCount
      },
      sort,
      direction: sortDirection
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/high-severity", async (req, res) => {
  try {
    const result = await query(`
      SELECT
        c.*,
        ${normalizedSeveritySql("c.severity", "c.cvss_base_score")} AS display_severity,
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
      ORDER BY ${severityOrderSql("c.severity", "c.cvss_base_score")} DESC, c.cvss_base_score DESC NULLS LAST, c.published_at DESC
      LIMIT 8
    `);

    res.json({ items: result.rows.map(serializeCve) });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/watchlist", async (req, res) => {
  try {
    const savedIds = await store.getSavedCves(defaultUserId);
    const watchedProducts = await store.getWatchedProducts(defaultUserId);

    if (!savedIds.length) {
      return res.json({ items: [], watched_products: watchedProducts, count: 0 });
    }

    const placeholders = savedIds.map((_, index) => `$${index + 1}`).join(", ");
    const result = await query(`
      SELECT
        c.*,
        ${normalizedSeveritySql("c.severity", "c.cvss_base_score")} AS display_severity,
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
      WHERE c.id IN (${placeholders})
      ORDER BY c.published_at DESC, c.cvss_base_score DESC NULLS LAST, c.id DESC
    `, savedIds);

    res.json({
      items: result.rows.map(serializeCve),
      watched_products: watchedProducts,
      count: result.rows.length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/cves/:cveId", async (req, res) => {
  try {
    const cveId = String(req.params.cveId || "").trim().toUpperCase();
    const row = await getCveById(cveId);

    if (!row) {
      return res.status(404).json({ error: "CVE not found" });
    }

    const [productsResult, referencesResult, relatedResult, savedCves, watchedProducts] = await Promise.all([
      query(`
        SELECT
          p.id AS product_id,
          p.name AS product_name,
          v.name AS vendor_name,
          p.cpe_uri AS canonical_cpe_uri,
          cp.cpe_uri,
          cp.version_start_including,
          cp.version_start_excluding,
          cp.version_end_including,
          cp.version_end_excluding,
          cp.is_vulnerable
        FROM cve_products cp
        JOIN products p ON p.id = cp.product_id
        JOIN vendors v ON v.id = p.vendor_id
        WHERE cp.cve_id = $1
        ORDER BY v.name ASC, p.name ASC
        LIMIT 50
      `, [cveId]),
      query(`
        SELECT url, source, tags
        FROM cve_references
        WHERE cve_id = $1
        ORDER BY id ASC
        LIMIT 50
      `, [cveId]),
      query(`
        SELECT
          c.*, 
          ${normalizedSeveritySql("c.severity", "c.cvss_base_score")} AS display_severity,
          primary_match.vendor_name AS primary_vendor,
          primary_match.product_name AS primary_product,
          primary_match.product_id AS primary_product_id
        FROM cves c
        LEFT JOIN LATERAL (
          SELECT v.name AS vendor_name, p.name AS product_name, p.id AS product_id
          FROM cve_products cp
          JOIN products p ON p.id = cp.product_id
          JOIN vendors v ON v.id = p.vendor_id
          WHERE cp.cve_id = c.id
          ORDER BY v.name ASC, p.name ASC
          LIMIT 1
        ) primary_match ON TRUE
        WHERE c.id <> $1
          AND (
            ($2 <> '' AND c.cwe_id = $2)
            OR EXISTS (
              SELECT 1
              FROM cve_products cp_self
              JOIN cve_products cp_other ON cp_other.product_id = cp_self.product_id
              WHERE cp_self.cve_id = $1
                AND cp_other.cve_id = c.id
            )
          )
        ORDER BY c.trending_score DESC, c.cvss_base_score DESC NULLS LAST, c.published_at DESC
        LIMIT 5
      `, [cveId, row.cwe_id || ""]),
      store.getSavedCves(defaultUserId),
      store.getWatchedProducts(defaultUserId)
    ]);

    const watchedIds = new Set(watchedProducts.map((item) => Number(item.product_id)));
    const serialized = serializeCve(row);

    res.json({
      ...serialized,
      products: productsResult.rows.map((product) => ({
        product_id: Number(product.product_id),
        product_name: product.product_name,
        vendor_name: product.vendor_name,
        canonical_cpe_uri: product.canonical_cpe_uri,
        cpe_uri: product.cpe_uri,
        version_start_including: product.version_start_including,
        version_start_excluding: product.version_start_excluding,
        version_end_including: product.version_end_including,
        version_end_excluding: product.version_end_excluding,
        is_vulnerable: Boolean(product.is_vulnerable)
      })),
      references: referencesResult.rows,
      related_cves: relatedResult.rows.map(serializeCve),
      saved: savedCves.includes(cveId),
      primary_product_watched: serialized.primary_product_id ? watchedIds.has(serialized.primary_product_id) : false
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/cves/:cveId/saved", async (req, res) => {
  try {
    const cveId = String(req.params.cveId || "").trim().toUpperCase();
    const exists = await query("SELECT id FROM cves WHERE id = $1", [cveId]);
    if (!exists.rows[0]) {
      return res.status(404).json({ error: "CVE not found" });
    }

    await store.addSavedCve(defaultUserId, cveId);
    res.json({ ok: true, cve_id: cveId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/cves/:cveId/saved", async (req, res) => {
  try {
    const cveId = String(req.params.cveId || "").trim().toUpperCase();
    await store.removeSavedCve(defaultUserId, cveId);
    res.json({ ok: true, cve_id: cveId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/cves/:cveId/watch-product", async (req, res) => {
  try {
    const cveId = String(req.params.cveId || "").trim().toUpperCase();
    const productId = Number(req.body?.product_id || 0);

    const cveExists = await query("SELECT id FROM cves WHERE id = $1", [cveId]);
    if (!cveExists.rows[0]) {
      return res.status(404).json({ error: "CVE not found" });
    }

    if (!productId) {
      return res.status(400).json({ error: "product_id is required" });
    }

    const productResult = await query(`
      SELECT p.id AS product_id, p.name AS product_name, v.name AS vendor_name
      FROM products p
      JOIN vendors v ON v.id = p.vendor_id
      WHERE p.id = $1
    `, [productId]);

    const product = productResult.rows[0];
    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    await store.addWatchedProduct(defaultUserId, {
      product_id: productId,
      product_name: product.product_name || "",
      vendor_name: product.vendor_name || ""
    });

    res.json({ ok: true, product_id: productId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/cves/:cveId/watch-product/:productId", async (req, res) => {
  try {
    const productId = Number(req.params.productId || 0);
    if (!productId) {
      return res.status(400).json({ error: "product_id is required" });
    }

    await store.removeWatchedProduct(defaultUserId, productId);
    res.json({ ok: true, product_id: productId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`${appName} running on http://localhost:${port}`);
});
