# CVE Analyzer

A Google Cloud web application that ingests CVE records from the National Vulnerability Database (NVD), stores normalized vulnerability data in Cloud SQL for PostgreSQL, stores per-user saved state in Firestore, and exposes Looker Studio-friendly views for trend dashboards.

## What this app does

- Pulls CVE data from the NVD CVE API into PostgreSQL.
- Lets users browse the newest CVEs.
- Lets users filter by severity, year, keyword, vendor, and product.
- Shows the highest-severity CVEs in a right-side panel.
- Shows a detailed page for each CVE with metrics, affected software, references, and related CVEs.
- Stores saved CVEs and watched products in Firestore.
- Builds summary tables and views that can be connected directly to Looker Studio.

## Google Cloud pieces

- **Cloud Run**: Express web app.
- **Cloud SQL for PostgreSQL**: relational storage for CVEs, products, references, and analytics tables.
- **Firestore**: saved CVEs and watched products per user.
- **Cloud Functions (Gen2)**:
  - `syncRecentCves`: incremental NVD ingestion.
  - `refreshTrendAnalytics`: recompute trending scores and analytics summary tables.
- **Looker Studio**: connect to PostgreSQL views for dashboards.

## Data model

### PostgreSQL

- `vendors`
- `products`
- `cves`
- `cve_products`
- `cve_references`
- `ingest_runs`
- `analytics_daily_severity`
- `analytics_vendor_year`

### Firestore

- `users/{userId}/saved_cves/{cveId}`
- `users/{userId}/watched_products/{productId}`

## Main routes

- `GET /` – homepage
- `GET /cves/:cveId` – CVE detail page
- `GET /api/cves` – filtered CVE list
- `GET /api/cves/:cveId` – CVE details JSON
- `GET /api/high-severity` – highest severity sidebar data
- `GET /api/analytics/overview` – homepage stats
- `POST /api/cves/:cveId/saved`
- `DELETE /api/cves/:cveId/saved`
- `POST /api/cves/:cveId/watch-product`
- `DELETE /api/cves/:cveId/watch-product/:productId`

## Looker Studio setup

This app creates PostgreSQL views you can point Looker Studio at:

- `looker_cve_overview`
- `looker_daily_severity`
- `looker_vendor_year`

Suggested charts:

1. **Time series** on `looker_daily_severity`
   - Dimension: `published_date`
   - Breakdown: `severity`
   - Metric: `cve_count`
2. **Bar chart** on `looker_vendor_year`
   - Dimension: `vendor_name`
   - Metric: `cve_count`
   - Filter: `year = current year`
3. **Table** on `looker_cve_overview`
   - Columns: `cve_id`, `severity`, `cvss_base_score`, `primary_vendor`, `primary_product`, `published_date`
   - Sort by `published_date DESC`

Looker Studio can connect directly to PostgreSQL tables and views, so you can point it at the Cloud SQL database without adding BigQuery.

## Local development

1. Copy `.env.example` to `.env`.
2. Fill in PostgreSQL and Firestore values.
3. Run `npm install`.
4. Apply `db/schema-postgres.sql`.
5. Seed live NVD data with:
   - `npm run seed`
6. Rebuild analytics:
   - `npm run refresh-analytics`
7. Start the app:
   - `npm start`

## Google Cloud deployment

Use `install_gcloud.sh` from the project root. It creates:

- Firestore database
- Cloud SQL instance/database/user
- schema and initial sync
- Cloud Run service
- the two Cloud Functions

## Notes

- The app uses a single demo user by default via `APP_USER_ID`.
- This is suitable for a course project demo. For production, add real auth, Secret Manager, and tighter access control on Cloud Run and Cloud Functions.
- The app includes the NVD attribution notice required by the NVD developer documentation.
