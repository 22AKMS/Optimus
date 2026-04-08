CREATE TABLE IF NOT EXISTS vendors (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  vendor_id INTEGER NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  cpe_uri TEXT,
  UNIQUE (vendor_id, name)
);

CREATE TABLE IF NOT EXISTS cves (
  id TEXT PRIMARY KEY,
  source_identifier TEXT,
  published_at TIMESTAMPTZ NOT NULL,
  last_modified_at TIMESTAMPTZ NOT NULL,
  vuln_status TEXT,
  description TEXT NOT NULL,
  cvss_version TEXT,
  cvss_base_score NUMERIC(4,1),
  severity TEXT,
  attack_vector TEXT,
  attack_complexity TEXT,
  privileges_required TEXT,
  user_interaction TEXT,
  scope TEXT,
  confidentiality_impact TEXT,
  integrity_impact TEXT,
  availability_impact TEXT,
  exploitability_score NUMERIC(5,2),
  impact_score NUMERIC(5,2),
  cwe_id TEXT,
  cwe_name TEXT,
  reference_count INTEGER NOT NULL DEFAULT 0,
  product_count INTEGER NOT NULL DEFAULT 0,
  has_kev BOOLEAN NOT NULL DEFAULT FALSE,
  year INTEGER NOT NULL,
  trending_score NUMERIC(8,2) NOT NULL DEFAULT 0,
  raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cve_products (
  cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  match_criteria_id TEXT,
  cpe_uri TEXT,
  version_start_including TEXT,
  version_start_excluding TEXT,
  version_end_including TEXT,
  version_end_excluding TEXT,
  is_vulnerable BOOLEAN NOT NULL DEFAULT TRUE,
  PRIMARY KEY (cve_id, product_id)
);

CREATE TABLE IF NOT EXISTS cve_references (
  id BIGSERIAL PRIMARY KEY,
  cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  source TEXT,
  tags TEXT[] NOT NULL DEFAULT '{}',
  UNIQUE (cve_id, url)
);

CREATE TABLE IF NOT EXISTS ingest_runs (
  id BIGSERIAL PRIMARY KEY,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ,
  status TEXT NOT NULL,
  cve_count INTEGER NOT NULL DEFAULT 0,
  note TEXT
);

CREATE TABLE IF NOT EXISTS analytics_daily_severity (
  published_date DATE NOT NULL,
  severity TEXT NOT NULL,
  cve_count INTEGER NOT NULL,
  max_cvss NUMERIC(4,1),
  avg_cvss NUMERIC(4,2),
  PRIMARY KEY (published_date, severity)
);

CREATE TABLE IF NOT EXISTS analytics_vendor_year (
  year INTEGER NOT NULL,
  vendor_name TEXT NOT NULL,
  severity TEXT NOT NULL,
  cve_count INTEGER NOT NULL,
  critical_count INTEGER NOT NULL,
  avg_cvss NUMERIC(4,2),
  PRIMARY KEY (year, vendor_name, severity)
);

CREATE INDEX IF NOT EXISTS idx_cves_published_at ON cves(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_cves_last_modified_at ON cves(last_modified_at DESC);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_year ON cves(year DESC);
CREATE INDEX IF NOT EXISTS idx_cves_trending ON cves(trending_score DESC);
CREATE INDEX IF NOT EXISTS idx_cves_description_gin ON cves USING GIN (to_tsvector('english', description));
CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);
CREATE INDEX IF NOT EXISTS idx_vendors_name ON vendors(name);
CREATE INDEX IF NOT EXISTS idx_cve_products_product_id ON cve_products(product_id);
CREATE INDEX IF NOT EXISTS idx_cve_references_cve_id ON cve_references(cve_id);

CREATE OR REPLACE VIEW looker_cve_overview AS
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
) primary_match ON TRUE;

CREATE OR REPLACE VIEW looker_daily_severity AS
SELECT published_date, severity, cve_count, max_cvss, avg_cvss
FROM analytics_daily_severity;

CREATE OR REPLACE VIEW looker_vendor_year AS
SELECT year, vendor_name, severity, cve_count, critical_count, avg_cvss
FROM analytics_vendor_year;
