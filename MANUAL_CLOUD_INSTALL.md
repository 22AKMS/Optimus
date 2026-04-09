# Manual Cloud Installation Guide

This guide installs **Optimus - A CVE Analysis Optimizer** on Google Cloud **without** using `install_gcloud.sh`.

It follows the same architecture as the project:
- **Cloud Run** for the web app
- **Cloud SQL for PostgreSQL** for CVE data
- **Firestore** for saved CVEs and watched products
- **Cloud Functions Gen2** for NVD sync and analytics refresh

## 1. Prerequisites

You need all of these before starting:

- a Google Cloud project with billing enabled
- `gcloud` CLI installed and authenticated
- `node` and `npm`
- `psql`
- `cloud-sql-proxy`
- this project checked out locally
- an optional NVD API key

Check the tools:

```bash
gcloud --version
node --version
npm --version
psql --version
cloud-sql-proxy --version
```

## 2. Set your variables

Run these in the project root and change values if needed.

```bash
export PROJECT_ID="YOUR_PROJECT_ID"
export REGION="us-central1"
export INSTANCE="cve-analyzer-sql"
export DB_NAME="cve_analyzer"
export DB_USER="appuser"
export DB_PASSWORD="CHANGE_ME_APP_PASSWORD"
export POSTGRES_PASSWORD="CHANGE_ME_POSTGRES_PASSWORD"
export FIRESTORE_DB="cve-analyzer"
export APP_SERVICE="cve-analyzer-app"
export APP_SA="cve-analyzer-sa"
export APP_USER_ID="demo-user"
export SYNC_FUNCTION="syncRecentCves"
export ANALYTICS_FUNCTION="refreshTrendAnalytics"
export INITIAL_SYNC_DAYS="30"
export NVD_API_KEY="YOUR_OPTIONAL_NVD_API_KEY"
```

Set the active project:

```bash
gcloud config set project "$PROJECT_ID"
```

## 3. Enable required APIs

```bash
gcloud services enable \
  run.googleapis.com \
  cloudfunctions.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  sqladmin.googleapis.com \
  firestore.googleapis.com
```

## 4. Install Node dependencies

```bash
npm install
```

## 5. Create Firestore database

If the database does not exist yet:

```bash
gcloud firestore databases create \
  --project "$PROJECT_ID" \
  --database "$FIRESTORE_DB" \
  --location "$REGION" \
  --edition=standard \
  --type=firestore-native
```

If it already exists, this command will fail. That is normal. Use this to check:

```bash
gcloud firestore databases describe \
  --project "$PROJECT_ID" \
  --database "$FIRESTORE_DB"
```

## 6. Create the Cloud SQL PostgreSQL instance

```bash
gcloud sql instances create "$INSTANCE" \
  --project "$PROJECT_ID" \
  --database-version=POSTGRES_16 \
  --edition=ENTERPRISE \
  --cpu=1 \
  --memory=3840MB \
  --region "$REGION"
```

Set the `postgres` password:

```bash
gcloud sql users set-password postgres \
  --project "$PROJECT_ID" \
  --instance "$INSTANCE" \
  --password "$POSTGRES_PASSWORD"
```

Create the application database:

```bash
gcloud sql databases create "$DB_NAME" \
  --project "$PROJECT_ID" \
  --instance "$INSTANCE"
```

Create the application user:

```bash
gcloud sql users create "$DB_USER" \
  --project "$PROJECT_ID" \
  --instance "$INSTANCE" \
  --password "$DB_PASSWORD"
```

Get the instance connection name:

```bash
export INSTANCE_CONNECTION_NAME="$(gcloud sql instances describe "$INSTANCE" --project "$PROJECT_ID" --format='value(connectionName)')"
echo "$INSTANCE_CONNECTION_NAME"
```

## 7. Start the Cloud SQL Auth Proxy

This is only for schema setup and the initial seed from your machine.

```bash
cloud-sql-proxy "$INSTANCE_CONNECTION_NAME" --port 9470
```

Leave that terminal running.

Open a second terminal in the project root and set:

```bash
export PGPASSWORD="$POSTGRES_PASSWORD"
```

Grant database privileges:

```bash
psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -p 9470 -U postgres -d "$DB_NAME" <<SQL
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
GRANT USAGE, CREATE ON SCHEMA public TO $DB_USER;
SQL
```

Apply the schema as the app user:

```bash
export PGPASSWORD="$DB_PASSWORD"
psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -p 9470 -U "$DB_USER" -d "$DB_NAME" -f db/schema-postgres.sql
```

## 8. Perform the initial CVE sync

With the proxy still running:

```bash
DB_HOST=127.0.0.1 \
DB_PORT=9470 \
DB_USER="$DB_USER" \
DB_NAME="$DB_NAME" \
DB_PASSWORD="$DB_PASSWORD" \
NVD_API_KEY="$NVD_API_KEY" \
DEFAULT_SYNC_WINDOW_TYPE=published \
node scripts/syncNvdToDb.js --days="$INITIAL_SYNC_DAYS" --window-type=published --max-records=300
```

Then rebuild analytics once:

```bash
DB_HOST=127.0.0.1 \
DB_PORT=9470 \
DB_USER="$DB_USER" \
DB_NAME="$DB_NAME" \
DB_PASSWORD="$DB_PASSWORD" \
node scripts/refreshAnalytics.js
```

## 9. Create the service account

```bash
gcloud iam service-accounts create "$APP_SA" \
  --project "$PROJECT_ID" \
  --display-name "Optimus service account"
```

Set the service account email:

```bash
export SA_EMAIL="${APP_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
echo "$SA_EMAIL"
```

Grant the required roles:

```bash
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/cloudsql.client"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/datastore.user"
```

## 10. Deploy the Cloud Run web app

```bash
gcloud run deploy "$APP_SERVICE" \
  --project "$PROJECT_ID" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --service-account "$SA_EMAIL" \
  --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME" \
  --set-env-vars "APP_NAME=Optimus - A CVE Analysis Optimizer,APP_USER_ID=$APP_USER_ID,FIRESTORE_PROJECT_ID=$PROJECT_ID,FIRESTORE_DATABASE_ID=$FIRESTORE_DB,INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME,DB_NAME=$DB_NAME,DB_USER=$DB_USER,DB_PASSWORD=$DB_PASSWORD,NVD_API_KEY=$NVD_API_KEY,DEFAULT_SYNC_WINDOW_TYPE=published"
```

Get the app URL:

```bash
export APP_URL="$(gcloud run services describe "$APP_SERVICE" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"
echo "$APP_URL"
```

## 11. Deploy the sync function

```bash
gcloud functions deploy "$SYNC_FUNCTION" \
  --project "$PROJECT_ID" \
  --gen2 \
  --runtime=nodejs22 \
  --region="$REGION" \
  --source=functions/syncRecentCves \
  --entry-point=syncRecentCves \
  --trigger-http \
  --allow-unauthenticated \
  --service-account="$SA_EMAIL" \
  --set-env-vars "INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME,DB_NAME=$DB_NAME,DB_USER=$DB_USER,DB_PASSWORD=$DB_PASSWORD,NVD_API_KEY=$NVD_API_KEY,DEFAULT_SYNC_WINDOW_TYPE=published"
```

## 12. Deploy the analytics function

```bash
gcloud functions deploy "$ANALYTICS_FUNCTION" \
  --project "$PROJECT_ID" \
  --gen2 \
  --runtime=nodejs22 \
  --region="$REGION" \
  --source=functions/refreshTrendAnalytics \
  --entry-point=refreshTrendAnalytics \
  --trigger-http \
  --allow-unauthenticated \
  --service-account="$SA_EMAIL" \
  --set-env-vars "INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME,DB_NAME=$DB_NAME,DB_USER=$DB_USER,DB_PASSWORD=$DB_PASSWORD"
```

## 13. Attach Cloud SQL to the function backing services

Cloud Functions Gen2 runs on Cloud Run under the hood. Get the backing service names:

```bash
export SYNC_RUN_SERVICE="$(gcloud functions describe "$SYNC_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --format='value(serviceConfig.service)' | awk -F/ '{print $NF}')"
export ANALYTICS_RUN_SERVICE="$(gcloud functions describe "$ANALYTICS_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --format='value(serviceConfig.service)' | awk -F/ '{print $NF}')"

echo "$SYNC_RUN_SERVICE"
echo "$ANALYTICS_RUN_SERVICE"
```

Attach Cloud SQL:

```bash
gcloud run services update "$SYNC_RUN_SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME"

gcloud run services update "$ANALYTICS_RUN_SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME"
```

## 14. Get the function URLs

```bash
export SYNC_URL="$(gcloud functions describe "$SYNC_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --format='value(serviceConfig.uri)')"
export ANALYTICS_URL="$(gcloud functions describe "$ANALYTICS_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --format='value(serviceConfig.uri)')"

echo "$SYNC_URL"
echo "$ANALYTICS_URL"
```

## 15. Update the web app with the function URLs

```bash
gcloud run services update "$APP_SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --update-env-vars "SYNC_FUNCTION_URL=$SYNC_URL,ANALYTICS_FUNCTION_URL=$ANALYTICS_URL"
```

Refresh the app URL in case it changed:

```bash
export APP_URL="$(gcloud run services describe "$APP_SERVICE" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"
echo "$APP_URL"
```

## 16. Smoke test the deployment

```bash
curl -fsS "$APP_URL/healthz" && echo
curl -fsS "$APP_URL/api/cves?sort=newest&limit=3" | head -c 600 && echo
```

## 17. Manual operations after deployment

Trigger a manual CVE sync:

```bash
curl -X POST "$SYNC_URL" \
  -H 'Content-Type: application/json' \
  -d '{"days":30,"max_records":300,"window_type":"published"}'
```

Trigger a manual analytics refresh:

```bash
curl -X POST "$ANALYTICS_URL" -H 'Content-Type: application/json' -d '{}'
```

## 18. Looker Studio connection

The app creates these PostgreSQL views for reporting:

- `looker_cve_overview`
- `looker_daily_severity`
- `looker_vendor_year`

Connect Looker Studio directly to the Cloud SQL PostgreSQL database and use those views.

## 19. Common issues

### `Cannot find module 'dotenv'`
You forgot to run:

```bash
npm install
```

### `psql: error: connection refused`
The Cloud SQL Auth Proxy is not running, or it is not listening on port `9470`.

### The app loads but shows old CVEs
Run the sync with `window_type=published` so the newest published CVEs are prioritized.

### Firestore database already exists
Skip the create command and use `gcloud firestore databases describe` instead.

### Functions deploy but cannot reach PostgreSQL
You probably forgot the Cloud SQL attachment step for the function backing Cloud Run services.

## 20. What you will have at the end

- one Cloud Run web app
- one Cloud SQL PostgreSQL instance
- one Firestore database
- two Cloud Functions Gen2 endpoints
- PostgreSQL views ready for Looker Studio
