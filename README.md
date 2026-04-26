## Demo Note
### For the sake of the Demo, The amount of data we retrieve from NVD's API is limited to the last 15 days and we trigger the refresh manually as not to get rate limited or outright blocked.

<p align="center">
  <img src="https://github.com/22AKMS/Optimus/blob/main/public/apple-touch-icon.png" width="120" />
</p>

<h1 align="center">Optimus</h1>

<p align="center">
  <strong>A CVE Analysis Optimizer</strong>
</p>


<p align="center">
  <a href="#Install">Automatic Install</a> •
  <a href="#Manual-Installation">Manual Installation</a> •
  <a href="#Team-member-responsibilities">Team Responsibilities</a> •
  <a href="#Project-Requirements">Project Requirements</a> •
  <a href="#Diagram">Diagram</a>
</p>


## ⚠️⚠️ Optional Prerequisite ⚠️⚠️

### This app uses data from NVD API. An API key is not required but if you plan on requesting a lot of data without getting rate limited then we recommend getting an API key from here:

https://nvd.nist.gov/developers/request-an-api-key


## Install
You will need to add your Enterprise GitHub credentials to git to be able to clone this project.

Run these commands in Google Cloud Console


### Clone this project
```bash
git clone https://github.itap.purdue.edu/aalsaadi/Optimus/
cd Optimus
```

### Add execute permission to the script and run it 
```bash
chmod +x install_gcloud.sh
npm install
./install_gcloud.sh
```

WIP<!-- ⚠️⚠️ add more here...-->



## Team member responsibilities

- [ ] **Abdulla Alsaadi - Backend / API implementation / Installer / Backend scripts**
- [ ] **Liulseged Abate - Web app / frontend**
- [ ] **Matteo Hodge - Databases / cloud services**
- [ ] **Noah Pumphrey - Functions / deployment / demo**


## Project Requirements
| Requirement | Status | Note |
|---|---|---|
| One relational database | ✅ | Cloud SQL - PostgreSQL |
| One Non-relational database | ✅ | Firestore |
| Google Cloud Function 1 | ✅ | syncRecentCves |
| Google Cloud Function 2 | ✅ | refreshTrentAnalystics |

## Diagram

                           +---------------------------+
                           |         Browser           |
                           |  homepage / CVE detail    |
                           |  filters / watchlist      |
                           +-------------+-------------+
                                         |
                                         | HTTPS
                                         v
                           +---------------------------+
                           |    Cloud Run web app      |
                           |   Node.js / Express       |
                           |   Optimus CVE Analyzer    |
                           +------+--------------+-----+
                                  |              |
                 relational data  |              |  non-relational data
                                  v              v
                    +--------------------+   +--------------------+
                    | Cloud SQL          |   | Firestore          |
                    | PostgreSQL         |   | saved CVEs /       |
                    | CVEs / products /  |   | watchlist /        |
                    | references / stats |   | user state         |
                    +----------+---------+   +--------------------+
                               ^
                               |
                               | ingest / refresh
                               |
                +--------------+------------------------------+
                | Google Cloud Functions                      |
                | 1) syncRecentCves                           |
                |    pulls CVEs from NVD API into Cloud SQL   |
                | 2) refreshTrendAnalytics                    |
                |    updates trend/summary analytics          |
                +--------------+------------------------------+
                               ^
                               |
                               | CVE feed
                               |
                    +----------------------------+
                    | NVD CVE API                |
                    | public vulnerability data  |
                    +----------------------------+

                    +----------------------------+
                    | Looker Studio              |
                    | trend dashboards / charts  |
                    +-------------^--------------+
                                  |
                                  | reads analytics data
                                  |
                           +------+------+
                           |  Cloud SQL  |
                           +-------------+


## Manual Installation
Use these steps if you want to deploy the GCP resources yourself instead of running `install_gcloud.sh`.

### 1. Prepare the project
Run these commands from Google Cloud Shell:

```bash
git clone https://github.itap.purdue.edu/aalsaadi/Optimus/
cd Optimus
npm install
```

Set the deployment values. Replace the password values before running the commands.

```bash
export PROJECT_ID="your-gcp-project-id"
export REGION="us-central1"
export INSTANCE="cve-analyzer-sql"
export DB_NAME="cve_analyzer"
export DB_USER="appuser"
export DB_PASSWORD="replace-with-app-db-password"
export POSTGRES_PASSWORD="replace-with-postgres-admin-password"
export FIRESTORE_DB="cve-analyzer"
export APP_SERVICE="cve-analyzer-app"
export APP_SA="cve-analyzer-sa"
export SYNC_FUNCTION="syncRecentCves"
export ANALYTICS_FUNCTION="refreshTrendAnalytics"
export APP_USER_ID="demo-user"
export INITIAL_SYNC_DAYS="30"
export NVD_API_KEY=""
export LOOKER_DB_USER="looker_reader"
export LOOKER_DB_PASSWORD="replace-with-looker-reader-password"
```

```bash
gcloud config set project "$PROJECT_ID"

gcloud services enable \
  run.googleapis.com \
  cloudfunctions.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  sqladmin.googleapis.com \
  firestore.googleapis.com
```

### 2. Create data services
Create Firestore and Cloud SQL:

```bash
gcloud firestore databases describe --database="$FIRESTORE_DB" \
  || gcloud firestore databases create \
    --database="$FIRESTORE_DB" \
    --location="$REGION" \
    --edition=standard \
    --type=firestore-native

gcloud sql instances describe "$INSTANCE" \
  || gcloud sql instances create "$INSTANCE" \
    --database-version=POSTGRES_16 \
    --edition=ENTERPRISE \
    --cpu=1 \
    --memory=3840MB \
    --region="$REGION"
```

Create the database users and database:

```bash
gcloud sql users set-password postgres \
  --instance="$INSTANCE" \
  --password="$POSTGRES_PASSWORD"

gcloud sql databases describe "$DB_NAME" --instance="$INSTANCE" \
  || gcloud sql databases create "$DB_NAME" --instance="$INSTANCE"

if gcloud sql users describe "$DB_USER" --instance="$INSTANCE" >/dev/null 2>&1; then
  gcloud sql users set-password "$DB_USER" --instance="$INSTANCE" --password="$DB_PASSWORD"
else
  gcloud sql users create "$DB_USER" --instance="$INSTANCE" --password="$DB_PASSWORD"
fi

if gcloud sql users describe "$LOOKER_DB_USER" --instance="$INSTANCE" >/dev/null 2>&1; then
  gcloud sql users set-password "$LOOKER_DB_USER" --instance="$INSTANCE" --password="$LOOKER_DB_PASSWORD"
else
  gcloud sql users create "$LOOKER_DB_USER" --instance="$INSTANCE" --password="$LOOKER_DB_PASSWORD"
fi
```

Apply the database schema. This requires Cloud SQL Auth Proxy to be available as `cloud-sql-proxy`.

```bash
export INSTANCE_CONNECTION_NAME="$(gcloud sql instances describe "$INSTANCE" --format='value(connectionName)')"
export PROXY_PORT="9470"

cloud-sql-proxy "$INSTANCE_CONNECTION_NAME" --port "$PROXY_PORT" >/tmp/cloud-sql-proxy.log 2>&1 &
export PROXY_PID="$!"
sleep 5

export PGPASSWORD="$POSTGRES_PASSWORD"
psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PROXY_PORT" -U postgres -d "$DB_NAME" <<SQL
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
GRANT USAGE, CREATE ON SCHEMA public TO $DB_USER;
GRANT CONNECT ON DATABASE $DB_NAME TO $LOOKER_DB_USER;
GRANT USAGE ON SCHEMA public TO $LOOKER_DB_USER;
SQL

export PGPASSWORD="$DB_PASSWORD"
psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PROXY_PORT" -U "$DB_USER" -d "$DB_NAME" -f db/schema-postgres.sql

psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PROXY_PORT" -U "$DB_USER" -d "$DB_NAME" <<SQL
REVOKE SELECT ON ALL TABLES IN SCHEMA public FROM $LOOKER_DB_USER;
REVOKE SELECT ON ALL SEQUENCES IN SCHEMA public FROM $LOOKER_DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM $LOOKER_DB_USER;
GRANT USAGE ON SCHEMA public TO $LOOKER_DB_USER;
GRANT SELECT ON looker_cve_overview TO $LOOKER_DB_USER;
SQL
```

### 3. Load initial CVE data
Run the initial NVD sync through the local script:

```bash
DB_HOST=127.0.0.1 \
DB_PORT="$PROXY_PORT" \
DB_USER="$DB_USER" \
DB_NAME="$DB_NAME" \
DB_PASSWORD="$DB_PASSWORD" \
NVD_API_KEY="$NVD_API_KEY" \
DEFAULT_SYNC_WINDOW_TYPE=published \
DEFAULT_SYNC_WINDOW_DAYS="$INITIAL_SYNC_DAYS" \
DEFAULT_SYNC_MAX_RECORDS=0 \
node scripts/syncNvdToDb.js --days="$INITIAL_SYNC_DAYS" --window-type=published --max-records=0
```

Verify that the Looker view reflects all CVEs:

```bash
psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PROXY_PORT" -U "$DB_USER" -d "$DB_NAME" <<SQL
SELECT
  (SELECT COUNT(*) FROM cves) AS source_cves,
  (SELECT COUNT(*) FROM looker_cve_overview) AS looker_cve_overview;
SQL
```

The two counts must match.

### 4. Create the service account
```bash
export SA_EMAIL="${APP_SA}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts describe "$SA_EMAIL" \
  || gcloud iam service-accounts create "$APP_SA" --display-name="Optimus service account"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/cloudsql.client" \
  --quiet

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/datastore.user" \
  --quiet
```

### 5. Deploy Cloud Run
```bash
gcloud run deploy "$APP_SERVICE" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --service-account "$SA_EMAIL" \
  --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME" \
  --set-env-vars "APP_NAME=Optimus - A CVE Analysis Optimizer,APP_USER_ID=$APP_USER_ID,FIRESTORE_PROJECT_ID=$PROJECT_ID,FIRESTORE_DATABASE_ID=$FIRESTORE_DB,INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME,DB_NAME=$DB_NAME,DB_USER=$DB_USER,DB_PASSWORD=$DB_PASSWORD,NVD_API_KEY=$NVD_API_KEY,DEFAULT_SYNC_WINDOW_TYPE=published,DEFAULT_SYNC_WINDOW_DAYS=$INITIAL_SYNC_DAYS"
```

### 6. Deploy the Cloud Functions
```bash
gcloud functions deploy "$SYNC_FUNCTION" \
  --gen2 \
  --runtime=nodejs22 \
  --region="$REGION" \
  --source=functions/syncRecentCves \
  --entry-point=syncRecentCves \
  --trigger-http \
  --allow-unauthenticated \
  --service-account="$SA_EMAIL" \
  --timeout=3600s \
  --memory=1GiB \
  --set-env-vars "INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME,DB_NAME=$DB_NAME,DB_USER=$DB_USER,DB_PASSWORD=$DB_PASSWORD,NVD_API_KEY=$NVD_API_KEY,DEFAULT_SYNC_WINDOW_TYPE=published,DEFAULT_SYNC_WINDOW_DAYS=$INITIAL_SYNC_DAYS,DEFAULT_SYNC_MAX_RECORDS=0"

gcloud functions deploy "$ANALYTICS_FUNCTION" \
  --gen2 \
  --runtime=nodejs22 \
  --region="$REGION" \
  --source=functions/refreshTrendAnalytics \
  --entry-point=refreshTrendAnalytics \
  --trigger-http \
  --allow-unauthenticated \
  --service-account="$SA_EMAIL" \
  --timeout=3600s \
  --memory=1GiB \
  --set-env-vars "INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME,DB_NAME=$DB_NAME,DB_USER=$DB_USER,DB_PASSWORD=$DB_PASSWORD,DEFAULT_SYNC_WINDOW_DAYS=$INITIAL_SYNC_DAYS"
```

Attach Cloud SQL to the Gen 2 function backing services:

```bash
export SYNC_RUN_SERVICE="$(gcloud functions describe "$SYNC_FUNCTION" --gen2 --region "$REGION" --format='value(serviceConfig.service)' | awk -F/ '{print $NF}')"
export ANALYTICS_RUN_SERVICE="$(gcloud functions describe "$ANALYTICS_FUNCTION" --gen2 --region "$REGION" --format='value(serviceConfig.service)' | awk -F/ '{print $NF}')"

gcloud run services update "$SYNC_RUN_SERVICE" \
  --region "$REGION" \
  --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME"

gcloud run services update "$ANALYTICS_RUN_SERVICE" \
  --region "$REGION" \
  --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME"
```

### 7. Smoke test
```bash
export APP_URL="$(gcloud run services describe "$APP_SERVICE" --region "$REGION" --format='value(status.url)')"
export ANALYTICS_URL="$(gcloud functions describe "$ANALYTICS_FUNCTION" --gen2 --region "$REGION" --format='value(serviceConfig.uri)')"

curl -fsS "$APP_URL/healthz" && echo
curl -fsS "$APP_URL/api/cves?sort=newest&limit=3" | head -c 600 && echo
curl -sS -X POST "$ANALYTICS_URL" -H 'Content-Type: application/json' -d "{\"days\":$INITIAL_SYNC_DAYS}" && echo
```

The analytics response should include matching `looker_counts.source_count` and `looker_counts.overview_count`.

### 8. Looker Studio
Use the PostgreSQL connector with the Cloud SQL public IP, port `5432`, database `cve_analyzer`, and user `looker_reader`.
Before connecting, add the Looker Studio connector range `142.251.74.0/23` to the Cloud SQL authorized networks without removing any existing authorized networks.

Use only this reporting source:

```text
looker_cve_overview
```
