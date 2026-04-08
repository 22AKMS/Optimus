#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log() {
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

prompt_default() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="${3:-}"
  local value=""

  while true; do
    if [[ -n "$default_value" ]]; then
      read -r -p "$prompt_text [$default_value]: " value || true
    else
      read -r -p "$prompt_text: " value || true
    fi
    value="${value:-$default_value}"
    [[ -n "$value" ]] || { echo "Value is required."; continue; }
    printf -v "$var_name" '%s' "$value"
    return 0
  done
}

prompt_optional() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="${3:-}"
  local value=""
  read -r -p "$prompt_text${default_value:+ [$default_value]}: " value || true
  value="${value:-$default_value}"
  printf -v "$var_name" '%s' "$value"
}

prompt_password() {
  local var_name="$1"
  local prompt_text="$2"
  local password=""
  while true; do
    read -r -s -p "$prompt_text: " password || true
    printf '\n'
    [[ -n "$password" ]] || { echo "Password is required."; continue; }
    printf -v "$var_name" '%s' "$password"
    return 0
  done
}

wait_for_service_account() {
  local sa_email="$1"
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if gcloud iam service-accounts describe "$sa_email" --project "$PROJECT_ID" >/dev/null 2>&1; then
      return 0
    fi
    sleep $((attempt * 2))
  done
  return 1
}

add_binding_if_missing() {
  local member="$1"
  local role="$2"
  gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="$member" --role="$role" --quiet >/dev/null
}

start_proxy() {
  local port="$1"
  [[ -n "$CLOUD_SQL_PROXY_BIN" ]] || fail "cloud-sql-proxy not found."
  "$CLOUD_SQL_PROXY_BIN" "$INSTANCE_CONNECTION_NAME" --port "$port" >/tmp/cloud-sql-proxy.log 2>&1 &
  PROXY_PID=$!
  sleep 5
  kill -0 "$PROXY_PID" >/dev/null 2>&1 || {
    cat /tmp/cloud-sql-proxy.log >&2 || true
    fail "Cloud SQL Auth Proxy failed to start."
  }
}

wait_for_url() {
  local path="$1"
  local attempts=20
  local delay=5
  for ((i=1; i<=attempts; i++)); do
    if curl -fsS "$APP_URL$path" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$delay"
  done
  return 1
}

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]]; then
    kill "$PROXY_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

require_cmd gcloud
require_cmd curl
require_cmd psql
require_cmd node

if [[ ! -f package.json || ! -d db || ! -d functions ]]; then
  fail "Run this from the project root that contains package.json, db/, and functions/."
fi

CLOUD_SQL_PROXY_BIN="$(command -v cloud-sql-proxy || true)"
DEFAULT_PROJECT="$(gcloud config get-value project 2>/dev/null || true)"

prompt_default PROJECT_ID "Google Cloud project ID" "$DEFAULT_PROJECT"
prompt_default REGION "Region" "us-central1"
prompt_default INSTANCE "Cloud SQL instance name" "cve-analyzer-sql"
prompt_default DB_NAME "PostgreSQL database name" "cve_analyzer"
prompt_default DB_USER "PostgreSQL app user" "appuser"
prompt_password DB_PASSWORD "PostgreSQL app user password"
prompt_password POSTGRES_PASSWORD "PostgreSQL postgres admin password"
prompt_default FIRESTORE_DB "Firestore database ID" "cve-analyzer"
prompt_default APP_SERVICE "Cloud Run service name" "cve-analyzer-app"
prompt_default APP_SA "Service account name" "cve-analyzer-sa"
prompt_default SYNC_FUNCTION "Sync function name" "syncRecentCves"
prompt_default ANALYTICS_FUNCTION "Analytics function name" "refreshTrendAnalytics"
prompt_default APP_USER_ID "Demo app user ID" "demo-user"
prompt_default INITIAL_SYNC_DAYS "Initial sync window in days" "30"
prompt_optional NVD_API_KEY "Optional NVD API key" ""

log "Using project $PROJECT_ID"
gcloud config set project "$PROJECT_ID" >/dev/null

log "Enabling required APIs"
gcloud services enable \
  run.googleapis.com \
  cloudfunctions.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  sqladmin.googleapis.com \
  firestore.googleapis.com >/dev/null

log "Ensuring Firestore database exists"
if gcloud firestore databases describe --project "$PROJECT_ID" --database="$FIRESTORE_DB" >/dev/null 2>&1; then
  echo "Firestore database $FIRESTORE_DB already exists."
else
  gcloud firestore databases create \
    --project "$PROJECT_ID" \
    --database="$FIRESTORE_DB" \
    --location="$REGION" \
    --edition=standard \
    --type=firestore-native >/dev/null
fi

log "Ensuring Cloud SQL instance exists"
if gcloud sql instances describe "$INSTANCE" --project "$PROJECT_ID" >/dev/null 2>&1; then
  echo "Cloud SQL instance $INSTANCE already exists."
else
  gcloud sql instances create "$INSTANCE" \
    --project "$PROJECT_ID" \
    --database-version=POSTGRES_16 \
    --edition=ENTERPRISE \
    --cpu=1 \
    --memory=3840MB \
    --region="$REGION"
fi

log "Setting postgres admin password"
gcloud sql users set-password postgres \
  --project "$PROJECT_ID" \
  --instance="$INSTANCE" \
  --password="$POSTGRES_PASSWORD" >/dev/null

log "Ensuring PostgreSQL database exists"
if ! gcloud sql databases describe "$DB_NAME" --project "$PROJECT_ID" --instance="$INSTANCE" >/dev/null 2>&1; then
  gcloud sql databases create "$DB_NAME" --project "$PROJECT_ID" --instance="$INSTANCE" >/dev/null
fi

log "Ensuring app user exists"
if gcloud sql users describe "$DB_USER" --project "$PROJECT_ID" --instance="$INSTANCE" >/dev/null 2>&1; then
  gcloud sql users set-password "$DB_USER" \
    --project "$PROJECT_ID" \
    --instance="$INSTANCE" \
    --password="$DB_PASSWORD" >/dev/null
else
  gcloud sql users create "$DB_USER" \
    --project "$PROJECT_ID" \
    --instance="$INSTANCE" \
    --password="$DB_PASSWORD" >/dev/null
fi

INSTANCE_CONNECTION_NAME="$(gcloud sql instances describe "$INSTANCE" --project "$PROJECT_ID" --format='value(connectionName)')"
PROXY_PORT=9470

log "Starting Cloud SQL Auth Proxy"
start_proxy "$PROXY_PORT"

export PGPASSWORD="$POSTGRES_PASSWORD"
log "Granting database privileges"
psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PROXY_PORT" -U postgres -d "$DB_NAME" <<SQL >/dev/null
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
GRANT USAGE, CREATE ON SCHEMA public TO $DB_USER;
SQL

export PGPASSWORD="$DB_PASSWORD"
log "Applying schema"
psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PROXY_PORT" -U "$DB_USER" -d "$DB_NAME" -f db/schema-postgres.sql >/dev/null

log "Ensuring service account exists"
SA_EMAIL="${APP_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
if ! gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$APP_SA" --project "$PROJECT_ID" --display-name="CVE Analyzer service account" >/dev/null
  wait_for_service_account "$SA_EMAIL" || fail "Service account $SA_EMAIL did not become available in time."
fi

log "Granting IAM roles"
add_binding_if_missing "serviceAccount:$SA_EMAIL" "roles/cloudsql.client"
add_binding_if_missing "serviceAccount:$SA_EMAIL" "roles/datastore.user"

log "Deploying Cloud Run service"
gcloud run deploy "$APP_SERVICE" \
  --project "$PROJECT_ID" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --service-account "$SA_EMAIL" \
  --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME" \
  --set-env-vars "APP_NAME=CVE Analyzer,APP_USER_ID=$APP_USER_ID,FIRESTORE_PROJECT_ID=$PROJECT_ID,FIRESTORE_DATABASE_ID=$FIRESTORE_DB,INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME,DB_NAME=$DB_NAME,DB_USER=$DB_USER,DB_PASSWORD=$DB_PASSWORD,NVD_API_KEY=$NVD_API_KEY"

log "Deploying function $SYNC_FUNCTION"
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
  --set-env-vars "INSTANCE_CONNECTION_NAME=$INSTANCE_CONNECTION_NAME,DB_NAME=$DB_NAME,DB_USER=$DB_USER,DB_PASSWORD=$DB_PASSWORD,NVD_API_KEY=$NVD_API_KEY"

log "Deploying function $ANALYTICS_FUNCTION"
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

SYNC_RUN_SERVICE="$(gcloud functions describe "$SYNC_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --format='value(serviceConfig.service)' | awk -F/ '{print $NF}')"
ANALYTICS_RUN_SERVICE="$(gcloud functions describe "$ANALYTICS_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --format='value(serviceConfig.service)' | awk -F/ '{print $NF}')"

log "Attaching Cloud SQL to function backing services"
gcloud run services update "$SYNC_RUN_SERVICE" --project "$PROJECT_ID" --region "$REGION" --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME" >/dev/null
gcloud run services update "$ANALYTICS_RUN_SERVICE" --project "$PROJECT_ID" --region "$REGION" --add-cloudsql-instances "$INSTANCE_CONNECTION_NAME" >/dev/null

SYNC_URL="$(gcloud functions describe "$SYNC_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --format='value(serviceConfig.uri)')"
ANALYTICS_URL="$(gcloud functions describe "$ANALYTICS_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --format='value(serviceConfig.uri)')"

log "Updating Cloud Run with function URLs"
gcloud run services update "$APP_SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --update-env-vars "SYNC_FUNCTION_URL=$SYNC_URL,ANALYTICS_FUNCTION_URL=$ANALYTICS_URL" >/dev/null

APP_URL="$(gcloud run services describe "$APP_SERVICE" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"

log "Triggering initial NVD sync in Google Cloud"
curl -fsS -X POST "$SYNC_URL" \
  -H 'Content-Type: application/json' \
  -d "{\"days\":$INITIAL_SYNC_DAYS,\"max_records\":300,\"max_pages\":10}" >/tmp/initial-sync-response.json
cat /tmp/initial-sync-response.json && echo

log "Smoke testing deployment"
if wait_for_url '/healthz'; then
  curl -fsS "$APP_URL/healthz" && echo
else
  echo "Warning: /healthz did not respond successfully in time."
fi
curl -fsS "$APP_URL/api/cves?sort=newest&limit=3" | head -c 600 && echo

cat <<OUT

Finished.

App URL: $APP_URL
Sync function: $SYNC_URL
Analytics function: $ANALYTICS_URL
Cloud SQL instance: $INSTANCE
Firestore database: $FIRESTORE_DB

OUT
