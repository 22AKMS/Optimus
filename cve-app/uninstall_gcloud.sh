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

prompt_project_id() {
  local value=""
  while true; do
    read -r -p "Google Cloud project ID: " value || true
    [[ -n "$value" ]] || { echo "Value is required."; continue; }
    if gcloud projects describe "$value" >/dev/null 2>&1; then
      PROJECT_ID="$value"
      return 0
    fi
    echo "Project '$value' was not found or is not accessible with your current gcloud account."
  done
}

resource_exists() {
  "$@" >/dev/null 2>&1
}

require_cmd gcloud

prompt_project_id
prompt_default REGION "Region" "us-central1"
prompt_default APP_SERVICE "Cloud Run service name" "cve-analyzer-app"
prompt_default SYNC_FUNCTION "Sync function name" "syncRecentCves"
prompt_default ANALYTICS_FUNCTION "Analytics function name" "refreshTrendAnalytics"
prompt_default SQL_INSTANCE "Cloud SQL instance name" "cve-analyzer-sql"
prompt_default FIRESTORE_DB "Firestore database ID" "cve-analyzer"
prompt_default APP_SA "Service account name" "cve-analyzer-sa"

log "Active project: $PROJECT_ID"
gcloud config set project "$PROJECT_ID" >/dev/null

cat <<OUT
This deletes these resources from project '$PROJECT_ID':
  - Cloud Run service: $APP_SERVICE
  - Cloud Function: $SYNC_FUNCTION
  - Cloud Function: $ANALYTICS_FUNCTION
  - Cloud SQL instance: $SQL_INSTANCE
  - Firestore database: $FIRESTORE_DB
  - Service account: ${APP_SA}@${PROJECT_ID}.iam.gserviceaccount.com
OUT

echo
read -r -p "Type DELETE to continue: " CONFIRM
[[ "$CONFIRM" == "DELETE" ]] || fail "Cancelled."

log "Deleting Cloud Run service"
if resource_exists gcloud run services describe "$APP_SERVICE" --project "$PROJECT_ID" --region "$REGION"; then
  gcloud run services delete "$APP_SERVICE" --project "$PROJECT_ID" --region "$REGION" --quiet
fi

log "Deleting Cloud Functions"
if resource_exists gcloud functions describe "$SYNC_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION"; then
  gcloud functions delete "$SYNC_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --quiet
fi
if resource_exists gcloud functions describe "$ANALYTICS_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION"; then
  gcloud functions delete "$ANALYTICS_FUNCTION" --project "$PROJECT_ID" --gen2 --region "$REGION" --quiet
fi

log "Deleting Cloud SQL instance"
if resource_exists gcloud sql instances describe "$SQL_INSTANCE" --project "$PROJECT_ID"; then
  gcloud sql instances patch "$SQL_INSTANCE" --project "$PROJECT_ID" --no-deletion-protection --quiet >/dev/null 2>&1 || true
  gcloud sql instances delete "$SQL_INSTANCE" --project "$PROJECT_ID" --quiet
fi

log "Deleting Firestore database"
if resource_exists gcloud firestore databases describe --project "$PROJECT_ID" --database "$FIRESTORE_DB"; then
  gcloud firestore databases update --project "$PROJECT_ID" --database "$FIRESTORE_DB" --no-delete-protection --quiet >/dev/null 2>&1 || true
  gcloud firestore databases delete --project "$PROJECT_ID" --database "$FIRESTORE_DB" --quiet
fi

log "Deleting service account"
SERVICE_ACCOUNT_EMAIL="${APP_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
if resource_exists gcloud iam service-accounts describe "$SERVICE_ACCOUNT_EMAIL" --project "$PROJECT_ID"; then
  gcloud iam service-accounts delete "$SERVICE_ACCOUNT_EMAIL" --project "$PROJECT_ID" --quiet
fi

log "Uninstall complete."
