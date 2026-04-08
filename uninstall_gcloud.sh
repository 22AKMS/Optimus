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

resource_exists() {
  "$@" >/dev/null 2>&1
}

require_cmd gcloud

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
APP_SERVICE="${APP_SERVICE:-cve-analyzer-app}"
SYNC_FUNCTION="${SYNC_FUNCTION:-syncRecentCves}"
ANALYTICS_FUNCTION="${ANALYTICS_FUNCTION:-refreshTrendAnalytics}"
SQL_INSTANCE="${INSTANCE:-cve-analyzer-sql}"
FIRESTORE_DB="${FIRESTORE_DB:-cve-analyzer}"
APP_SA="${APP_SA:-cve-analyzer-sa}"

[[ -n "$PROJECT_ID" ]] || fail "Set PROJECT_ID or configure gcloud first."

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
