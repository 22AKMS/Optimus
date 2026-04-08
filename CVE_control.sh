#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$ROOT_DIR/.cve_runtime"
PID_FILE="$RUNTIME_DIR/local.pid"
LOG_FILE="$RUNTIME_DIR/local.log"
CONFIG_FILE="$RUNTIME_DIR/control.env"
mkdir -p "$RUNTIME_DIR"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
APP_SERVICE="${APP_SERVICE:-cve-analyzer-app}"
SYNC_FUNCTION="${SYNC_FUNCTION:-syncRecentCves}"
ANALYTICS_FUNCTION="${ANALYTICS_FUNCTION:-refreshTrendAnalytics}"
LOCAL_PORT="${PORT:-8080}"
DEFAULT_SYNC_DAYS="${DEFAULT_SYNC_DAYS:-7}"
DEFAULT_MAX_RECORDS="${DEFAULT_MAX_RECORDS:-250}"

say() { printf '\n%s\n' "$*"; }

load_config() {
  SYNC_DAYS="$DEFAULT_SYNC_DAYS"
  SYNC_MAX_RECORDS="$DEFAULT_MAX_RECORDS"
  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
  fi
  validate_positive_integer "$SYNC_DAYS" "sync days" >/dev/null
  validate_positive_integer "$SYNC_MAX_RECORDS" "max records" >/dev/null
}

save_config() {
  cat > "$CONFIG_FILE" <<CFG
SYNC_DAYS=$SYNC_DAYS
SYNC_MAX_RECORDS=$SYNC_MAX_RECORDS
CFG
}

validate_positive_integer() {
  local value="$1"
  local label="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || { say "Invalid $label: $value"; return 1; }
  (( value >= 1 )) || { say "$label must be at least 1."; return 1; }
}

set_sync_days() {
  local value="$1"
  validate_positive_integer "$value" "sync days" || return 1
  SYNC_DAYS="$value"
  save_config
  say "Default sync window set to $SYNC_DAYS day(s)."
}

set_sync_max_records() {
  local value="$1"
  validate_positive_integer "$value" "max CVEs" || return 1
  if (( value > 1000 )); then
    say "Max CVEs cannot exceed 1000 because the sync function caps max_records at 1000."
    return 1
  fi
  SYNC_MAX_RECORDS="$value"
  save_config
  say "Default max CVEs per sync set to $SYNC_MAX_RECORDS."
}

show_sync_config() {
  load_config
  say "Sync window days: $SYNC_DAYS"
  say "Max CVEs per sync: $SYNC_MAX_RECORDS"
}

require_cloud_project() {
  [[ -n "$PROJECT_ID" ]] || { say "No gcloud project is configured."; return 1; }
}

local_running() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE")"
  kill -0 "$pid" >/dev/null 2>&1
}

start_local() {
  if local_running; then
    say "Local CVE Analyzer is already running on PID $(cat "$PID_FILE")."
    return
  fi
  say "Starting local CVE Analyzer on port $LOCAL_PORT..."
  cd "$ROOT_DIR"
  nohup npm start >"$LOG_FILE" 2>&1 &
  echo $! >"$PID_FILE"
  sleep 2
  if local_running; then
    say "Started. URL: http://localhost:$LOCAL_PORT"
    say "Log file: $LOG_FILE"
  else
    say "Start failed. Check $LOG_FILE"
  fi
}

stop_local() {
  if ! local_running; then
    say "Local CVE Analyzer is not running."
    rm -f "$PID_FILE"
    return
  fi
  local pid
  pid="$(cat "$PID_FILE")"
  kill "$pid" >/dev/null 2>&1 || true
  rm -f "$PID_FILE"
  say "Stopped local CVE Analyzer."
}

local_status() {
  if local_running; then
    say "Local CVE Analyzer is running on PID $(cat "$PID_FILE")."
    say "URL: http://localhost:$LOCAL_PORT"
  else
    say "Local CVE Analyzer is not running."
  fi
}

show_cloud_status() {
  require_cloud_project || return
  gcloud run services describe "$APP_SERVICE" --region "$REGION" --format='table(metadata.name,status.url,status.latestReadyRevisionName,status.conditions[0].status)' || true
}

show_cloud_url() {
  require_cloud_project || return
  gcloud run services describe "$APP_SERVICE" --region "$REGION" --format='value(status.url)' || true
}

start_cloud_app() {
  require_cloud_project || return
  say "Starting Cloud Run web app $APP_SERVICE in $REGION..."
  gcloud run services update "$APP_SERVICE" --region "$REGION" --scaling=auto
  say "Cloud Run web app resumed with automatic scaling."
  local url
  url="$(gcloud run services describe "$APP_SERVICE" --region "$REGION" --format='value(status.url)' 2>/dev/null || true)"
  [[ -n "$url" ]] && say "URL: $url"
}

stop_cloud_app() {
  require_cloud_project || return
  say "Stopping Cloud Run web app $APP_SERVICE in $REGION..."
  gcloud run services update "$APP_SERVICE" --region "$REGION" --scaling=0
  say "Cloud Run web app disabled. New requests will fail until you start it again."
}

cloud_app_status() {
  require_cloud_project || return
  local scaling
  scaling="$(gcloud run services describe "$APP_SERVICE" --region "$REGION" --format='value(metadata.annotations.[run.googleapis.com/scalingMode],metadata.annotations.[run.googleapis.com/manualInstanceCount])' 2>/dev/null || true)"
  say "Cloud Run scaling state: ${scaling:-unknown}"
  show_cloud_status
}

tail_cloud_logs() {
  require_cloud_project || return
  gcloud run services logs read "$APP_SERVICE" --region "$REGION" --limit=50
}

function_url() {
  local function_name="$1"
  gcloud functions describe "$function_name" --gen2 --region "$REGION" --format='value(serviceConfig.uri)' 2>/dev/null || true
}

trigger_sync() {
  require_cloud_project || return
  load_config
  local days="${1:-$SYNC_DAYS}"
  local max_records="${2:-$SYNC_MAX_RECORDS}"
  validate_positive_integer "$days" "sync days" || return 1
  validate_positive_integer "$max_records" "max CVEs" || return 1
  if (( max_records > 1000 )); then
    say "Max CVEs cannot exceed 1000 because the sync function caps max_records at 1000."
    return 1
  fi
  local url
  url="$(function_url "$SYNC_FUNCTION")"
  [[ -n "$url" ]] || { say "Could not find function URL for $SYNC_FUNCTION."; return 1; }
  say "Triggering $SYNC_FUNCTION for the last $days day(s), up to $max_records CVEs..."
  curl -sS -X POST "$url" \
    -H 'Content-Type: application/json' \
    -d "{\"days\":$days,\"max_records\":$max_records}" && echo
}

trigger_analytics() {
  require_cloud_project || return
  local url
  url="$(function_url "$ANALYTICS_FUNCTION")"
  [[ -n "$url" ]] || { say "Could not find function URL for $ANALYTICS_FUNCTION."; return 1; }
  say "Triggering $ANALYTICS_FUNCTION..."
  curl -sS -X POST "$url" -H 'Content-Type: application/json' -d '{}' && echo
}

show_menu() {
  cat <<'MENU'

CVE Analyzer control panel
1) Start local app
2) Stop local app
3) Local status
4) Show cloud status
5) Show cloud URL
6) Tail cloud logs
7) Trigger syncRecentCves with saved days/max CVE settings
8) Set sync window days
9) Set max CVEs per sync
10) Show sync settings
11) Trigger refreshTrendAnalytics
12) Start Cloud Run web app
13) Stop Cloud Run web app
14) Cloud web app status
15) Exit
MENU
}

load_config

case "${1:-}" in
  start) start_local; exit 0 ;;
  stop) stop_local; exit 0 ;;
  status) local_status; exit 0 ;;
  cloud-start) start_cloud_app; exit 0 ;;
  cloud-stop) stop_cloud_app; exit 0 ;;
  cloud-status) cloud_app_status; exit 0 ;;
  sync) trigger_sync "${2:-}" "${3:-}"; exit 0 ;;
  analytics) trigger_analytics; exit 0 ;;
  set-days) [[ -n "${2:-}" ]] || { say "Usage: ./CVE_control.sh set-days <days>"; exit 1; }; set_sync_days "$2"; exit 0 ;;
  set-max-records) [[ -n "${2:-}" ]] || { say "Usage: ./CVE_control.sh set-max-records <count>"; exit 1; }; set_sync_max_records "$2"; exit 0 ;;
  config) show_sync_config; exit 0 ;;
esac

while true; do
  show_menu
  read -r -p 'Choose an option: ' choice
  case "$choice" in
    1) start_local ;;
    2) stop_local ;;
    3) local_status ;;
    4) show_cloud_status ;;
    5) show_cloud_url ;;
    6) tail_cloud_logs ;;
    7) trigger_sync ;;
    8)
      read -r -p 'Enter sync window days: ' value
      set_sync_days "$value"
      ;;
    9)
      read -r -p 'Enter max CVEs per sync (1-1000): ' value
      set_sync_max_records "$value"
      ;;
    10) show_sync_config ;;
    11) trigger_analytics ;;
    12) start_cloud_app ;;
    13) stop_cloud_app ;;
    14) cloud_app_status ;;
    15) exit 0 ;;
    *) say "Invalid choice." ;;
  esac
done
