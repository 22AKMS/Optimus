#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$ROOT_DIR/.cve_runtime"
CONFIG_FILE="$RUNTIME_DIR/control.env"
mkdir -p "$RUNTIME_DIR"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
APP_SERVICE="${APP_SERVICE:-cve-analyzer-app}"
SYNC_FUNCTION="${SYNC_FUNCTION:-syncRecentCves}"
ANALYTICS_FUNCTION="${ANALYTICS_FUNCTION:-refreshTrendAnalytics}"
DEFAULT_SYNC_DAYS="${DEFAULT_SYNC_DAYS:-7}"
DEFAULT_MAX_RECORDS="${DEFAULT_MAX_RECORDS:-0}"
MAX_SYNC_DAYS="${MAX_SYNC_DAYS:-30}"

say() { printf '\n%s\n' "$*"; }

validate_positive_integer() {
  local value="$1"
  local label="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || { say "Invalid $label: $value"; return 1; }
  (( value >= 1 )) || { say "$label must be at least 1."; return 1; }
}

validate_nonnegative_integer() {
  local value="$1"
  local label="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || { say "Invalid $label: $value"; return 1; }
  (( value >= 0 )) || { say "$label cannot be negative."; return 1; }
}

load_config() {
  SYNC_DAYS="$DEFAULT_SYNC_DAYS"
  SYNC_MAX_RECORDS="$DEFAULT_MAX_RECORDS"
  if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
  fi
  validate_positive_integer "$SYNC_DAYS" "sync days" >/dev/null || SYNC_DAYS="$DEFAULT_SYNC_DAYS"
  validate_nonnegative_integer "$SYNC_MAX_RECORDS" "max records" >/dev/null || SYNC_MAX_RECORDS="$DEFAULT_MAX_RECORDS"
  if (( SYNC_DAYS > MAX_SYNC_DAYS )); then
    SYNC_DAYS="$MAX_SYNC_DAYS"
  fi
}

save_config() {
  cat > "$CONFIG_FILE" <<CFG
SYNC_DAYS=$SYNC_DAYS
SYNC_MAX_RECORDS=$SYNC_MAX_RECORDS
CFG
}

set_sync_days() {
  local value="$1"
  validate_positive_integer "$value" "sync days" || return 1
  if (( value > MAX_SYNC_DAYS )); then
    say "Sync days cannot exceed $MAX_SYNC_DAYS to keep NVD pulls bounded."
    return 1
  fi
  SYNC_DAYS="$value"
  save_config
  say "Default sync window set to $SYNC_DAYS day(s)."
}

set_sync_max_records() {
  local value="$1"
  validate_nonnegative_integer "$value" "max CVEs" || return 1
  SYNC_MAX_RECORDS="$value"
  save_config
  if (( value == 0 )); then
    say "Default max CVEs per sync set to 0 (pull the full selected day window, up to $MAX_SYNC_DAYS days)."
  else
    say "Default max CVEs per sync set to $SYNC_MAX_RECORDS."
  fi
}

show_sync_config() {
  load_config
  say "Sync window days: $SYNC_DAYS (max $MAX_SYNC_DAYS)"
  if (( SYNC_MAX_RECORDS == 0 )); then
    say "Max CVEs per sync: 0 (full selected day window)"
  else
    say "Max CVEs per sync: $SYNC_MAX_RECORDS"
  fi
}

require_cloud_project() {
  [[ -n "$PROJECT_ID" ]] || { say "No gcloud project is configured."; return 1; }
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


run_service_json() {
  gcloud run services describe "$APP_SERVICE" --region "$REGION" --format=json 2>/dev/null || true
}

current_dashboard_url() {
  local service_json
  service_json="$(run_service_json)"
  [[ -n "$service_json" ]] || return 0
  python3 -c 'import json,sys
try:
    data=json.load(sys.stdin)
    envs=((data.get("spec") or {}).get("template") or {}).get("spec", {}).get("containers", [{}])[0].get("env", [])
    for item in envs:
        if item.get("name") == "SHARED_LOOKER_STUDIO_URL":
            print(item.get("value", ""))
            break
except Exception:
    pass
' <<<"$service_json"
}

validate_http_url() {
  local value="$1"
  [[ "$value" =~ ^https?://.+$ ]] || { say "Enter a valid http(s) URL."; return 1; }
}

show_dashboard_url() {
  require_cloud_project || return
  local current
  current="$(current_dashboard_url)"
  if [[ -n "$current" ]]; then
    say "Shared dashboard URL: $current"
  else
    say "No shared dashboard URL is configured on $APP_SERVICE."
  fi
}

set_dashboard_url() {
  require_cloud_project || return
  local url="$1"
  validate_http_url "$url" || return 1
  say "Updating shared Looker Studio URL on $APP_SERVICE..."
  gcloud run services update "$APP_SERVICE" --region "$REGION" --update-env-vars "^~^SHARED_LOOKER_STUDIO_URL=$url" >/dev/null
  say "Shared dashboard URL updated. It will appear in the app after the new revision becomes ready."
  show_dashboard_url
}

clear_dashboard_url() {
  require_cloud_project || return
  say "Removing shared Looker Studio URL from $APP_SERVICE..."
  gcloud run services update "$APP_SERVICE" --region "$REGION" --remove-env-vars SHARED_LOOKER_STUDIO_URL >/dev/null
  say "Shared dashboard URL removed from the app."
}



function_json() {
  gcloud functions describe "$SYNC_FUNCTION" --gen2 --region "$REGION" --format=json 2>/dev/null || true
}

current_nvd_api_key() {
  local fn_json
  fn_json="$(function_json)"
  [[ -n "$fn_json" ]] || return 0
  python3 -c 'import json,sys
try:
    data=json.load(sys.stdin)
    envs=((data.get("serviceConfig") or {}).get("environmentVariables") or {})
    print(envs.get("NVD_API_KEY", ""))
except Exception:
    pass
' <<<"$fn_json"
}

mask_secret() {
  local value="$1"
  local length=${#value}
  if (( length <= 4 )); then
    printf '****'
  else
    printf '****%s' "${value: -4}"
  fi
}

sync_run_service_name() {
  local fn_json
  fn_json="$(function_json)"
  [[ -n "$fn_json" ]] || return 0
  python3 -c 'import json,sys
try:
    data=json.load(sys.stdin)
    service=(data.get("serviceConfig") or {}).get("service", "")
    print(service.rsplit("/", 1)[-1] if service else "")
except Exception:
    pass
' <<<"$fn_json"
}

show_nvd_api_key() {
  require_cloud_project || return
  local current
  current="$(current_nvd_api_key)"
  if [[ -n "$current" ]]; then
    say "NVD API key is configured on $SYNC_FUNCTION: $(mask_secret "$current")"
  else
    say "No NVD API key is configured on $SYNC_FUNCTION."
  fi
}

set_nvd_api_key() {
  require_cloud_project || return
  local key="$1"
  [[ -n "$key" ]] || { say "Enter a non-empty NVD API key."; return 1; }
  local service_name
  service_name="$(sync_run_service_name)"
  [[ -n "$service_name" ]] || { say "Could not determine the underlying Cloud Run service for $SYNC_FUNCTION."; return 1; }
  say "Updating NVD API key on $SYNC_FUNCTION..."
  gcloud run services update "$service_name" --region "$REGION" --update-env-vars "^~^NVD_API_KEY=$key" >/dev/null
  say "NVD API key updated on $SYNC_FUNCTION."
  show_nvd_api_key
}

clear_nvd_api_key() {
  require_cloud_project || return
  local service_name
  service_name="$(sync_run_service_name)"
  [[ -n "$service_name" ]] || { say "Could not determine the underlying Cloud Run service for $SYNC_FUNCTION."; return 1; }
  say "Removing NVD API key from $SYNC_FUNCTION..."
  gcloud run services update "$service_name" --region "$REGION" --remove-env-vars NVD_API_KEY >/dev/null
  say "NVD API key removed from $SYNC_FUNCTION."
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
  if (( days > MAX_SYNC_DAYS )); then
    say "Sync days cannot exceed $MAX_SYNC_DAYS to keep NVD pulls bounded."
    return 1
  fi
  validate_nonnegative_integer "$max_records" "max CVEs" || return 1
  local url
  url="$(function_url "$SYNC_FUNCTION")"
  [[ -n "$url" ]] || { say "Could not find function URL for $SYNC_FUNCTION."; return 1; }
  if (( max_records == 0 )); then
    say "Triggering $SYNC_FUNCTION for the full last $days day(s) window..."
  else
    say "Triggering $SYNC_FUNCTION for the last $days day(s), up to $max_records CVEs..."
  fi
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

Optimus control panel
1) Show cloud status
2) Show cloud URL
3) Tail cloud logs
4) Trigger syncRecentCves with saved days/max CVE settings
5) Set sync window days
6) Set max CVEs per sync
7) Show sync settings
8) Trigger refreshTrendAnalytics
9) Show shared dashboard URL
10) Set or change shared dashboard URL
11) Remove shared dashboard URL
12) Show NVD API key status
13) Set or change NVD API key
14) Remove NVD API key
15) Start Cloud Run web app
16) Stop Cloud Run web app
17) Cloud web app status
18) Exit
MENU
}

load_config

case "${1:-}" in
  cloud-start) start_cloud_app; exit 0 ;;
  cloud-stop) stop_cloud_app; exit 0 ;;
  cloud-status) cloud_app_status; exit 0 ;;
  sync) trigger_sync "${2:-}" "${3:-}"; exit 0 ;;
  analytics) trigger_analytics; exit 0 ;;
  dashboard-show) show_dashboard_url; exit 0 ;;
  dashboard-set) [[ -n "${2:-}" ]] || { say "Usage: ./CVE_control.sh dashboard-set <https://...>"; exit 1; }; set_dashboard_url "$2"; exit 0 ;;
  dashboard-clear) clear_dashboard_url; exit 0 ;;
  nvd-key-show) show_nvd_api_key; exit 0 ;;
  nvd-key-set) [[ -n "${2:-}" ]] || { say "Usage: ./CVE_control.sh nvd-key-set <api-key>"; exit 1; }; set_nvd_api_key "$2"; exit 0 ;;
  nvd-key-clear) clear_nvd_api_key; exit 0 ;;
  set-days) [[ -n "${2:-}" ]] || { say "Usage: ./CVE_control.sh set-days <days>"; exit 1; }; set_sync_days "$2"; exit 0 ;;
  set-max-records) [[ -n "${2:-}" ]] || { say "Usage: ./CVE_control.sh set-max-records <count|0>"; exit 1; }; set_sync_max_records "$2"; exit 0 ;;
  config) show_sync_config; exit 0 ;;
esac

while true; do
  show_menu
  read -r -p 'Choose an option: ' choice
  case "$choice" in
    1) show_cloud_status ;;
    2) show_cloud_url ;;
    3) tail_cloud_logs ;;
    4) trigger_sync ;;
    5)
      read -r -p 'Enter sync window days (1-30): ' value
      set_sync_days "$value"
      ;;
    6)
      read -r -p 'Enter max CVEs per sync (0 = full day window): ' value
      set_sync_max_records "$value"
      ;;
    7) show_sync_config ;;
    8) trigger_analytics ;;
    9) show_dashboard_url ;;
    10)
      read -r -p 'Enter the shared Looker Studio URL: ' value
      set_dashboard_url "$value"
      ;;
    11) clear_dashboard_url ;;
    12) show_nvd_api_key ;;
    13)
      read -r -p 'Enter the NVD API key: ' value
      set_nvd_api_key "$value"
      ;;
    14) clear_nvd_api_key ;;
    15) start_cloud_app ;;
    16) stop_cloud_app ;;
    17) cloud_app_status ;;
    18) exit 0 ;;
    *) say "Invalid choice." ;;
  esac
done
