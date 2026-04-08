#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$ROOT_DIR/.cve_runtime"
PID_FILE="$RUNTIME_DIR/local.pid"
LOG_FILE="$RUNTIME_DIR/local.log"
mkdir -p "$RUNTIME_DIR"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
APP_SERVICE="${APP_SERVICE:-cve-analyzer-app}"
SYNC_FUNCTION="${SYNC_FUNCTION:-syncRecentCves}"
ANALYTICS_FUNCTION="${ANALYTICS_FUNCTION:-refreshTrendAnalytics}"
LOCAL_PORT="${PORT:-8080}"

say() { printf '\n%s\n' "$*"; }

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
  [[ -n "$PROJECT_ID" ]] || { say "No gcloud project is configured."; return; }
  gcloud run services describe "$APP_SERVICE" --region "$REGION" --format='table(metadata.name,status.url,status.latestReadyRevisionName,status.conditions[0].status)' || true
}

show_cloud_url() {
  [[ -n "$PROJECT_ID" ]] || { say "No gcloud project is configured."; return; }
  gcloud run services describe "$APP_SERVICE" --region "$REGION" --format='value(status.url)' || true
}

tail_cloud_logs() {
  [[ -n "$PROJECT_ID" ]] || { say "No gcloud project is configured."; return; }
  gcloud run services logs read "$APP_SERVICE" --region "$REGION" --limit=50
}

trigger_function() {
  local function_name="$1"
  [[ -n "$PROJECT_ID" ]] || { say "No gcloud project is configured."; return; }
  local url
  url="$(gcloud functions describe "$function_name" --gen2 --region "$REGION" --format='value(serviceConfig.uri)' 2>/dev/null || true)"
  [[ -n "$url" ]] || { say "Could not find function URL for $function_name."; return; }
  curl -sS -X POST "$url" -H 'Content-Type: application/json' -d '{}' && echo
}

show_menu() {
  cat <<EOF

CVE Analyzer control panel
1) Start local app
2) Stop local app
3) Local status
4) Show cloud status
5) Show cloud URL
6) Tail cloud logs
7) Trigger syncRecentCves
8) Trigger refreshTrendAnalytics
9) Exit
EOF
}

if [[ "${1:-}" == "start" ]]; then
  start_local
  exit 0
elif [[ "${1:-}" == "stop" ]]; then
  stop_local
  exit 0
elif [[ "${1:-}" == "status" ]]; then
  local_status
  exit 0
fi

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
    7) trigger_function "$SYNC_FUNCTION" ;;
    8) trigger_function "$ANALYTICS_FUNCTION" ;;
    9) exit 0 ;;
    *) say "Invalid choice." ;;
  esac
done
