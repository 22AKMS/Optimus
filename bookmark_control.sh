#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
printf '\nbookmark_control.sh has been renamed to CVE_control.sh. Redirecting...\n\n'
exec "$ROOT_DIR/CVE_control.sh" "$@"
