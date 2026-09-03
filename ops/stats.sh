#!/bin/sh
# Print steepd's operator figures from anywhere. Reads the bearer token from
# $STEEPD_STATS_TOKEN or ~/.config/steepd/stats-token (the same value as the service's
# STATS_TOKEN variable). Usage: ops/stats.sh [base-url]
set -eu
base="${1:-https://steepd.app}"
token="${STEEPD_STATS_TOKEN:-$(cat "$HOME/.config/steepd/stats-token")}"
exec curl -fsS -H "Authorization: Bearer $token" "$base/admin/stats"
