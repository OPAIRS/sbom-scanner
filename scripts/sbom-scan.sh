#!/bin/bash
# sbom-scan — CLI wrapper for the SBOM Scanner REST API
#
# Usage:
#   sbom-scan images              → scan all running Docker images
#   sbom-scan filesystem          → scan SCAN_SOURCES paths
#   sbom-scan k8s                 → scan all Kubernetes pod images
#   sbom-scan all                 → images + filesystem + k8s
#   sbom-scan <image:tag>         → scan a specific image
#   sbom-scan <path>              → scan a specific filesystem path
#   sbom-scan status <scan_id>    → check scan status
#   sbom-scan watch  <scan_id>    → poll status until done
#   sbom-scan reports             → list all saved reports
#   sbom-scan summary <scan_id>   → show consolidated summary JSON
#   sbom-scan top    <scan_id>    → top offenders table (Critical + High)
#
# Environment:
#   SBOM_API   API base URL (default: http://localhost:8100)
#   SEVERITY   Severity threshold for --fail-on (default: medium)

set -euo pipefail

API="${SBOM_API:-http://localhost:8100}"
SEVERITY="${SEVERITY:-medium}"
cmd="${1:-all}"

_json() { python3 -m json.tool; }

case "$cmd" in

  images|filesystem|k8s|all)
    echo "▶ Starting scan: target=$cmd, severity=$SEVERITY"
    RESPONSE=$(curl -sf -X POST "$API/scan" \
      -H "Content-Type: application/json" \
      -d "{\"target\": \"$cmd\", \"severity_threshold\": \"$SEVERITY\"}")
    SCAN_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")
    echo "✓ Queued: $SCAN_ID"
    echo ""
    echo "  Check status:  $0 status $SCAN_ID"
    echo "  Watch live:    $0 watch  $SCAN_ID"
    echo "  Summary:       $0 summary $SCAN_ID"
    ;;

  status)
    SCAN_ID="${2:?Usage: $0 status <scan_id>}"
    curl -sf "$API/scan/$SCAN_ID" | _json
    ;;

  watch)
    SCAN_ID="${2:?Usage: $0 watch <scan_id>}"
    echo "▶ Watching $SCAN_ID (Ctrl+C to abort)..."
    while true; do
      STATUS=$(curl -sf "$API/scan/$SCAN_ID" | python3 -c \
        "import sys,json; print(json.load(sys.stdin)['status'])")
      echo "[$(date +%T)] $STATUS"
      if [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]]; then
        echo ""
        curl -sf "$API/scan/$SCAN_ID" | _json
        break
      fi
      sleep 5
    done
    ;;

  reports)
    curl -sf "$API/reports" | _json
    ;;

  summary)
    SCAN_ID="${2:?Usage: $0 summary <scan_id>}"
    curl -sf "$API/reports/$SCAN_ID/summary" | _json
    ;;

  top)
    SCAN_ID="${2:?Usage: $0 top <scan_id>}"
    curl -sf "$API/reports/$SCAN_ID/summary" | python3 - <<'PY'
import sys, json
data = json.load(sys.stdin)
results = sorted(
    data["results"],
    key=lambda x: (
        x["severity_counts"].get("Critical", 0) +
        x["severity_counts"].get("High", 0)
    ),
    reverse=True,
)
print(f"{'Target':<60} {'Crit':>6} {'High':>6} {'Med':>6}")
print("-" * 84)
for r in results:
    name = r["target"]
    sc   = r["severity_counts"]
    print(f"{name:<60} {sc.get('Critical',0):>6} {sc.get('High',0):>6} {sc.get('Medium',0):>6}")
PY
    ;;

  images-list)
    echo "▶ Scannable Docker images:"
    curl -sf "$API/images" | _json
    ;;

  k8s-list)
    NAMESPACE="${2:-}"
    echo "▶ Kubernetes images${NAMESPACE:+ in namespace $NAMESPACE}:"
    URL="$API/k8s/images${NAMESPACE:+?namespace=$NAMESPACE}"
    curl -sf "$URL" | _json
    ;;

  *)
    # Treat as specific image or path
    echo "▶ Scanning specific target: $cmd"
    curl -sf -X POST "$API/scan" \
      -H "Content-Type: application/json" \
      -d "{\"target\": \"$cmd\", \"severity_threshold\": \"$SEVERITY\"}" \
      | _json
    ;;

esac
