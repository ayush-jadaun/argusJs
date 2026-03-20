#!/bin/bash
set -e

BASE_URL=${BASE_URL:-http://localhost:3100}
SCENARIOS_DIR="$(dirname "$0")/scenarios"
PASSED=0
FAILED=0
RESULTS=()

echo "================================="
echo "ArgusJS k6 Performance Test Suite"
echo "Base URL: $BASE_URL"
echo "================================="

for scenario in "$SCENARIOS_DIR"/*.js; do
  name=$(basename "$scenario" .js)
  echo ""
  echo "--- Running: $name ---"
  if k6 run --env BASE_URL="$BASE_URL" "$scenario" 2>&1; then
    RESULTS+=("PASS  $name")
    PASSED=$((PASSED + 1))
  else
    RESULTS+=("FAIL  $name")
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "================================="
echo "Results Summary"
echo "================================="
for r in "${RESULTS[@]}"; do echo "$r"; done
echo "---------------------------------"
echo "Passed: $PASSED  Failed: $FAILED"
echo "================================="

exit $FAILED
