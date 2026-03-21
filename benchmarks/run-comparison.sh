#!/bin/bash
set -e

echo "╔═══════════════════════════════════════════════════════╗"
echo "║   ArgusJS vs Competitors — Head-to-Head Benchmark     ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

RESULTS_DIR="benchmarks/results"
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ==========================================
# BENCHMARK 1: ArgusJS
# ==========================================
echo "━━━ [1/3] Benchmarking ArgusJS ━━━"
echo "Make sure ArgusJS server is running on port 3100"
echo ""

k6 run --env BASE_URL=http://localhost:3100 \
  --summary-export="$RESULTS_DIR/argus_${TIMESTAMP}.json" \
  benchmarks/k6/bench-argus.js 2>&1 | tee "$RESULTS_DIR/argus_${TIMESTAMP}.log"

echo ""
echo "━━━ ArgusJS benchmark complete ━━━"
echo ""

# ==========================================
# BENCHMARK 2: Keycloak
# ==========================================
echo "━━━ [2/3] Benchmarking Keycloak ━━━"
echo "Make sure Keycloak is running on port 8080"
echo ""

k6 run --env KC_URL=http://localhost:8080 --env KC_REALM=benchmark \
  --summary-export="$RESULTS_DIR/keycloak_${TIMESTAMP}.json" \
  benchmarks/k6/bench-keycloak.js 2>&1 | tee "$RESULTS_DIR/keycloak_${TIMESTAMP}.log"

echo ""
echo "━━━ Keycloak benchmark complete ━━━"
echo ""

# ==========================================
# BENCHMARK 3: FusionAuth
# ==========================================
echo "━━━ [3/3] Benchmarking FusionAuth ━━━"
echo "Make sure FusionAuth is running on port 9011"
echo ""

k6 run --env FA_URL=http://localhost:9011 \
  --env FA_API_KEY="${FA_API_KEY}" \
  --env FA_APP_ID="${FA_APP_ID}" \
  --summary-export="$RESULTS_DIR/fusionauth_${TIMESTAMP}.json" \
  benchmarks/k6/bench-fusionauth.js 2>&1 | tee "$RESULTS_DIR/fusionauth_${TIMESTAMP}.log"

echo ""
echo "━━━ FusionAuth benchmark complete ━━━"
echo ""

echo "╔═══════════════════════════════════════════════════════╗"
echo "║   All benchmarks complete!                            ║"
echo "║   Results saved to: ${RESULTS_DIR}/                   ║"
echo "╚═══════════════════════════════════════════════════════╝"
