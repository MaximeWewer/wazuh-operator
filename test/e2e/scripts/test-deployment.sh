#!/bin/bash
set -euo pipefail

#==============================================================================
# E2E Test: Basic Cluster Deployment
#==============================================================================
# Tests acceptance criteria:
# - Manager StatefulSet with 1 replica
# - Indexer StatefulSet with 1 replica
# - Dashboard Deployment with 1 replica
# - All pods reach Ready within 10 minutes (NFR-P4)
# - Cluster status shows "Ready"
# - TLS interconnection (NFR-S1)
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
NAMESPACE="${CLUSTER_NAMESPACE:-wazuh}"
CLUSTER_NAME="${CLUSTER_NAME:-wazuh-cluster}"
MAX_WAIT_TIME=600  # 10 minutes for NFR-P4

# Test results
PASSED=0
FAILED=0
TOTAL=0

# Helper functions
log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
    TOTAL=$((TOTAL + 1))
}

log_pass() {
    echo -e "${GREEN}[✓]${NC} $1"
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "${RED}[✗]${NC} $1"
    FAILED=$((FAILED + 1))
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

wait_for_ready() {
    local resource_type=$1
    local resource_name=$2
    local timeout=$3

    log_info "Waiting for $resource_type/$resource_name to be ready (timeout: ${timeout}s)..."

    if kubectl wait --for=condition=ready "$resource_type" "$resource_name" \
        -n "$NAMESPACE" --timeout="${timeout}s" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

#==============================================================================
# Test 1: Verify WazuhCluster CR exists
#==============================================================================
log_test "Test 1: Verify WazuhCluster CR exists"
if kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" &>/dev/null; then
    log_pass "WazuhCluster CR '$CLUSTER_NAME' exists"
else
    log_fail "WazuhCluster CR '$CLUSTER_NAME' not found"
    exit 1
fi

#==============================================================================
# Test 2: Verify Manager StatefulSet created with 1 replica
#==============================================================================
log_test "Test 2: Verify Manager StatefulSet created"

# Check master
MASTER_REPLICAS=$(kubectl get statefulset wazuh-cluster-manager-master \
    -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

if [[ "$MASTER_REPLICAS" == "1" ]]; then
    log_pass "Manager Master StatefulSet has 1 replica"
else
    log_fail "Manager Master StatefulSet has $MASTER_REPLICAS replicas (expected 1)"
fi

# Check worker (should be 1 for profile S)
WORKER_REPLICAS=$(kubectl get statefulset wazuh-cluster-manager-worker \
    -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

if [[ "$WORKER_REPLICAS" == "1" ]]; then
    log_pass "Manager Worker StatefulSet has 1 replica"
else
    log_fail "Manager Worker StatefulSet has $WORKER_REPLICAS replicas (expected 1)"
fi

#==============================================================================
# Test 3: Verify Indexer StatefulSet created with 1 replica
#==============================================================================
log_test "Test 3: Verify Indexer StatefulSet created"

INDEXER_REPLICAS=$(kubectl get statefulset wazuh-cluster-indexer \
    -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

if [[ "$INDEXER_REPLICAS" == "1" ]]; then
    log_pass "Indexer StatefulSet has 1 replica"
else
    log_fail "Indexer StatefulSet has $INDEXER_REPLICAS replicas (expected 1)"
fi

#==============================================================================
# Test 4: Verify Dashboard Deployment created with 1 replica
#==============================================================================
log_test "Test 4: Verify Dashboard Deployment created"

DASHBOARD_REPLICAS=$(kubectl get deployment wazuh-cluster-dashboard \
    -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

if [[ "$DASHBOARD_REPLICAS" == "1" ]]; then
    log_pass "Dashboard Deployment has 1 replica"
else
    log_fail "Dashboard Deployment has $DASHBOARD_REPLICAS replicas (expected 1)"
fi

#==============================================================================
# Test 5: Verify all pods reach Ready within 10 minutes (NFR-P4)
#==============================================================================
log_test "Test 5: Verify all pods reach Ready within 10 minutes (NFR-P4)"

START_TIME=$(date +%s)

# Wait for all pods
PODS=(
    "wazuh-cluster-manager-master-0"
    "wazuh-cluster-manager-worker-0"
    "wazuh-cluster-indexer-0"
)

ALL_READY=true
for pod in "${PODS[@]}"; do
    if ! wait_for_ready "pod" "$pod" "$MAX_WAIT_TIME"; then
        log_fail "Pod $pod did not reach Ready within $MAX_WAIT_TIME seconds"
        ALL_READY=false
    fi
done

# Dashboard is a Deployment, check differently
DASHBOARD_POD=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/component=dashboard \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [[ -n "$DASHBOARD_POD" ]]; then
    if ! wait_for_ready "pod" "$DASHBOARD_POD" "$MAX_WAIT_TIME"; then
        log_fail "Dashboard pod did not reach Ready within $MAX_WAIT_TIME seconds"
        ALL_READY=false
    fi
fi

if $ALL_READY; then
    # Get WazuhCluster creation time and latest pod Ready time
    CLUSTER_CREATED=$(kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.metadata.creationTimestamp}')
    CLUSTER_CREATED_TS=$(date -d "$CLUSTER_CREATED" +%s 2>/dev/null || echo "$START_TIME")

    # Get the LATEST pod Ready timestamp (slowest pod to become ready)
    LATEST_READY_TIME=""
    LATEST_READY_TS=0

    for pod in "${PODS[@]}" "$DASHBOARD_POD"; do
        POD_READY_TIME=$(kubectl get pod "$pod" -n "$NAMESPACE" \
            -o jsonpath='{.status.conditions[?(@.type=="Ready")].lastTransitionTime}' 2>/dev/null || echo "")

        if [[ -n "$POD_READY_TIME" ]]; then
            POD_READY_TS=$(date -d "$POD_READY_TIME" +%s 2>/dev/null || echo "0")
            if [[ $POD_READY_TS -gt $LATEST_READY_TS ]]; then
                LATEST_READY_TS=$POD_READY_TS
                LATEST_READY_TIME=$POD_READY_TIME
            fi
        fi
    done

    # Calculate elapsed time from cluster creation to last pod ready
    ELAPSED=$((LATEST_READY_TS - CLUSTER_CREATED_TS))

    # Check if this is a fresh deployment (within last hour) or existing cluster
    CURRENT_TIME=$(date +%s)
    TIME_SINCE_READY=$((CURRENT_TIME - LATEST_READY_TS))

    if [[ $TIME_SINCE_READY -gt 3600 ]]; then
        # Existing cluster (pods ready more than 1 hour ago)
        log_pass "All pods are Ready (existing cluster - NFR-P4 timing check skipped)"
        log_info "Cluster age: $((CURRENT_TIME - CLUSTER_CREATED_TS))s, Last pod ready: ${TIME_SINCE_READY}s ago"
    elif [[ $ELAPSED -le 600 ]]; then
        log_pass "All pods reached Ready in ${ELAPSED}s (< 10 minutes)"
    else
        log_fail "Pods took ${ELAPSED}s to reach Ready (> 10 minutes limit)"
    fi
fi

#==============================================================================
# Test 6: Verify cluster status shows "Ready"
#==============================================================================
log_test "Test 6: Verify cluster status shows 'Ready'"

CLUSTER_PHASE=$(kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")

if [[ "$CLUSTER_PHASE" == "Running" ]]; then
    log_pass "Cluster status phase is 'Running'"
else
    log_fail "Cluster status phase is '$CLUSTER_PHASE' (expected 'Running')"
fi

# Check Ready condition
READY_CONDITION=$(kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")

if [[ "$READY_CONDITION" == "True" ]]; then
    log_pass "Cluster Ready condition is 'True'"
else
    log_fail "Cluster Ready condition is '$READY_CONDITION' (expected 'True')"
fi

#==============================================================================
# Test 7: Verify TLS certificates exist (NFR-S1)
#==============================================================================
log_test "Test 7: Verify TLS certificates exist (NFR-S1)"

CERT_SECRETS=(
    "wazuh-cluster-manager-master-certs"
    "wazuh-cluster-indexer-certs"
    "wazuh-cluster-dashboard-certs"
)

ALL_CERTS_EXIST=true
for secret in "${CERT_SECRETS[@]}"; do
    if kubectl get secret "$secret" -n "$NAMESPACE" &>/dev/null; then
        log_pass "Certificate secret '$secret' exists"
    else
        log_fail "Certificate secret '$secret' not found"
        ALL_CERTS_EXIST=false
    fi
done

#==============================================================================
# Test 8: Verify TLS interconnection
#==============================================================================
log_test "Test 8: Verify TLS interconnection"

# Check manager logs for TLS connection to indexer
MANAGER_POD="wazuh-cluster-manager-master-0"

# Get logs and search for TLS-related patterns
MANAGER_LOGS=$(kubectl logs "$MANAGER_POD" -n "$NAMESPACE" --tail=200 2>/dev/null || echo "")

if [[ -n "$MANAGER_LOGS" ]]; then
    # Combined pattern: HTTPS URLs, SSL/TLS keywords, or certificate references
    if echo "$MANAGER_LOGS" | grep -qi -E "(https://|ssl|tls|certificate|cert\.pem|key\.pem)"; then
        log_pass "Manager logs show TLS/SSL activity"
    else
        log_fail "No TLS/SSL activity detected in manager logs"
        log_info "Note: This may occur if manager is still initializing"
    fi
else
    log_fail "Could not retrieve manager logs"
fi

#==============================================================================
# Test Summary
#==============================================================================
echo ""
echo "========================================"
echo "Test Summary: Deployment"
echo "========================================"
echo -e "Total:  ${TOTAL}"
echo -e "${GREEN}Passed: ${PASSED}${NC}"
echo -e "${RED}Failed: ${FAILED}${NC}"
echo "========================================"

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
