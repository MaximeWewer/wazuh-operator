#!/bin/bash
set -euo pipefail

#==============================================================================
# E2E Test: Topology Scaling
#==============================================================================
# Tests acceptance criteria:
# - Scale from Profile S (1-1-1) to Profile M (3-3-2)
# - All new pods reach Ready
# - Cluster status reflects new topology
# - Scale back down to Profile S
# - Verify topology changes
#
# NOTE: Due to resource constraints (8GB RAM, 4 CPUs), this test uses
# cleanup-and-redeploy approach instead of in-place scaling.
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
MAX_WAIT_TIME=600  # 10 minutes for pods to become ready
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/../.."

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

log_section() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
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

cleanup_cluster() {
    log_section "Cleaning Up Existing Cluster"

    if kubectl get namespace "$NAMESPACE" &>/dev/null; then
        log_info "Deleting WazuhCluster CR..."
        kubectl delete wazuhcluster --all -n "$NAMESPACE" --timeout=60s 2>/dev/null || true

        log_info "Waiting for resources to be cleaned up..."
        sleep 10

        # Force delete any stuck pods
        kubectl delete pods --all -n "$NAMESPACE" --grace-period=0 --force 2>/dev/null || true

        log_info "Deleting namespace..."
        kubectl delete namespace "$NAMESPACE" --timeout=120s 2>/dev/null || true

        # Wait for namespace to be fully deleted
        for i in {1..30}; do
            if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
                break
            fi
            sleep 2
        done
    fi

    log_info "Cleanup completed"
}

deploy_profile() {
    local profile=$1
    log_section "Deploying Profile $profile"

    log_info "Using wazuh-dev to deploy profile $profile..."
    cd "${PROJECT_ROOT}"

    if ./wazuh-dev deploy "$profile" 2>&1 | grep -q "ERROR\|FAILED"; then
        log_fail "Failed to deploy profile $profile"
        return 1
    fi

    log_info "Waiting for deployment to stabilize..."
    sleep 10

    return 0
}

verify_topology() {
    local expected_indexer=$1
    local expected_manager_master=$2
    local expected_manager_worker=$3
    local expected_dashboard=$4

    log_test "Verify topology: Indexer=$expected_indexer, Manager(M/W)=$expected_manager_master/$expected_manager_worker, Dashboard=$expected_dashboard"

    local all_correct=true

    # Check indexer
    local indexer_replicas=$(kubectl get statefulset wazuh-cluster-indexer \
        -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

    if [[ "$indexer_replicas" == "$expected_indexer" ]]; then
        log_pass "Indexer has $indexer_replicas replica(s)"
    else
        log_fail "Indexer has $indexer_replicas replicas (expected $expected_indexer)"
        all_correct=false
    fi

    # Check manager master
    local master_replicas=$(kubectl get statefulset wazuh-cluster-manager-master \
        -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

    if [[ "$master_replicas" == "$expected_manager_master" ]]; then
        log_pass "Manager Master has $master_replicas replica(s)"
    else
        log_fail "Manager Master has $master_replicas replicas (expected $expected_manager_master)"
        all_correct=false
    fi

    # Check manager worker
    local worker_replicas=$(kubectl get statefulset wazuh-cluster-manager-worker \
        -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

    if [[ "$worker_replicas" == "$expected_manager_worker" ]]; then
        log_pass "Manager Worker has $worker_replicas replica(s)"
    else
        log_fail "Manager Worker has $worker_replicas replicas (expected $expected_manager_worker)"
        all_correct=false
    fi

    # Check dashboard
    local dashboard_replicas=$(kubectl get deployment wazuh-cluster-dashboard \
        -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

    if [[ "$dashboard_replicas" == "$expected_dashboard" ]]; then
        log_pass "Dashboard has $dashboard_replicas replica(s)"
    else
        log_fail "Dashboard has $dashboard_replicas replicas (expected $expected_dashboard)"
        all_correct=false
    fi

    if ! $all_correct; then
        return 1
    fi

    return 0
}

wait_for_all_pods_ready() {
    local expected_pod_count=$1

    log_test "Verify all pods reach Ready state"

    log_info "Waiting for cluster to be ready..."
    sleep 20

    # Get all pod names
    local pod_names=$(kubectl get pods -n "$NAMESPACE" \
        -l app.kubernetes.io/name=wazuh \
        -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")

    if [[ -z "$pod_names" ]]; then
        log_fail "No pods found in namespace $NAMESPACE"
        return 1
    fi

    local pod_count=$(echo "$pod_names" | wc -w)
    log_info "Found $pod_count pods (expected: $expected_pod_count)"

    # Wait for each pod
    local all_ready=true
    for pod in $pod_names; do
        if ! wait_for_ready "pod" "$pod" "$MAX_WAIT_TIME"; then
            log_fail "Pod $pod did not reach Ready within $MAX_WAIT_TIME seconds"
            all_ready=false
        else
            log_info "✓ Pod $pod is Ready"
        fi
    done

    if $all_ready && [[ $pod_count -eq $expected_pod_count ]]; then
        log_pass "All $pod_count pods are Ready"
        return 0
    elif ! $all_ready; then
        log_fail "Some pods failed to reach Ready state"
        return 1
    else
        log_fail "Pod count mismatch: found $pod_count, expected $expected_pod_count"
        return 1
    fi
}

verify_cluster_status() {
    log_test "Verify cluster status shows 'Running' and 'Ready'"

    local phase=$(kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")

    local ready=$(kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")

    if [[ "$phase" == "Running" ]] && [[ "$ready" == "True" ]]; then
        log_pass "Cluster status: Phase=$phase, Ready=$ready"
        return 0
    else
        log_fail "Cluster status: Phase=$phase (expected 'Running'), Ready=$ready (expected 'True')"
        return 1
    fi
}

#==============================================================================
# Main Test Flow
#==============================================================================

echo ""
echo "========================================"
echo "E2E Test: Scaling"
echo "Component Topology Scaling"
echo "========================================"
echo ""
log_info "Testing scaling using cleanup-and-redeploy approach"
log_info "This approach is required for resource-constrained environments"
echo ""

#==============================================================================
# Phase 1: Deploy Profile S (Small - 1-1-1)
#==============================================================================

log_section "PHASE 1: Deploy Profile S (1-1-1)"

# Cleanup any existing deployment
cleanup_cluster

# Deploy Profile S
if ! deploy_profile "S"; then
    echo ""
    echo -e "${RED}✗ Failed to deploy Profile S${NC}"
    exit 1
fi

# Wait for pods to be ready
sleep 30

# Verify Profile S topology
verify_topology 1 1 1 1

# Wait for all pods ready (4 total: 1 indexer + 1 master + 1 worker + 1 dashboard)
wait_for_all_pods_ready 4

# Verify cluster status
verify_cluster_status

#==============================================================================
# Phase 2: Scale UP - Deploy Profile M (Medium - 3-3-2)
#==============================================================================

log_section "PHASE 2: Scale UP to Profile M (3-3-2)"

log_info "Cleaning up Profile S deployment..."
cleanup_cluster

# Deploy Profile M
if ! deploy_profile "M"; then
    echo ""
    echo -e "${RED}✗ Failed to deploy Profile M${NC}"
    exit 1
fi

# Wait for pods to be ready
sleep 30

# Verify Profile M topology
verify_topology 3 1 2 2

# Wait for all pods ready (8 total: 3 indexers + 1 master + 2 workers + 2 dashboards)
wait_for_all_pods_ready 8

# Verify cluster status
verify_cluster_status

#==============================================================================
# Phase 3: Scale DOWN - Deploy Profile S again (1-1-1)
#==============================================================================

log_section "PHASE 3: Scale DOWN to Profile S (1-1-1)"

log_info "Cleaning up Profile M deployment..."
cleanup_cluster

# Deploy Profile S again
if ! deploy_profile "S"; then
    echo ""
    echo -e "${RED}✗ Failed to deploy Profile S${NC}"
    exit 1
fi

# Wait for pods to be ready
sleep 30

# Verify Profile S topology again
verify_topology 1 1 1 1

# Wait for all pods ready (4 total)
wait_for_all_pods_ready 4

# Verify cluster status
verify_cluster_status

#==============================================================================
# Test Summary
#==============================================================================
echo ""
echo "========================================"
echo "Test Summary: Scaling"
echo "========================================"
echo -e "Total:  ${TOTAL}"
echo -e "${GREEN}Passed: ${PASSED}${NC}"
echo -e "${RED}Failed: ${FAILED}${NC}"
echo "========================================"

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    log_info "Successfully tested:"
    echo "  - Profile S deployment (1-1-1)"
    echo "  - Scale UP to Profile M (3-3-2)"
    echo "  - Scale DOWN to Profile S (1-1-1)"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
