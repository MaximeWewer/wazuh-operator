#!/bin/bash
#
# Wazuh Operator Deployment Validation Script
#
# This script validates a Wazuh cluster deployment by checking:
# - Operator health
# - CRD installation
# - Cluster resources
# - Pod status
# - Service endpoints
# - Basic connectivity
#
# Usage:
#   ./validate-deployment.sh [cluster-name] [namespace]
#
# Examples:
#   ./validate-deployment.sh wazuh-minimal default
#   ./validate-deployment.sh wazuh-production wazuh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="${1:-wazuh-minimal}"
NAMESPACE="${2:-default}"
OPERATOR_NAMESPACE="wazuh-operator"
TIMEOUT=300  # 5 minutes

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is not installed or not in PATH"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    check_command kubectl

    # Check kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Check operator installation
check_operator() {
    log_info "Checking Wazuh Operator installation..."

    # Check operator namespace exists
    if ! kubectl get namespace "$OPERATOR_NAMESPACE" &> /dev/null; then
        log_error "Operator namespace '$OPERATOR_NAMESPACE' not found"
        return 1
    fi

    # Check operator deployment
    if ! kubectl get deployment -n "$OPERATOR_NAMESPACE" wazuh-operator-controller-manager &> /dev/null; then
        log_error "Operator deployment not found in namespace '$OPERATOR_NAMESPACE'"
        return 1
    fi

    # Check operator pod status
    local pod_status=$(kubectl get pods -n "$OPERATOR_NAMESPACE" -l control-plane=controller-manager \
        -o jsonpath='{.items[0].status.phase}' 2>/dev/null)

    if [ "$pod_status" != "Running" ]; then
        log_error "Operator pod is not running (status: $pod_status)"
        kubectl get pods -n "$OPERATOR_NAMESPACE"
        return 1
    fi

    # Check operator logs for errors
    local error_count=$(kubectl logs -n "$OPERATOR_NAMESPACE" \
        -l control-plane=controller-manager --tail=50 2>/dev/null | grep -c "ERROR" || true)

    if [ "$error_count" -gt 5 ]; then
        log_warning "Operator has $error_count recent errors in logs"
        log_info "Check logs with: kubectl logs -n $OPERATOR_NAMESPACE -l control-plane=controller-manager"
    fi

    log_success "Operator is running"
}

# Check CRD installation
check_crds() {
    log_info "Checking CRD installation..."

    local required_crds=(
        "wazuhclusters.wazuh.wazuh.io"
        "wazuhrules.wazuh.wazuh.io"
        "wazuhdecoders.wazuh.wazuh.io"
    )

    local missing_crds=()

    for crd in "${required_crds[@]}"; do
        if ! kubectl get crd "$crd" &> /dev/null; then
            missing_crds+=("$crd")
        fi
    done

    if [ ${#missing_crds[@]} -gt 0 ]; then
        log_error "Missing CRDs: ${missing_crds[*]}"
        return 1
    fi

    log_success "All required CRDs are installed"
}

# Check cluster resource
check_cluster_resource() {
    log_info "Checking WazuhCluster resource '$CLUSTER_NAME' in namespace '$NAMESPACE'..."

    # Check if cluster exists
    if ! kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" &> /dev/null; then
        log_error "WazuhCluster '$CLUSTER_NAME' not found in namespace '$NAMESPACE'"
        log_info "Available clusters:"
        kubectl get wazuhclusters -A
        return 1
    fi

    # Check cluster phase
    local phase=$(kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.status.phase}' 2>/dev/null)

    log_info "Cluster phase: $phase"

    if [ "$phase" = "Failed" ]; then
        log_error "Cluster is in Failed state"
        kubectl describe wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE"
        return 1
    fi

    if [ "$phase" != "Ready" ] && [ "$phase" != "Creating" ]; then
        log_warning "Cluster phase is '$phase' (expected: Ready or Creating)"
    fi

    log_success "WazuhCluster resource exists (phase: $phase)"
}

# Check pods
check_pods() {
    log_info "Checking pod status for cluster '$CLUSTER_NAME'..."

    # Get all pods for this cluster
    local pods=$(kubectl get pods -n "$NAMESPACE" \
        -l "app.kubernetes.io/instance=$CLUSTER_NAME" \
        -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

    if [ -z "$pods" ]; then
        log_warning "No pods found for cluster '$CLUSTER_NAME'"
        log_info "This may be normal if cluster is still being created"
        return 0
    fi

    log_info "Found pods: $pods"

    # Check each pod status
    local all_running=true
    local pod_count=0
    local running_count=0

    for pod in $pods; do
        ((pod_count++))
        local status=$(kubectl get pod "$pod" -n "$NAMESPACE" \
            -o jsonpath='{.status.phase}' 2>/dev/null)

        local ready=$(kubectl get pod "$pod" -n "$NAMESPACE" \
            -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)

        if [ "$status" = "Running" ] && [ "$ready" = "True" ]; then
            ((running_count++))
            log_success "Pod $pod is Running and Ready"
        else
            all_running=false
            log_warning "Pod $pod status: $status, Ready: $ready"
        fi
    done

    log_info "Pod summary: $running_count/$pod_count running and ready"

    if [ "$running_count" -eq 0 ]; then
        log_error "No pods are running"
        kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/instance=$CLUSTER_NAME"
        return 1
    fi

    if ! $all_running; then
        log_warning "Some pods are not ready yet"
        log_info "Wait for pods with: kubectl get pods -n $NAMESPACE -w"
    fi
}

# Check services
check_services() {
    log_info "Checking services for cluster '$CLUSTER_NAME'..."

    # Expected services
    local services=(
        "$CLUSTER_NAME-indexer"
        "$CLUSTER_NAME-manager-master"
        "$CLUSTER_NAME-dashboard"
    )

    local service_count=0

    for service in "${services[@]}"; do
        if kubectl get service "$service" -n "$NAMESPACE" &> /dev/null; then
            ((service_count++))

            # Get endpoint count
            local endpoints=$(kubectl get endpoints "$service" -n "$NAMESPACE" \
                -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null | wc -w)

            if [ "$endpoints" -gt 0 ]; then
                log_success "Service $service has $endpoints endpoint(s)"
            else
                log_warning "Service $service has no endpoints"
            fi
        else
            log_warning "Service $service not found (may not be created yet)"
        fi
    done

    if [ "$service_count" -eq 0 ]; then
        log_error "No services found for cluster"
        return 1
    fi
}

# Check PVCs
check_pvcs() {
    log_info "Checking PersistentVolumeClaims for cluster '$CLUSTER_NAME'..."

    local pvcs=$(kubectl get pvc -n "$NAMESPACE" \
        -l "app.kubernetes.io/instance=$CLUSTER_NAME" \
        -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

    if [ -z "$pvcs" ]; then
        log_warning "No PVCs found (may be normal for dashboard-only deployments)"
        return 0
    fi

    local all_bound=true
    local pvc_count=0
    local bound_count=0

    for pvc in $pvcs; do
        ((pvc_count++))
        local status=$(kubectl get pvc "$pvc" -n "$NAMESPACE" \
            -o jsonpath='{.status.phase}' 2>/dev/null)

        if [ "$status" = "Bound" ]; then
            ((bound_count++))
            log_success "PVC $pvc is Bound"
        else
            all_bound=false
            log_warning "PVC $pvc status: $status"
        fi
    done

    log_info "PVC summary: $bound_count/$pvc_count bound"

    if [ "$bound_count" -eq 0 ]; then
        log_error "No PVCs are bound"
        kubectl get pvc -n "$NAMESPACE" -l "app.kubernetes.io/instance=$CLUSTER_NAME"
        return 1
    fi
}

# Test basic connectivity
test_connectivity() {
    log_info "Testing basic connectivity..."

    # Find indexer pod
    local indexer_pod=$(kubectl get pods -n "$NAMESPACE" \
        -l "app.kubernetes.io/instance=$CLUSTER_NAME,wazuh.io/component=indexer" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

    if [ -z "$indexer_pod" ]; then
        log_warning "No indexer pod found, skipping connectivity test"
        return 0
    fi

    # Wait for pod to be ready
    local ready=$(kubectl get pod "$indexer_pod" -n "$NAMESPACE" \
        -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)

    if [ "$ready" != "True" ]; then
        log_warning "Indexer pod not ready, skipping connectivity test"
        return 0
    fi

    # Test indexer cluster health
    log_info "Testing indexer cluster health..."
    local health=$(kubectl exec "$indexer_pod" -n "$NAMESPACE" -- \
        curl -k -s -u admin:admin https://localhost:9200/_cluster/health 2>/dev/null | \
        grep -o '"status":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

    if [ "$health" = "green" ] || [ "$health" = "yellow" ]; then
        log_success "Indexer cluster health: $health"
    else
        log_warning "Indexer cluster health: $health (expected: green or yellow)"
    fi
}

# Wait for cluster to be ready
wait_for_ready() {
    log_info "Waiting for cluster to be ready (timeout: ${TIMEOUT}s)..."

    local elapsed=0
    local interval=10

    while [ $elapsed -lt $TIMEOUT ]; do
        local phase=$(kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" \
            -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")

        if [ "$phase" = "Ready" ]; then
            log_success "Cluster is Ready"
            return 0
        fi

        if [ "$phase" = "Failed" ]; then
            log_error "Cluster entered Failed state"
            return 1
        fi

        echo -n "."
        sleep $interval
        ((elapsed+=interval))
    done

    echo ""
    log_warning "Timeout waiting for cluster to be ready (current phase: $phase)"
}

# Generate report
generate_report() {
    log_info "=========================================="
    log_info "Deployment Validation Report"
    log_info "=========================================="
    log_info "Cluster: $CLUSTER_NAME"
    log_info "Namespace: $NAMESPACE"
    log_info "Timestamp: $(date)"
    log_info "=========================================="

    # Cluster summary
    echo ""
    log_info "Cluster Summary:"
    kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" 2>/dev/null || true

    echo ""
    log_info "Pods:"
    kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/instance=$CLUSTER_NAME" 2>/dev/null || \
        echo "No pods found"

    echo ""
    log_info "Services:"
    kubectl get services -n "$NAMESPACE" -l "app.kubernetes.io/instance=$CLUSTER_NAME" 2>/dev/null || \
        echo "No services found"

    echo ""
    log_info "PVCs:"
    kubectl get pvc -n "$NAMESPACE" -l "app.kubernetes.io/instance=$CLUSTER_NAME" 2>/dev/null || \
        echo "No PVCs found"

    echo ""
    log_info "Recent Events:"
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | \
        grep -i "$CLUSTER_NAME" | tail -10 || echo "No recent events"
}

# Main execution
main() {
    log_info "=========================================="
    log_info "Wazuh Operator Deployment Validation"
    log_info "=========================================="

    check_prerequisites
    echo ""

    check_operator
    echo ""

    check_crds
    echo ""

    check_cluster_resource
    echo ""

    check_pods
    echo ""

    check_services
    echo ""

    check_pvcs
    echo ""

    test_connectivity
    echo ""

    generate_report

    log_info "=========================================="
    log_success "Validation completed!"
    log_info "=========================================="

    # Exit code based on cluster phase
    local phase=$(kubectl get wazuhcluster "$CLUSTER_NAME" -n "$NAMESPACE" \
        -o jsonpath='{.status.phase}' 2>/dev/null)

    if [ "$phase" = "Failed" ]; then
        log_error "Cluster is in Failed state"
        exit 1
    elif [ "$phase" = "Ready" ]; then
        log_success "Cluster is Ready"
        exit 0
    else
        log_warning "Cluster is in '$phase' state (not Ready yet)"
        log_info "Monitor with: kubectl get wazuhcluster $CLUSTER_NAME -n $NAMESPACE -w"
        exit 0
    fi
}

# Run main function
main "$@"
