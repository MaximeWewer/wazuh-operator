#!/bin/bash
set -euo pipefail

#==============================================================================
# Wazuh Operator - Status Check Script
#==============================================================================
# Quick status overview of the local deployment
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
MINIKUBE_PROFILE="${MINIKUBE_PROFILE:-wazuh-dev}"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-wazuh-operator}"
CLUSTER_NAMESPACE="${CLUSTER_NAMESPACE:-wazuh}"
CLUSTER_NAME="${CLUSTER_NAME:-wazuh-cluster}"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $*"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*"
}

log_section() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}$*${NC}"
    echo -e "${GREEN}========================================${NC}"
}

check_minikube() {
    log_section "Minikube Status"

    if ! command -v minikube &> /dev/null; then
        log_error "Minikube not installed"
        return 1
    fi

    if minikube profile list 2>/dev/null | grep -q "^${MINIKUBE_PROFILE}"; then
        log_success "Minikube profile exists: ${MINIKUBE_PROFILE}"

        STATUS=$(minikube status --profile "${MINIKUBE_PROFILE}" --format='{{.Host}}' 2>/dev/null || echo "Unknown")
        if [[ "${STATUS}" == "Running" ]]; then
            log_success "Minikube is running"
        else
            log_warning "Minikube status: ${STATUS}"
        fi

        # Show resources
        log_info "Resources:"
        minikube profile list | grep "${MINIKUBE_PROFILE}" || true
    else
        log_error "Minikube profile not found: ${MINIKUBE_PROFILE}"
        return 1
    fi
}

check_kubectl_context() {
    log_section "Kubectl Context"

    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not installed"
        return 1
    fi

    CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null || echo "none")
    if [[ "${CURRENT_CONTEXT}" == "${MINIKUBE_PROFILE}" ]]; then
        log_success "Connected to Minikube: ${MINIKUBE_PROFILE}"
    else
        log_warning "Not connected to ${MINIKUBE_PROFILE}, current: ${CURRENT_CONTEXT}"
        log_info "Run: kubectl config use-context ${MINIKUBE_PROFILE}"
    fi
}

check_operator() {
    log_section "Operator Status"

    # Check namespace
    if kubectl get namespace "${OPERATOR_NAMESPACE}" &>/dev/null; then
        log_success "Namespace exists: ${OPERATOR_NAMESPACE}"
    else
        log_error "Namespace not found: ${OPERATOR_NAMESPACE}"
        return 1
    fi

    # Check Helm release
    if helm list -n "${OPERATOR_NAMESPACE}" 2>/dev/null | grep -q "wazuh-operator"; then
        log_success "Helm release found: wazuh-operator"
        helm list -n "${OPERATOR_NAMESPACE}" | grep "wazuh-operator"
    else
        log_error "Helm release not found: wazuh-operator"
        return 1
    fi

    # Check deployment
    if kubectl get deployment wazuh-operator-controller-manager -n "${OPERATOR_NAMESPACE}" &>/dev/null; then
        READY=$(kubectl get deployment wazuh-operator-controller-manager -n "${OPERATOR_NAMESPACE}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        DESIRED=$(kubectl get deployment wazuh-operator-controller-manager -n "${OPERATOR_NAMESPACE}" -o jsonpath='{.status.replicas}' 2>/dev/null || echo "0")

        if [[ "${READY}" == "${DESIRED}" ]] && [[ "${READY}" -gt 0 ]]; then
            log_success "Operator deployment ready: ${READY}/${DESIRED}"
        else
            log_warning "Operator deployment not ready: ${READY}/${DESIRED}"
        fi

        # Show pods
        log_info "Operator pods:"
        kubectl get pods -n "${OPERATOR_NAMESPACE}" -l app.kubernetes.io/name=wazuh-operator
    else
        log_error "Operator deployment not found"
        return 1
    fi
}

check_cluster() {
    log_section "Wazuh Cluster Status"

    # Check namespace
    if kubectl get namespace "${CLUSTER_NAMESPACE}" &>/dev/null; then
        log_success "Namespace exists: ${CLUSTER_NAMESPACE}"
    else
        log_error "Namespace not found: ${CLUSTER_NAMESPACE}"
        return 1
    fi

    # Check Helm release
    if helm list -n "${CLUSTER_NAMESPACE}" 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
        log_success "Helm release found: ${CLUSTER_NAME}"
        helm list -n "${CLUSTER_NAMESPACE}" | grep "${CLUSTER_NAME}"
    else
        log_error "Helm release not found: ${CLUSTER_NAME}"
        return 1
    fi

    # Check WazuhCluster CR
    if kubectl get wazuhcluster "${CLUSTER_NAME}" -n "${CLUSTER_NAMESPACE}" &>/dev/null; then
        log_success "WazuhCluster CR exists: ${CLUSTER_NAME}"

        # Check ready condition
        READY=$(kubectl get wazuhcluster "${CLUSTER_NAME}" -n "${CLUSTER_NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
        if [[ "${READY}" == "True" ]]; then
            log_success "Cluster is Ready"
        else
            log_warning "Cluster not ready, status: ${READY}"
        fi

        # Show cluster
        echo ""
        kubectl get wazuhcluster "${CLUSTER_NAME}" -n "${CLUSTER_NAMESPACE}" -o wide
    else
        log_error "WazuhCluster CR not found: ${CLUSTER_NAME}"
        return 1
    fi

    # Check components
    log_info ""
    log_info "Components:"

    # Manager Master
    if kubectl get statefulset "${CLUSTER_NAME}-manager-master" -n "${CLUSTER_NAMESPACE}" &>/dev/null; then
        READY=$(kubectl get statefulset "${CLUSTER_NAME}-manager-master" -n "${CLUSTER_NAMESPACE}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        DESIRED=$(kubectl get statefulset "${CLUSTER_NAME}-manager-master" -n "${CLUSTER_NAMESPACE}" -o jsonpath='{.status.replicas}' 2>/dev/null || echo "0")

        if [[ "${READY}" == "${DESIRED}" ]] && [[ "${READY}" -gt 0 ]]; then
            log_success "Manager Master: ${READY}/${DESIRED}"
        else
            log_warning "Manager Master: ${READY}/${DESIRED}"
        fi
    else
        log_error "Manager Master not found"
    fi

    # Indexer
    if kubectl get statefulset "${CLUSTER_NAME}-indexer" -n "${CLUSTER_NAMESPACE}" &>/dev/null; then
        READY=$(kubectl get statefulset "${CLUSTER_NAME}-indexer" -n "${CLUSTER_NAMESPACE}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        DESIRED=$(kubectl get statefulset "${CLUSTER_NAME}-indexer" -n "${CLUSTER_NAMESPACE}" -o jsonpath='{.status.replicas}' 2>/dev/null || echo "0")

        if [[ "${READY}" == "${DESIRED}" ]] && [[ "${READY}" -gt 0 ]]; then
            log_success "Indexer: ${READY}/${DESIRED}"
        else
            log_warning "Indexer: ${READY}/${DESIRED}"
        fi
    else
        log_error "Indexer not found"
    fi

    # Dashboard
    if kubectl get deployment "${CLUSTER_NAME}-dashboard" -n "${CLUSTER_NAMESPACE}" &>/dev/null; then
        READY=$(kubectl get deployment "${CLUSTER_NAME}-dashboard" -n "${CLUSTER_NAMESPACE}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        DESIRED=$(kubectl get deployment "${CLUSTER_NAME}-dashboard" -n "${CLUSTER_NAMESPACE}" -o jsonpath='{.status.replicas}' 2>/dev/null || echo "0")

        if [[ "${READY}" == "${DESIRED}" ]] && [[ "${READY}" -gt 0 ]]; then
            log_success "Dashboard: ${READY}/${DESIRED}"
        else
            log_warning "Dashboard: ${READY}/${DESIRED}"
        fi
    else
        log_error "Dashboard not found"
    fi

    # Show all pods
    log_info ""
    log_info "All pods:"
    kubectl get pods -n "${CLUSTER_NAMESPACE}"
}

check_resources() {
    log_section "Resource Usage"

    if kubectl top nodes &>/dev/null; then
        log_info "Node resources:"
        kubectl top nodes
    else
        log_warning "Metrics not available (metrics-server not ready?)"
    fi

    log_info ""
    log_info "PVCs:"
    kubectl get pvc -n "${CLUSTER_NAMESPACE}" 2>/dev/null || log_info "No PVCs found"
}

show_access_info() {
    log_section "Access Information"

    # Dashboard service
    DASHBOARD_SVC=$(kubectl get svc -n "${CLUSTER_NAMESPACE}" -l app.kubernetes.io/component=dashboard -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [[ -n "${DASHBOARD_SVC}" ]]; then
        log_info "Dashboard access:"
        echo ""
        echo -e "  ${GREEN}minikube service ${DASHBOARD_SVC} -n ${CLUSTER_NAMESPACE} --profile ${MINIKUBE_PROFILE}${NC}"
        echo ""
        echo "  Or port-forward:"
        echo -e "  ${GREEN}kubectl port-forward -n ${CLUSTER_NAMESPACE} svc/${DASHBOARD_SVC} 5601:5601${NC}"
        echo ""
        echo "  Credentials:"
        echo -e "  ${YELLOW}Username: admin${NC}"
        echo -e "  ${YELLOW}Password: MyS3cureP@ssw0rd${NC}"
    fi
}

show_logs() {
    log_section "Recent Logs"

    log_info "Operator logs (last 10 lines):"
    kubectl logs -n "${OPERATOR_NAMESPACE}" \
        -l app.kubernetes.io/name=wazuh-operator \
        --tail=10 2>/dev/null || log_warning "No operator logs available"

    log_info ""
    log_info "Recent events in ${CLUSTER_NAMESPACE}:"
    kubectl get events -n "${CLUSTER_NAMESPACE}" \
        --sort-by='.lastTimestamp' \
        --field-selector type=Warning \
        2>/dev/null | tail -5 || log_info "No recent warnings"
}

main() {
    log_section "Wazuh Operator - Status Check"
    log_info "Profile: ${MINIKUBE_PROFILE}"

    check_minikube || true
    check_kubectl_context || true
    check_operator || true
    check_cluster || true
    check_resources || true
    show_access_info || true

    if [[ "${1:-}" == "--logs" ]]; then
        show_logs || true
    fi

    log_section "Status Check Complete"

    echo ""
    log_info "For more details:"
    echo "  $0 --logs    # Show logs and events"
    echo ""
}

case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --logs    Show recent logs and events"
        echo "  --help    Show this help message"
        echo ""
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
