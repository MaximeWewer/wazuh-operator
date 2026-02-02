#!/bin/bash
set -euo pipefail

#==============================================================================
# Wazuh Operator - Local Environment Cleanup Script
#==============================================================================
# This script removes all local development resources:
# - Wazuh cluster (Helm release)
# - Wazuh operator (Helm release)
# - Minikube cluster
# - Docker images
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
MINIKUBE_PROFILE="${MINIKUBE_PROFILE:-wazuh-dev}"
OPERATOR_IMAGE="${OPERATOR_IMAGE:-wazuh-operator}"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-wazuh-system}"
CLUSTER_NAMESPACE="${CLUSTER_NAMESPACE:-wazuh}"
CLUSTER_NAME="${CLUSTER_NAME:-wazuh-cluster}"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_section() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}$*${NC}"
    echo -e "${GREEN}========================================${NC}"
}

cleanup_helm_releases() {
    log_section "Cleaning Up Helm Releases"

    # Check if kubectl context is set to minikube
    CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null || echo "")
    if [[ "${CURRENT_CONTEXT}" == "${MINIKUBE_PROFILE}" ]]; then
        # Delete cluster
        if helm list -n "${CLUSTER_NAMESPACE}" 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
            log_info "Uninstalling Wazuh Cluster: ${CLUSTER_NAME}"
            helm uninstall "${CLUSTER_NAME}" -n "${CLUSTER_NAMESPACE}" || true
            log_success "Cluster uninstalled"
        else
            log_info "Cluster not found, skipping"
        fi

        # Delete operator
        if helm list -n "${OPERATOR_NAMESPACE}" 2>/dev/null | grep -q "wazuh-operator"; then
            log_info "Uninstalling Wazuh Operator"
            helm uninstall wazuh-operator -n "${OPERATOR_NAMESPACE}" || true
            log_success "Operator uninstalled"
        else
            log_info "Operator not found, skipping"
        fi

        # Delete namespaces
        log_info "Deleting namespaces..."
        kubectl delete namespace "${CLUSTER_NAMESPACE}" --ignore-not-found=true --timeout=60s || true
        kubectl delete namespace "${OPERATOR_NAMESPACE}" --ignore-not-found=true --timeout=60s || true
    else
        log_warning "Not connected to Minikube profile ${MINIKUBE_PROFILE}, skipping Helm cleanup"
    fi
}

cleanup_minikube() {
    log_section "Cleaning Up Minikube Cluster"

    if minikube profile list 2>/dev/null | grep -q "^${MINIKUBE_PROFILE}"; then
        log_info "Deleting Minikube profile: ${MINIKUBE_PROFILE}"
        minikube delete --profile "${MINIKUBE_PROFILE}"
        log_success "Minikube cluster deleted"
    else
        log_info "Minikube profile not found, skipping"
    fi
}

cleanup_docker_images() {
    log_section "Cleaning Up Docker Images"

    log_info "Removing ${OPERATOR_IMAGE} images..."
    docker images "${OPERATOR_IMAGE}" --format "{{.Repository}}:{{.Tag}}" | while read -r image; do
        log_info "Removing: ${image}"
        docker rmi "${image}" -f || true
    done

    log_info "Removing dangling images..."
    docker image prune -f || true

    log_success "Docker images cleaned up"
}

main() {
    log_section "Wazuh Operator Local Cleanup"

    read -p "This will delete ALL local Wazuh resources. Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warning "Cleanup cancelled"
        exit 0
    fi

    cleanup_helm_releases
    cleanup_minikube
    cleanup_docker_images

    log_section "Cleanup Complete!"
    log_success "All local resources removed"

    echo ""
    log_info "To redeploy, run:"
    echo "  ./scripts/deploy-local.sh"
    echo ""
}

case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "This script removes:"
        echo "  - Helm releases (cluster and operator)"
        echo "  - Minikube cluster"
        echo "  - Docker images"
        echo ""
        echo "Environment variables:"
        echo "  MINIKUBE_PROFILE      Minikube profile (default: wazuh-dev)"
        echo "  OPERATOR_IMAGE        Image name (default: wazuh-operator)"
        echo ""
        exit 0
        ;;
    --force|-f)
        log_warning "Force mode: skipping confirmation"
        REPLY="y"
        cleanup_helm_releases
        cleanup_minikube
        cleanup_docker_images
        log_success "Force cleanup complete"
        ;;
    *)
        main "$@"
        ;;
esac
