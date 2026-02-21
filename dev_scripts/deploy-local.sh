#!/bin/bash
set -euo pipefail

#==============================================================================
# Wazuh Operator - Local Development & Testing Deployment Script
#==============================================================================
# This script automates:
# 1. Minikube cluster creation with sufficient resources
# 2. Docker image build (no cache) & load into Minikube
# 3. Old image cleanup
# 4. Operator deployment via Helm
# 5. Full Wazuh cluster deployment (all components)
# 6. Health checks and validation
#==============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Configuration
MINIKUBE_PROFILE="${MINIKUBE_PROFILE:-wazuh-dev}"
MINIKUBE_CPUS="${MINIKUBE_CPUS:-4}"
MINIKUBE_MEMORY="${MINIKUBE_MEMORY:-8192}"  # 8GB
MINIKUBE_DISK_SIZE="${MINIKUBE_DISK_SIZE:-40g}"
MINIKUBE_DRIVER="${MINIKUBE_DRIVER:-docker}"

OPERATOR_IMAGE="${OPERATOR_IMAGE:-wazuh-operator}"
OPERATOR_TAG="${OPERATOR_TAG:-dev-$(date +%s)}"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-wazuh-operator}"
CLUSTER_NAMESPACE="${CLUSTER_NAMESPACE:-wazuh}"
CLUSTER_NAME="${CLUSTER_NAME:-wazuh-cluster}"
SIZING_PROFILE="${SIZING_PROFILE:-S}"  # S, M, L, XL

# Helm values
HELM_TIMEOUT="${HELM_TIMEOUT:-10m}"

#==============================================================================
# Helper Functions
#==============================================================================

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

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Command '$1' not found. Please install it first."
        exit 1
    fi
}

#==============================================================================
# Preflight Checks
#==============================================================================

preflight_checks() {
    log_section "Preflight Checks"

    log_info "Checking required commands..."
    check_command minikube
    check_command kubectl
    check_command docker
    check_command helm
    check_command make

    log_info "Checking project structure..."
    if [[ ! -f "${PROJECT_ROOT}/Makefile" ]]; then
        log_error "Makefile not found. Are you in the project root?"
        exit 1
    fi

    if [[ ! -f "${PROJECT_ROOT}/Dockerfile" ]]; then
        log_error "Dockerfile not found in project root"
        exit 1
    fi

    if [[ ! -d "${PROJECT_ROOT}/charts/wazuh-operator" ]]; then
        log_error "Helm chart not found: charts/wazuh-operator"
        exit 1
    fi

    if [[ ! -d "${PROJECT_ROOT}/charts/wazuh-cluster" ]]; then
        log_error "Helm chart not found: charts/wazuh-cluster"
        exit 1
    fi

    log_success "Preflight checks passed"
}

#==============================================================================
# Minikube Cluster Management
#==============================================================================

setup_minikube() {
    log_section "Setting up Minikube Cluster"

    # Check if cluster already exists
    if minikube profile list 2>/dev/null | grep -q "^${MINIKUBE_PROFILE}"; then
        log_info "Minikube profile '${MINIKUBE_PROFILE}' already exists"
        read -p "Delete and recreate? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deleting existing Minikube profile..."
            minikube delete --profile "${MINIKUBE_PROFILE}"
        else
            log_info "Using existing cluster"
            minikube start --profile "${MINIKUBE_PROFILE}"
            return 0
        fi
    fi

    log_info "Creating Minikube cluster with:"
    log_info "  Profile: ${MINIKUBE_PROFILE}"
    log_info "  CPUs: ${MINIKUBE_CPUS}"
    log_info "  Memory: ${MINIKUBE_MEMORY}MB"
    log_info "  Disk: ${MINIKUBE_DISK_SIZE}"
    log_info "  Driver: ${MINIKUBE_DRIVER}"

    minikube start \
        --profile "${MINIKUBE_PROFILE}" \
        --cpus="${MINIKUBE_CPUS}" \
        --memory="${MINIKUBE_MEMORY}" \
        --disk-size="${MINIKUBE_DISK_SIZE}" \
        --driver="${MINIKUBE_DRIVER}" \
        --kubernetes-version=v1.35.0 \
        --extra-config=apiserver.service-node-port-range=1-65535

    # Set context
    kubectl config use-context "${MINIKUBE_PROFILE}"

    # Enable addons
    log_info "Enabling Minikube addons..."
    minikube addons enable storage-provisioner --profile "${MINIKUBE_PROFILE}"
    minikube addons enable default-storageclass --profile "${MINIKUBE_PROFILE}"
    minikube addons enable metrics-server --profile "${MINIKUBE_PROFILE}"

    log_success "Minikube cluster ready"
}

#==============================================================================
# Docker Image Build & Load
#==============================================================================

build_operator_image() {
    log_section "Building Operator Docker Image"

    cd "${PROJECT_ROOT}"

    # Clean old builds
    log_info "Cleaning old builds..."
    make clean || true

    # Build image with no cache
    log_info "Building Docker image: ${OPERATOR_IMAGE}:${OPERATOR_TAG}"
    log_warning "Building without cache for clean build..."

    docker build \
        --no-cache \
        --pull \
        --tag "${OPERATOR_IMAGE}:${OPERATOR_TAG}" \
        --tag "${OPERATOR_IMAGE}:latest" \
        --file Dockerfile \
        .

    log_success "Docker image built successfully"

    # Show image info
    docker images "${OPERATOR_IMAGE}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
}

load_image_to_minikube() {
    log_section "Loading Image to Minikube"

    log_info "Loading ${OPERATOR_IMAGE}:${OPERATOR_TAG} into Minikube..."
    minikube image load "${OPERATOR_IMAGE}:${OPERATOR_TAG}" --profile "${MINIKUBE_PROFILE}"

    log_info "Loading ${OPERATOR_IMAGE}:latest into Minikube..."
    minikube image load "${OPERATOR_IMAGE}:latest" --profile "${MINIKUBE_PROFILE}"

    # Verify images in Minikube
    log_info "Verifying images in Minikube..."
    minikube ssh --profile "${MINIKUBE_PROFILE}" -- docker images | grep "${OPERATOR_IMAGE}" || true

    log_success "Images loaded to Minikube"
}

cleanup_old_images() {
    log_section "Cleaning Up Old Images"

    log_info "Removing dangling Docker images..."
    docker image prune -f || true

    log_info "Listing all wazuh-operator images:"
    docker images "${OPERATOR_IMAGE}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

    # Keep only latest and current tag, remove others
    log_info "Cleaning up old tagged images (keeping latest and ${OPERATOR_TAG})..."
    docker images "${OPERATOR_IMAGE}" --format "{{.Tag}}" | \
        grep -v "^latest$" | \
        grep -v "^${OPERATOR_TAG}$" | \
        grep -v "^<none>$" | \
        while read -r tag; do
            log_info "Removing old image: ${OPERATOR_IMAGE}:${tag}"
            docker rmi "${OPERATOR_IMAGE}:${tag}" || true
        done || true

    log_success "Cleanup completed"
}

#==============================================================================
# Operator Deployment
#==============================================================================

deploy_operator() {
    log_section "Deploying Wazuh Operator via Helm"

    cd "${PROJECT_ROOT}"

    # Create namespace
    log_info "Creating operator namespace: ${OPERATOR_NAMESPACE}"
    kubectl create namespace "${OPERATOR_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

    # Delete if already exists
    log_info "Cleaning up previous operator resources (if any)..."
    helm template wazuh-operator ./charts/wazuh-operator \
        --namespace "${OPERATOR_NAMESPACE}" 2>/dev/null | kubectl delete -f - 2>/dev/null || true
    sleep 5

    # Install operator
    log_info "Installing Wazuh Operator Helm chart..."
    helm template wazuh-operator \
        ./charts/wazuh-operator \
        --namespace "${OPERATOR_NAMESPACE}" \
        --set operator.image.repository="${OPERATOR_IMAGE}" \
        --set operator.image.tag="${OPERATOR_TAG}" \
        --set operator.image.pullPolicy=Never \
        | kubectl apply --server-side -f -

    log_success "Operator deployed successfully"

    # Wait for operator to be ready
    log_info "Waiting for operator to be ready..."
    kubectl wait --for=condition=available --timeout=300s \
        deployment/wazuh-operator-controller-manager \
        -n "${OPERATOR_NAMESPACE}"

    # Show operator pod
    log_info "Operator pod status:"
    kubectl get pods -n "${OPERATOR_NAMESPACE}" -l app.kubernetes.io/name=wazuh-operator

    # Show operator logs (last 20 lines)
    log_info "Operator logs (last 20 lines):"
    kubectl logs -n "${OPERATOR_NAMESPACE}" \
        -l app.kubernetes.io/name=wazuh-operator \
        --tail=20 || true
}

#==============================================================================
# Wazuh Cluster Deployment
#==============================================================================

deploy_wazuh_cluster() {
    log_section "Deploying Wazuh Cluster (Profile: ${SIZING_PROFILE})"

    cd "${PROJECT_ROOT}"

    # Create namespace
    log_info "Creating cluster namespace: ${CLUSTER_NAMESPACE}"
    kubectl create namespace "${CLUSTER_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

    # Delete if already exists
    log_info "Cleaning up previous cluster resources (if any)..."
    helm template "${CLUSTER_NAME}" ./charts/wazuh-cluster \
        --namespace "${CLUSTER_NAMESPACE}" 2>/dev/null | kubectl delete -f - 2>/dev/null || true
    sleep 10

    # Install cluster
    log_info "Installing Wazuh Cluster Helm chart with sizing profile: ${SIZING_PROFILE}"
    log_info "Cluster components:"
    log_info "  - Manager Master (1 replica)"
    log_info "  - Manager Workers (1 replica for profile S)"
    log_info "  - Indexer (1 replica for profile S)"
    log_info "  - Dashboard (1 replica)"

    helm template "${CLUSTER_NAME}" \
        ./charts/wazuh-cluster \
        --namespace "${CLUSTER_NAMESPACE}" \
        --set sizing.profile="${SIZING_PROFILE}" \
        --set cluster.name="${CLUSTER_NAME}" \
        --set namespace="${CLUSTER_NAMESPACE}" \
        --set secrets.wazuhApi.password="MyS3cureP@ssw0rd" \
        --set secrets.indexerAdmin.password="MyS3cureP@ssw0rd" \
        --set secrets.wazuhAuthd.password="MyS3cureP@ssw0rd" \
        | kubectl apply --server-side -f -

    log_success "Wazuh Cluster deployed successfully"
}

#==============================================================================
# Health Checks & Validation
#==============================================================================

wait_for_cluster_ready() {
    log_section "Waiting for Cluster Components to be Ready"

    log_info "Waiting for WazuhCluster CR to be created..."
    kubectl wait --for=condition=Ready --timeout=600s \
        wazuhcluster/"${CLUSTER_NAME}" \
        -n "${CLUSTER_NAMESPACE}" || true

    log_info "Waiting for Manager Master StatefulSet..."
    kubectl wait --for=condition=ready --timeout=600s \
        pod -l app.kubernetes.io/component=manager-master \
        -n "${CLUSTER_NAMESPACE}" || true

    log_info "Waiting for Indexer StatefulSet..."
    kubectl wait --for=condition=ready --timeout=600s \
        pod -l app.kubernetes.io/component=indexer \
        -n "${CLUSTER_NAMESPACE}" || true

    log_info "Waiting for Dashboard Deployment..."
    kubectl wait --for=condition=ready --timeout=600s \
        pod -l app.kubernetes.io/component=dashboard \
        -n "${CLUSTER_NAMESPACE}" || true

    log_success "All components ready"
}

show_cluster_status() {
    log_section "Cluster Status"

    log_info "WazuhCluster CR:"
    kubectl get wazuhcluster -n "${CLUSTER_NAMESPACE}" -o wide || true

    log_info ""
    log_info "Pods:"
    kubectl get pods -n "${CLUSTER_NAMESPACE}" -o wide

    log_info ""
    log_info "Services:"
    kubectl get svc -n "${CLUSTER_NAMESPACE}"

    log_info ""
    log_info "PersistentVolumeClaims:"
    kubectl get pvc -n "${CLUSTER_NAMESPACE}"

    log_info ""
    log_info "StatefulSets:"
    kubectl get statefulsets -n "${CLUSTER_NAMESPACE}"

    log_info ""
    log_info "Deployments:"
    kubectl get deployments -n "${CLUSTER_NAMESPACE}"
}

get_dashboard_url() {
    log_section "Access Information"

    # Get dashboard service
    DASHBOARD_SVC=$(kubectl get svc -n "${CLUSTER_NAMESPACE}" -l app.kubernetes.io/component=dashboard -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [[ -n "${DASHBOARD_SVC}" ]]; then
        log_info "To access the Wazuh Dashboard, run:"
        echo ""
        echo -e "${GREEN}  minikube service ${DASHBOARD_SVC} -n ${CLUSTER_NAMESPACE} --profile ${MINIKUBE_PROFILE}${NC}"
        echo ""
        log_info "Or port-forward:"
        echo ""
        echo -e "${GREEN}  kubectl port-forward -n ${CLUSTER_NAMESPACE} svc/${DASHBOARD_SVC} 5601:5601${NC}"
        echo ""
        echo -e "${GREEN}  Then access: https://localhost:5601${NC}"
        echo ""
        log_info "Default credentials:"
        echo -e "${YELLOW}  Username: admin${NC}"
        echo -e "${YELLOW}  Password: MyS3cureP@ssw0rd${NC}"
    else
        log_warning "Dashboard service not found"
    fi
}

#==============================================================================
# Main Execution
#==============================================================================

main() {
    log_section "Wazuh Operator Local Deployment"
    log_info "Starting automated deployment..."
    log_info "Profile: ${MINIKUBE_PROFILE}"
    log_info "Sizing: ${SIZING_PROFILE}"

    # Run steps
    preflight_checks
    setup_minikube
    build_operator_image
    load_image_to_minikube
    cleanup_old_images
    deploy_operator
    deploy_wazuh_cluster
    wait_for_cluster_ready
    show_cluster_status
    get_dashboard_url

    log_section "Deployment Complete!"
    log_success "Wazuh Operator and Cluster deployed successfully"

    echo ""
    log_info "Useful commands:"
    echo ""
    echo "  # View operator logs:"
    echo "  kubectl logs -n ${OPERATOR_NAMESPACE} -l app.kubernetes.io/name=wazuh-operator -f"
    echo ""
    echo "  # View cluster status:"
    echo "  kubectl get wazuhcluster -n ${CLUSTER_NAMESPACE}"
    echo ""
    echo "  # View all resources:"
    echo "  kubectl get all -n ${CLUSTER_NAMESPACE}"
    echo ""
    echo "  # Delete cluster:"
    echo "  helm template ${CLUSTER_NAME} ./charts/wazuh-cluster --namespace ${CLUSTER_NAMESPACE} | kubectl delete -f -"
    echo ""
    echo "  # Delete operator:"
    echo "  helm template wazuh-operator ./charts/wazuh-operator --namespace ${OPERATOR_NAMESPACE} | kubectl delete -f -"
    echo ""
    echo "  # Delete Minikube cluster:"
    echo "  minikube delete --profile ${MINIKUBE_PROFILE}"
    echo ""
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Environment variables:"
        echo "  MINIKUBE_PROFILE      Minikube profile name (default: wazuh-dev)"
        echo "  MINIKUBE_CPUS         Number of CPUs (default: 4)"
        echo "  MINIKUBE_MEMORY       Memory in MB (default: 8192)"
        echo "  MINIKUBE_DISK_SIZE    Disk size (default: 40g)"
        echo "  SIZING_PROFILE        Cluster size: S, M, L, XL (default: S)"
        echo "  OPERATOR_TAG          Image tag (default: dev-<timestamp>)"
        echo ""
        echo "Example:"
        echo "  SIZING_PROFILE=S $0"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
