#!/bin/bash
set -euo pipefail

#==============================================================================
# Wazuh Operator - Development CLI
#==============================================================================
# Unified CLI for all local development operations
#==============================================================================

# Resolve symlinks to get the real script location
SCRIPT_PATH="${BASH_SOURCE[0]}"
while [ -L "${SCRIPT_PATH}" ]; do
    SCRIPT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"
    SCRIPT_PATH="$(readlink "${SCRIPT_PATH}")"
    [[ ${SCRIPT_PATH} != /* ]] && SCRIPT_PATH="${SCRIPT_DIR}/${SCRIPT_PATH}"
done
SCRIPT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
 _       __                  __       ____                        __            
| |     / /___ _____  __  __/ /_     / __ \____  ___  _________ _/ /_____  _____
| | /| / / __ `/_  / / / / / __ \   / / / / __ \/ _ \/ ___/ __ `/ __/ __ \/ ___/
| |/ |/ / /_/ / / /_/ /_/ / / / /  / /_/ / /_/ /  __/ /  / /_/ / /_/ /_/ / /    
|__/|__/\__,_/ /___/\__,_/_/ /_/   \____/ .___/\___/_/   \__,_/\__/\____/_/     
                                       /_/        
        Development CLI v1.0
EOF
    echo -e "${NC}"
}

show_help() {
    show_banner
    echo -e "${GREEN}Usage:${NC} $0 <command> [options]"
    echo ""
    echo -e "${GREEN}Commands:${NC}"
    echo ""
    echo -e "  ${YELLOW}deploy${NC} [profile]   Deploy full stack (default: S)"
    echo "                       Profiles: XS, S, M, L, XL"
    echo ""
    echo -e "  ${YELLOW}status${NC}             Show deployment status"
    echo -e "  ${YELLOW}logs${NC}               Show logs and events"
    echo ""
    echo -e "  ${YELLOW}cleanup${NC}            Remove all resources"
    echo -e "  ${YELLOW}cleanup --force${NC}    Force cleanup (no confirm)"
    echo ""
    echo -e "  ${YELLOW}restart${NC}            Cleanup + Redeploy"
    echo -e "  ${YELLOW}rebuild${NC}            Rebuild image only"
    echo ""
    echo -e "  ${YELLOW}dashboard${NC}          Open dashboard in browser"
    echo -e "  ${YELLOW}port-forward${NC}       Setup port forwarding"
    echo ""
    echo -e "  ${YELLOW}logs-operator${NC}      Stream operator logs"
    echo -e "  ${YELLOW}logs-manager${NC}       Stream manager logs"
    echo -e "  ${YELLOW}logs-indexer${NC}       Stream indexer logs"
    echo -e "  ${YELLOW}logs-dashboard${NC}     Stream dashboard logs"
    echo ""
    echo -e "  ${YELLOW}shell-manager${NC}      Shell into manager pod"
    echo -e "  ${YELLOW}shell-indexer${NC}      Shell into indexer pod"
    echo ""
    echo -e "  ${YELLOW}test${NC}               Run integration tests"
    echo -e "  ${YELLOW}help${NC}               Show this help"
    echo ""
    echo -e "${GREEN}Examples:${NC}"
    echo "  $0 deploy           # Deploy with profile S"
    echo "  $0 deploy XS        # Deploy with profile XS"
    echo "  $0 status           # Check deployment status"
    echo "  $0 restart          # Full restart"
    echo "  $0 logs-operator    # Stream operator logs"
    echo ""
}

cmd_deploy() {
    local profile="${1:-S}"
    echo -e "${GREEN}Deploying Wazuh Operator with profile: ${profile}${NC}"
    SIZING_PROFILE="${profile}" "${SCRIPT_DIR}/deploy-local.sh"
}

cmd_status() {
    "${SCRIPT_DIR}/status.sh"
}

cmd_logs() {
    "${SCRIPT_DIR}/status.sh" --logs
}

cmd_cleanup() {
    local force="${1:-}"
    if [[ "${force}" == "--force" ]]; then
        "${SCRIPT_DIR}/cleanup-local.sh" --force
    else
        "${SCRIPT_DIR}/cleanup-local.sh"
    fi
}

cmd_restart() {
    echo -e "${YELLOW}Restarting: cleanup + deploy${NC}"
    "${SCRIPT_DIR}/cleanup-local.sh" --force
    echo ""
    echo -e "${GREEN}Redeploying...${NC}"
    "${SCRIPT_DIR}/deploy-local.sh"
}

cmd_rebuild() {
    echo -e "${YELLOW}Rebuilding operator image...${NC}"
    cd "${SCRIPT_DIR}/.."
    make docker-build IMG=wazuh-operator:latest
}

cmd_dashboard() {
    local profile="${MINIKUBE_PROFILE:-wazuh-dev}"
    local namespace="${CLUSTER_NAMESPACE:-wazuh}"

    echo -e "${GREEN}Opening dashboard in browser...${NC}"
    minikube service wazuh-cluster-dashboard -n "${namespace}" --profile "${profile}"
}

cmd_port_forward() {
    local namespace="${CLUSTER_NAMESPACE:-wazuh}"

    echo -e "${GREEN}Setting up port forwarding...${NC}"
    echo -e "${CYAN}Dashboard: https://localhost:5601${NC}"
    echo -e "${CYAN}Credentials: admin / MyS3cureP@ssw0rd${NC}"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    echo ""
    kubectl port-forward -n "${namespace}" svc/wazuh-cluster-dashboard 5601:5601
}

cmd_logs_operator() {
    local namespace="${OPERATOR_NAMESPACE:-wazuh-operator}"
    echo -e "${GREEN}Streaming operator logs...${NC}"
    kubectl logs -n "${namespace}" -l app.kubernetes.io/name=wazuh-operator -f
}

cmd_logs_manager() {
    local namespace="${CLUSTER_NAMESPACE:-wazuh}"
    echo -e "${GREEN}Streaming manager logs...${NC}"
    kubectl logs -n "${namespace}" -l app.kubernetes.io/component=manager-master -f
}

cmd_logs_indexer() {
    local namespace="${CLUSTER_NAMESPACE:-wazuh}"
    echo -e "${GREEN}Streaming indexer logs...${NC}"
    kubectl logs -n "${namespace}" -l app.kubernetes.io/component=indexer -f
}

cmd_logs_dashboard() {
    local namespace="${CLUSTER_NAMESPACE:-wazuh}"
    echo -e "${GREEN}Streaming dashboard logs...${NC}"
    kubectl logs -n "${namespace}" -l app.kubernetes.io/component=dashboard -f
}

cmd_shell_manager() {
    local namespace="${CLUSTER_NAMESPACE:-wazuh}"
    echo -e "${GREEN}Opening shell in manager pod...${NC}"
    kubectl exec -it -n "${namespace}" wazuh-cluster-manager-master-0 -- bash
}

cmd_shell_indexer() {
    local namespace="${CLUSTER_NAMESPACE:-wazuh}"
    echo -e "${GREEN}Opening shell in indexer pod...${NC}"
    kubectl exec -it -n "${namespace}" wazuh-cluster-indexer-0 -- bash
}

cmd_test() {
    echo -e "${GREEN}Running integration tests...${NC}"
    cd "${SCRIPT_DIR}/.."
    make test
}

main() {
    local cmd="${1:-help}"
    shift || true

    case "${cmd}" in
        deploy)
            cmd_deploy "$@"
            ;;
        status)
            cmd_status "$@"
            ;;
        logs)
            cmd_logs "$@"
            ;;
        cleanup)
            cmd_cleanup "$@"
            ;;
        restart)
            cmd_restart "$@"
            ;;
        rebuild)
            cmd_rebuild "$@"
            ;;
        dashboard)
            cmd_dashboard "$@"
            ;;
        port-forward|pf)
            cmd_port_forward "$@"
            ;;
        logs-operator|lo)
            cmd_logs_operator "$@"
            ;;
        logs-manager|lm)
            cmd_logs_manager "$@"
            ;;
        logs-indexer|li)
            cmd_logs_indexer "$@"
            ;;
        logs-dashboard|ld)
            cmd_logs_dashboard "$@"
            ;;
        shell-manager|sm)
            cmd_shell_manager "$@"
            ;;
        shell-indexer|si)
            cmd_shell_indexer "$@"
            ;;
        test)
            cmd_test "$@"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown command: ${cmd}${NC}"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
