# Project Overview

## Executive Summary

**Wazuh Operator** is a Kubernetes operator for managing Wazuh security monitoring platform deployments. It provides declarative management of Wazuh clusters through Custom Resource Definitions (CRDs), enabling automated deployment, configuration, and lifecycle management of Wazuh components on Kubernetes.

## Project Information

- **Name**: wazuh-operator
- **Purpose**: Kubernetes operator for Wazuh security platform
- **License**: Apache License 2.0
- **Repository**: <https://github.com/MaximeWewer/wazuh-operator>
- **Language**: Go 1.26.0
- **Framework**: Kubebuilder v4 with controller-runtime
- **Target**: Kubernetes 1.25+

## Technology Stack

For detailed technology decisions and justifications, see [Technology Stack](technology-stack.md).

**Key Technologies**: Go 1.26.0, Kubebuilder v4, controller-runtime, Ginkgo/Gomega, Prometheus, OpenTelemetry

## Architecture Type

**Kubernetes Operator Pattern (Reconciliation-Based)**

The operator follows the standard Kubernetes operator pattern with:

- 22 Custom Resource Definitions (CRDs)
- 22 reconciliation controllers
- Declarative resource management
- Continuous reconciliation loops
- Event-driven architecture

## Repository Structure

**Type**: Monolith (single cohesive codebase)

**Organization**: Layered architecture

- **API Layer** (`api/v1/`): CRD type definitions (v1 storage version)
- **Controller Layer** (`controllers/`): Main reconciliation controllers
- **Business Logic Layer** (`internal/wazuh/`, `internal/opensearch/`): Domain-specific implementations
- **Cross-Cutting Layer** (`internal/certificates/`, `internal/networking/`, `internal/shared/`): Shared concerns
- **Validation Layer** (`internal/validation/`): CRD validation logic
- **Telemetry Layer** (`internal/telemetry/`): OpenTelemetry tracing
- **Public API Layer** (`pkg/`): Stable public packages (constants, config, dns, logging, version, versions)
- **Resource Builders** (`internal/*/builder/`): Kubernetes resource generation
- **Entry Point** (`cmd/wazuh-operator/`): Application startup

## Key Features

### Core Functionality

- **Declarative Cluster Management**: Define entire Wazuh cluster via YAML
- **Automated Deployment**: Provisions Manager, Indexer, and Dashboard automatically
- **Component Management**: 23 CRDs covering all aspects of Wazuh deployment

### Wazuh Management

- **Rule & Decoder Management**: Declarative Wazuh detection rules and log decoders
- **Filebeat Configuration**: Automated log forwarding configuration
- **Certificate Management**: Auto-generated TLS certificates with hot reload (Wazuh 4.9+)
- **Log Rotation**: Automated log cleanup via CronJob

### OpenSearch Integration

- **Security Management**: Users, roles, role mappings, tenants, action groups
- **Index Management**: Index templates, component templates, ISM policies
- **Backup & Restore**: Snapshot repositories, scheduled/manual snapshots, point-in-time restore
- **Advanced Topology**: NodePools with dedicated roles (master, data, ingest, ml, coordinating)

### Operational Features

- **High Availability**: Multi-node deployments with pod disruption budgets
- **Monitoring**: Prometheus exporters and ServiceMonitor integration
- **Drain Strategy**: Safe scale-down with drain coordination
- **Volume Expansion**: Dynamic PVC size increases
- **Upgrade Management**: Rolling updates with zero-downtime

### Deployment Options

- **Helm Charts**: Operator chart + Cluster chart
- **kubectl**: Direct manifest deployment
- **Inline Mode**: Define components directly in WazuhCluster CR

## Project Statistics

- **CRDs**: 22 Custom Resource Definitions
- **Controllers**: 22 Kubernetes controllers
- **Go Packages**: 30+ internal packages, 6 public packages
- **Lines of Code**: ~50,000+ (estimated)
- **Documentation Files**: 53+ markdown files
- **Test Files**: Unit, integration (envtest), and E2E tests with Ginkgo/Gomega

## Managed Resources

The operator creates and manages:

- **StatefulSets**: Wazuh Manager (master/workers), OpenSearch Indexer
- **Deployments**: OpenSearch Dashboard
- **Services**: ClusterIP for inter-component communication
- **ConfigMaps**: Configuration files (ossec.conf, opensearch.yml, etc.)
- **Secrets**: TLS certificates, credentials, tokens
- **PersistentVolumeClaims**: Data storage for stateful components
- **Jobs/CronJobs**: Backups, restores, init tasks
- **ServiceMonitors/PodMonitors**: Prometheus monitoring
- **PodDisruptionBudgets**: High availability

## Target Environment

- **Kubernetes**: 1.25+ (tested on 1.25-1.30)
- **Resources**: 16GB+ RAM recommended
- **Storage**: Dynamic PersistentVolume provisioning required
- **Networking**: ClusterIP services, optional Ingress
- **Monitoring**: Optional Prometheus Operator integration

## Development Status

**Current Version**: v1 (storage version)

**Completed Features**:

- Core operator functionality
- All 23 CRDs implemented
- TLS with auto-generation and hot reload
- Prometheus monitoring integration
- Advanced indexer topology (NodePools)
- Drain strategy for safe scale-down
- Volume expansion (PVC resizing)
- Comprehensive backup & restore (OpenSearch + Wazuh Manager)
- Helm charts (operator + cluster)
- OpenTelemetry distributed tracing
- API v1 migration (stable storage version)
- Gateway API support (HTTPRoute, TCPRoute, UDPRoute)
- Ingress support (networkingv1.Ingress)
- NetworkPolicies
- Admission webhooks (validation + mutation)
- Custom certificates (BYO certs)
- Multiple WazuhCluster support (across namespaces or within same namespace)

## Getting Started

### Quick Installation

```bash
# Install operator
helm template wazuh-operator oci://ghcr.io/maximewewer/charts/wazuh-operator \
  --namespace wazuh-operator | kubectl apply -f -

# Deploy Wazuh cluster
helm template wazuh-cluster oci://ghcr.io/maximewewer/charts/wazuh-cluster \
  --namespace wazuh | kubectl apply -f -
```

### Development

```bash
# Clone repository
git clone https://github.com/MaximeWewer/wazuh-operator.git

# Build operator
cd wazuh-operator
make build

# Run locally
make install run
```

## Documentation Structure

- **User Documentation** (`docs/usage/`):

  - Getting started guides
  - Feature documentation
  - Examples and troubleshooting
  - Complete CRD reference

- **Developer Documentation** (`docs/dev/`):
  - Architecture design
  - Testing guides
  - Contributing guidelines
  - Code style conventions

## Support & Resources

- **GitHub Repository**: <https://github.com/MaximeWewer/wazuh-operator>
- **Issues**: <https://github.com/MaximeWewer/wazuh-operator/issues>
- **Wazuh Documentation**: <https://documentation.wazuh.com/>
- **Wazuh Community**: <https://groups.google.com/g/wazuh>

## Comparison with Alternatives

| Feature                | Operator           | Helm Chart | Manual |
| ---------------------- | ------------------ | ---------- | ------ |
| Declarative Management | Full               | Limited    | None   |
| Dynamic Configuration  | Yes                | No         | No     |
| Self-Healing           | Yes                | Limited    | No     |
| Status Reporting       | Rich               | No         | No     |
| Validation             | Webhooks (planned) | No         | No     |
| Lifecycle Management   | Automated          | Manual     | Manual |

## Contributors

Built with [Kubebuilder](https://book.kubebuilder.io/) and inspired by the [opensearch-k8s-operator](https://github.com/opensearch-project/opensearch-k8s-operator).

## AI-Assisted Development

This project is documented for AI-assisted development. All generated documentation provides comprehensive context for AI agents to:

- Understand existing architecture
- Plan new features consistently
- Generate code following project conventions
- Implement changes with full codebase context
