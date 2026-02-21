# Wazuh Operator Documentation

Master documentation index for the Wazuh Kubernetes Operator.

## Quick Start

```bash
# Install operator
helm template wazuh-operator oci://ghcr.io/maximewewer/charts/wazuh-operator \
  --namespace wazuh-operator | kubectl apply -f -

# Deploy cluster
helm template wazuh-cluster oci://ghcr.io/maximewewer/charts/wazuh-cluster \
  --namespace wazuh | kubectl apply -f -

# Check status
kubectl get wazuhcluster -n wazuh
```

## Project Overview

| Property        | Value                                       |
| --------------- | ------------------------------------------- |
| **Type**        | Kubernetes Operator                         |
| **Language**    | Go 1.26.0                                   |
| **Framework**   | Kubebuilder v4 + controller-runtime         |
| **CRDs**        | 25 Custom Resource Definitions              |
| **Controllers** | 25 reconciliation controllers               |
| **API Group**   | `resources.wazuh.com/v1`                    |
| **Target**      | Kubernetes 1.25+                            |

## Documentation

### Getting Started

- [Prerequisites](requirements.md) - Required tools and cluster requirements
- [Installation](usage/getting-started/installation.md) - Install the operator
- [Quick Start](usage/getting-started/quick-start.md) - Deploy your first cluster

### User Guide

- [User Documentation](usage/README.md) - Complete user guide index
- [CRD Reference](usage/CRD-REFERENCE.md) - API documentation for all 25 CRDs
- [Examples](usage/examples/README.md) - Ready-to-use configurations

### Key Features

| Feature          | Documentation                                                                                                                              |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Deployment Modes | [Inline Mode](usage/features/inline-mode.md) (recommended), [Reference Mode](usage/features/reference-mode.md)                             |
| Security         | [Credentials](usage/features/credentials.md), [TLS](usage/features/tls.md)                                                                 |
| Observability    | [Monitoring](usage/features/monitoring.md), [OpenTelemetry](usage/features/opentelemetry.md)                                               |
| OpenSearch       | [Security CRDs](usage/features/opensearch-security.md), [Index Management](usage/features/opensearch-indices.md)                           |
| Operations       | [Backup/Restore](usage/features/backup-restore.md), [Sizing](usage/features/sizing.md), [Drain Strategy](usage/features/drain-strategy.md) |

### Developer Guide

- [Developer Documentation](dev/README.md) - Contributing and architecture
- [Operator Design](dev/architecture/operator-design.md) - Architecture overview
- [Testing Guide](dev/testing/testing-guide.md) - How to test

### Technical Reference

- [Project Overview](reference/project-overview.md) - Executive summary
- [Architecture](reference/architecture.md) - System design and patterns
- [Technology Stack](reference/technology-stack.md) - Technology decisions
- [Data Models](reference/data-models.md) - CRD schemas and relationships
- [API Contracts](reference/api-contracts.md) - Controller patterns
- [Source Tree](reference/source-tree-analysis.md) - Directory structure

### Troubleshooting

- [Common Issues](usage/troubleshooting/common-issues.md) - Frequent problems and solutions
- [Debugging Guide](usage/troubleshooting/debugging.md) - Debug techniques

## Key Directories

| Path                      | Description                                                          |
| ------------------------- | -------------------------------------------------------------------- |
| `api/v1/`                 | CRD type definitions (v1 storage version)                            |
| `controllers/`            | 25 Kubernetes controllers                                            |
| `internal/wazuh/`         | Wazuh reconcilers, config, builders, drain                           |
| `internal/opensearch/`    | OpenSearch reconcilers, API clients, config, builders                |
| `internal/certificates/`  | TLS certificate reconciler and generation                            |
| `internal/networking/`    | Gateway API and Ingress reconcilers + builders                       |
| `internal/shared/`        | Cross-cutting: affinity, PDB, drain state machine, config, patch     |
| `internal/validation/`    | CRD validation (cluster, opensearch, wazuh, password)                |
| `pkg/`                    | Public stable APIs (constants, config, dns, logging, version, versions) |
| `config/`                 | CRDs, RBAC, samples                                                  |
| `charts/`                 | Helm charts (operator, cluster)                                      |

## Build Commands

```bash
make generate manifests                     # Generate code and CRDs
make build                                  # Build operator
make test                                   # Run tests
make run                                    # Run locally
make docker-build IMG=wazuh-operator:dev    # Build image
make deploy IMG=wazuh-operator:dev          # Deploy to cluster
```

## Support

- **GitHub**: <https://github.com/MaximeWewer/wazuh-operator>
- **Issues**: <https://github.com/MaximeWewer/wazuh-operator/issues>
- **Wazuh Docs**: <https://documentation.wazuh.com/>
