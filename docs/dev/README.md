# Developer Documentation

This directory contains documentation for developers working on the Wazuh Operator.

## Contents

### Architecture

- [Operator Design](architecture/operator-design.md) - Overall operator architecture and design decisions
- [Certificate Reconciliation](architecture/certificate-reconciliation.md) - TLS certificate management internals
- [Reconciliation Flow](architecture/reconciliation-flow.md) - How the reconciliation loop works

### Testing

- [Certificate Renewal Scenarios](testing/certificate-renewal-scenarios.md) - Test scenarios for certificate management
- [Testing Guide](testing/testing-guide.md) - How to run and write tests

### Contributing

- [Contributing Guide](contributing/CONTRIBUTING.md) - How to contribute to the project
- [Code Style](contributing/code-style.md) - Code conventions and best practices

## Quick Start for Developers

### Prerequisites

- Go 1.25+
- Docker
- kubectl
- A Kubernetes cluster (minikube, kind, etc.)
- Make

### Build and Run

```bash
# Generate CRDs and code
make manifests generate

# Build the operator
make build

# Run tests
make test

# Run locally (against current kubeconfig cluster)
make run

# Build Docker image
make docker-build IMG=wazuh-operator:dev
```

### Project Structure

```
wazuh-operator/
├── api/v1alpha1/           # CRD type definitions
├── cmd/wazuh-operator/     # Main entry point
├── internal/
│   ├── controller/         # Reconciler implementations
│   │   ├── wazuhcluster/   # WazuhCluster controller
│   │   ├── certificate/    # Certificate management
│   │   ├── opensearch/     # OpenSearch CRD controllers
│   │   └── wazuh/          # Rule/Decoder controllers
│   ├── utils/              # Shared utilities
│   └── metrics/            # Prometheus metrics
├── pkg/
│   ├── constants/          # Shared constants
│   ├── resources/          # Kubernetes resource builders
│   └── version/            # Version information
├── config/                 # Kubernetes manifests
└── charts/                 # Helm charts
```

### Key Design Principles

1. **Config vs Builder Separation**: Domain logic (config generation) is separate from infrastructure (K8s resource creation)
2. **Declarative Management**: All configuration via CRDs
3. **Idempotent Reconciliation**: Same input always produces same output
4. **Status Reporting**: Rich status information for debugging

## Related Resources

- [User Documentation](../usage/README.md) - End-user documentation
- [CRD Reference](../usage/CRD-REFERENCE.md) - API documentation
