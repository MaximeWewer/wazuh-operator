# Developer Documentation

Documentation for developers working on the Wazuh Operator.

## Contents

### Architecture

- [Operator Design](architecture/operator-design.md) - Overall operator architecture
- [Reconciliation Flow](architecture/reconciliation-flow.md) - How reconciliation works
- [Certificate Reconciliation](architecture/certificate-reconciliation.md) - TLS certificate internals

### Testing

- [Testing Guide](testing/testing-guide.md) - How to run and write tests
- [Certificate Renewal Scenarios](testing/certificate-renewal-scenarios.md) - Certificate testing

### Contributing

- [Contributing Guide](contributing/CONTRIBUTING.md) - How to contribute
- [Code Style](contributing/code-style.md) - Code conventions

## Quick Start

See [Prerequisites](../usage/getting-started/prerequisites.md) for required tools.

```bash
# Generate CRDs and code
make manifests generate

# Build the operator
make build

# Run tests
make test

# Run locally
make run

# Build Docker image
make docker-build IMG=wazuh-operator:dev
```

## Key Design Principles

1. **Config vs Builder Separation**: Domain logic (config generation) is separate from infrastructure (K8s resource creation)
2. **Declarative Management**: All configuration via CRDs
3. **Idempotent Reconciliation**: Same input always produces same output
4. **Status Reporting**: Rich status information for debugging

## Related Resources

- [User Documentation](../usage/README.md)
- [CRD Reference](../usage/CRD-REFERENCE.md)
- [Technical Reference](../reference/)
