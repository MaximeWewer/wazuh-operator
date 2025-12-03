# User Documentation

This directory contains documentation for users of the Wazuh Operator.

## Contents

### Getting Started

- [Installation](getting-started/installation.md) - How to install the operator
- [Quick Start](getting-started/quick-start.md) - Deploy your first Wazuh cluster

### Features

- [Credentials Management](features/credentials.md) - Auto-generated passwords, secrets management
- [Sizing Profiles](features/sizing.md) - Cluster sizing guide
- [Volume Expansion](features/volume-expansion.md) - Online PVC storage expansion
- [TLS Configuration](features/tls.md) - Certificate management
- [Monitoring](features/monitoring.md) - Prometheus integration
- [Log Rotation](features/log-rotation.md) - Automated log cleanup
- [Wazuh Multi-API Hosts](features/wazuh-api-hosts.md) - Multiple Wazuh Manager APIs
- [OpenSearch Security](features/opensearch-security.md) - Users, roles, tenants
- [OpenSearch Index Management](features/opensearch-indices.md) - Templates, ISM policies

### Examples

Ready-to-use deployment examples:

- [Quick Start Examples](examples/quick-start/) - Minimal deployment
- [Production Examples](examples/production/) - Production-ready configuration
- [OpenSearch CRDs](examples/opensearch-crds/) - Security and index management

### Reference

- [CRD Reference](CRD-REFERENCE.md) - Complete API documentation for all CRDs

### Troubleshooting

- [Common Issues](troubleshooting/common-issues.md) - Solutions to frequent problems
- [Debugging Guide](troubleshooting/debugging.md) - How to debug issues

## Quick Links

### Install the Operator

```bash
helm install wazuh-operator ./charts/wazuh-operator -n wazuh-system --create-namespace
```

### Deploy a Cluster

```bash
helm install wazuh-cluster ./charts/wazuh-cluster -n wazuh --create-namespace
```

### Check Status

```bash
kubectl get wazuhcluster -n wazuh
```

## Related Resources

- [Developer Documentation](../dev/README.md) - For contributors
- [GitHub Repository](https://github.com/MaximeWewer/wazuh-operator)
