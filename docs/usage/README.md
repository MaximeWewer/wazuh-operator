# User Documentation

Documentation for users of the Wazuh Operator.

## Getting Started

- [Prerequisites](../requirements.md) - Required tools and cluster requirements
- [Installation](getting-started/installation.md) - How to install the operator
- [Quick Start](getting-started/quick-start.md) - Deploy your first cluster

## Features

### Core Configuration

- [Inline Mode](features/inline-mode.md) - Configuration pattern
- [Credentials](features/credentials.md) - Password and secret management
- [TLS Configuration](features/tls.md) - Certificate management
- [Sizing Profiles](features/sizing.md) - Cluster sizing guide

### Storage and Scaling

- [Volume Expansion](features/volume-expansion.md) - Online PVC resizing
- [Drain Strategy](features/drain-strategy.md) - Safe scale-down
- [Advanced Indexer Topology](features/advanced-indexer-topology.md) - NodePools and roles

### Observability

- [Monitoring](features/monitoring.md) - Prometheus integration
- [OpenTelemetry](features/opentelemetry.md) - Distributed tracing

### OpenSearch Management

- [OpenSearch Security](features/opensearch-security.md) - Users, roles, tenants
- [OpenSearch Indices](features/opensearch-indices.md) - Templates and ISM policies

### Networking

- [Gateway API](features/gateway-api.md) - Expose services via Gateway API (HTTPRoute, TCPRoute, UDPRoute)

### Other Features

- [Backup and Restore](features/backup-restore.md) - Data protection
- [Log Rotation](features/log-rotation.md) - Automated log cleanup
- [Filebeat Configuration](features/filebeat-configuration.md) - Log forwarding
- [Wazuh API Hosts](features/wazuh-api-hosts.md) - Multi-API configuration

## Examples

- [Quick Start Examples](examples/quick-start/) - Minimal deployments
- [Production Examples](examples/production/) - Production configurations
- [OpenSearch CRDs](examples/opensearch-crds/) - Security and index management

## Reference

- [CRD Reference](CRD-REFERENCE.md) - Complete API documentation for all 21 CRDs

## Troubleshooting

- [Common Issues](troubleshooting/common-issues.md) - Solutions to frequent problems
- [Debugging Guide](troubleshooting/debugging.md) - How to debug issues

## Related Resources

- [Developer Documentation](../dev/README.md)
- [Technical Reference](../reference/)
