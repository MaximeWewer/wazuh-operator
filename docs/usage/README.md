# User Documentation

Documentation for users of the Wazuh Operator.

## Getting Started

- [Prerequisites](getting-started/prerequisites.md) - Required tools and cluster requirements
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
- [Wazuh API RBAC](features/wazuh-api-rbac.md) - Wazuh API users and roles
- [Repository Plugins](features/repository-plugins.md) - Snapshot repository plugins (S3, GCS, Azure)

## Operations

- [Production Deployment](operations/production-deployment.md) - HA, scaling, security, finalizers, health checks
- [Upgrade Guide](operations/upgrade-guide.md) - Upgrade the operator and managed clusters

## Examples

- [Quick Start](examples/quick-start/) - Minimal deployment to get started
- [Production](examples/production/) - Production-ready configuration
- [Wazuh Cluster](examples/wazuh-cluster/) - TLS, drain, monitoring, multi-namespace, Gateway API
- [Wazuh Content](examples/wazuh-content/) - Rules, decoders, integrations, agent groups
- [Wazuh Certificate](examples/wazuh-certificate/) - Standalone TLS certificates
- [Filebeat](examples/filebeat/) - Log forwarding configuration
- [Wazuh API RBAC](examples/wazuh-rbac/) - Wazuh API users and roles (incl. external IdP)
- [Wazuh Backup](examples/wazuh-backup/) - Manager backup and restore
- [OpenSearch Security](examples/opensearch-security/) - Users, roles, tenants, auth
- [OpenSearch Index](examples/opensearch-index/) - Indices, templates, ISM policies
- [OpenSearch Backup](examples/opensearch-backup/) - Snapshots, repositories, restore
- [GitOps](examples/gitops/) - ArgoCD and Flux deployment

See [examples/README.md](examples/README.md) for the full per-CRD index.

## Reference

- [CRD Reference](CRD-REFERENCE.md) - Complete API documentation for all 25 CRDs

## Troubleshooting

- [Common Issues](troubleshooting/common-issues.md) - Solutions to frequent problems
- [Debugging Guide](troubleshooting/debugging.md) - How to debug issues

## Related Resources

- [Developer Documentation](../dev/README.md)
- [Technical Reference](../reference/)
