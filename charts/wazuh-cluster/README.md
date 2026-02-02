# wazuh-cluster

![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v1.0.0](https://img.shields.io/badge/AppVersion-v1.0.0-informational?style=flat-square)

Helm chart for deploying Wazuh clusters via the Wazuh Operator

**Homepage:** <https://github.com/MaximeWewer/wazuh-operator>

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- Wazuh Operator installed (use the `wazuh-operator` chart)

## Documentation

| Resource                                                       | Description                     |
| -------------------------------------------------------------- | ------------------------------- |
| [User Documentation](../../docs/usage/README.md)               | Full usage guide                |
| [Quick Start Examples](../../docs/usage/examples/quick-start/) | Minimal deployment examples     |
| [Production Examples](../../docs/usage/examples/production/)   | Production-ready configurations |
| [Sizing Profiles](../../docs/usage/features/sizing.md)         | Cluster sizing guide            |
| [CRD Reference](../../docs/usage/CRD-REFERENCE.md)             | Complete API documentation      |

## Installation

### Quick Start

1. Install the Wazuh Operator first (if not already installed):

```bash
helm install wazuh-operator ./charts/wazuh-operator
```

2. Install the chart with a sizing profile:

```bash
helm install my-wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=M \
  --namespace wazuh --create-namespace
```

## Upgrading

```bash
helm upgrade my-wazuh-cluster ./charts/wazuh-cluster -f my-values.yaml
```

## Uninstallation

```bash
helm uninstall my-wazuh-cluster
```

> **Note:** This will delete all WazuhCluster resources and secrets. The operator will clean up all associated Kubernetes resources.

## Values

### Global Parameters

| Key             | Type   | Default   | Description                                        |
| --------------- | ------ | --------- | -------------------------------------------------- |
| createNamespace | bool   | `true`    | Create namespace if it doesn't exist               |
| namespace       | string | `"wazuh"` | Namespace where the Wazuh cluster will be deployed |

### Sizing Profiles

| Key                     | Type   | Default | Description                                                                                                    |
| ----------------------- | ------ | ------- | -------------------------------------------------------------------------------------------------------------- |
| sizing.profile          | string | `"M"`   | Sizing profile: XS (testing), S (dev), M (small prod), L (prod), XL (enterprise). Set to "" for custom config. |
| sizing.storageClassName | string | `""`    | Custom storage class (applies to all profiles). Leave empty for cluster default.                               |

### Inline Secrets

| Key                           | Type   | Default                            | Description                                      |
| ----------------------------- | ------ | ---------------------------------- | ------------------------------------------------ |
| secrets.indexerAdmin.password | string | `"CHANGE_ME_STRONG_PASSWORD_HERE"` | Indexer admin password (CHANGE IN PRODUCTION)    |
| secrets.indexerAdmin.username | string | `"admin"`                          | Indexer admin username                           |
| secrets.wazuhApi.password     | string | `"CHANGE_ME_STRONG_PASSWORD_HERE"` | Wazuh API password (CHANGE IN PRODUCTION)        |
| secrets.wazuhApi.username     | string | `"wazuh-api"`                      | Wazuh API username                               |
| secrets.wazuhAuthd.enabled    | bool   | `true`                             | Enable authd password secret creation            |
| secrets.wazuhAuthd.password   | string | `"CHANGE_ME_STRONG_PASSWORD_HERE"` | Agent enrollment password (CHANGE IN PRODUCTION) |

### External Secrets Operator (ESO)

| Key                                              | Type   | Default         | Description                                                                                           |
| ------------------------------------------------ | ------ | --------------- | ----------------------------------------------------------------------------------------------------- |
| externalSecrets.enabled                          | bool   | `false`         | Enable External Secrets integration (when true, inline secrets are ignored for configured components) |
| externalSecrets.indexerAdmin.name                | string | `""`            | ExternalSecret name (leave empty to use inline secrets)                                               |
| externalSecrets.indexerAdmin.passwordKey         | string | `"password"`    | Key in synced secret containing password                                                              |
| externalSecrets.indexerAdmin.refreshInterval     | string | `"1h"`          | Sync interval (e.g., "1h", "30m")                                                                     |
| externalSecrets.indexerAdmin.remoteRef.key       | string | `""`            | Key/path in external provider (e.g., "secret/data/wazuh/indexer")                                     |
| externalSecrets.indexerAdmin.secretStoreRef.kind | string | `"SecretStore"` | SecretStore kind: SecretStore or ClusterSecretStore                                                   |
| externalSecrets.indexerAdmin.secretStoreRef.name | string | `""`            | SecretStore name                                                                                      |
| externalSecrets.indexerAdmin.usernameKey         | string | `"username"`    | Key in synced secret containing username                                                              |
| externalSecrets.wazuhApi.name                    | string | `""`            | ExternalSecret name (leave empty to use inline secrets)                                               |
| externalSecrets.wazuhApi.passwordKey             | string | `"password"`    |                                                                                                       |
| externalSecrets.wazuhApi.refreshInterval         | string | `"1h"`          |                                                                                                       |
| externalSecrets.wazuhApi.remoteRef.key           | string | `""`            |                                                                                                       |
| externalSecrets.wazuhApi.secretStoreRef.kind     | string | `"SecretStore"` |                                                                                                       |
| externalSecrets.wazuhApi.secretStoreRef.name     | string | `""`            |                                                                                                       |
| externalSecrets.wazuhApi.usernameKey             | string | `"username"`    |                                                                                                       |
| externalSecrets.wazuhAuthd.name                  | string | `""`            | ExternalSecret name (leave empty to use inline secrets)                                               |
| externalSecrets.wazuhAuthd.passwordKey           | string | `"password"`    | Key in synced secret containing password                                                              |
| externalSecrets.wazuhAuthd.refreshInterval       | string | `"1h"`          |                                                                                                       |
| externalSecrets.wazuhAuthd.remoteRef.key         | string | `""`            |                                                                                                       |
| externalSecrets.wazuhAuthd.secretStoreRef.kind   | string | `"SecretStore"` |                                                                                                       |
| externalSecrets.wazuhAuthd.secretStoreRef.name   | string | `""`            |                                                                                                       |

### WazuhCluster Configuration

| Key                          | Type   | Default           | Description                       |
| ---------------------------- | ------ | ----------------- | --------------------------------- |
| cluster.enabled              | bool   | `true`            | Enable WazuhCluster deployment    |
| cluster.name                 | string | `"wazuh-cluster"` | Name of the WazuhCluster resource |
| cluster.spec.dashboard       | object | `{}`              |                                   |
| cluster.spec.indexer         | object | `{}`              |                                   |
| cluster.spec.manager.master  | object | `{}`              |                                   |
| cluster.spec.manager.workers | object | `{}`              |                                   |
| cluster.spec.version         | string | `"4.9.0"`         | Wazuh version to deploy           |

### Backup Configuration

| Key                              | Type | Default | Description                                      |
| -------------------------------- | ---- | ------- | ------------------------------------------------ |
| backupCredentials.enabled        | bool | `false` | Enable backup credentials Secret creation        |
| opensearchRepository.enabled     | bool | `false` | Enable OpenSearchSnapshotRepository CRD creation |
| opensearchSnapshotPolicy.enabled | bool | `false` | Enable OpenSearchSnapshotPolicy CRD creation     |
| wazuhBackup.enabled              | bool | `false` | Enable WazuhBackup CRD creation                  |

### Network Policy Configuration

| Key                                         | Type   | Default          | Description                                                |
| ------------------------------------------- | ------ | ---------------- | ---------------------------------------------------------- |
| networkPolicy.dashboard.additionalEgress    | list   | `[]`             |                                                            |
| networkPolicy.dashboard.ingressFrom         | list   | `[]`             | Custom ingress rules (default: allow all on port 5601)     |
| networkPolicy.enabled                       | bool   | `false`          | Enable NetworkPolicies for cluster components              |
| networkPolicy.indexer.additionalEgress      | list   | `[]`             | Additional egress rules for indexer (e.g., for S3 backups) |
| networkPolicy.indexer.additionalIngress     | list   | `[]`             | Additional ingress rules for indexer                       |
| networkPolicy.manager.additionalEgress      | list   | `[]`             |                                                            |
| networkPolicy.manager.additionalIngress     | list   | `[]`             |                                                            |
| networkPolicy.manager.agentCIDRs            | list   | `[]`             | Restrict agent connections to specific CIDRs (empty = all) |
| networkPolicy.manager.allowAgentConnections | bool   | `true`           | Allow agent connections from outside the cluster           |
| networkPolicy.operatorNamespace             | string | `"wazuh-system"` | Operator namespace (for allowing operator access)          |

### Resource Quota Configuration

| Key                                            | Type   | Default   | Description                                                                   |
| ---------------------------------------------- | ------ | --------- | ----------------------------------------------------------------------------- |
| resourceQuota.configmaps                       | string | `"50"`    | Maximum ConfigMaps in namespace                                               |
| resourceQuota.enabled                          | bool   | `false`   | Enable ResourceQuota and LimitRange                                           |
| resourceQuota.limitRange.default.cpu           | string | `"1"`     |                                                                               |
| resourceQuota.limitRange.default.memory        | string | `"2Gi"`   |                                                                               |
| resourceQuota.limitRange.defaultRequest.cpu    | string | `"100m"`  |                                                                               |
| resourceQuota.limitRange.defaultRequest.memory | string | `"256Mi"` |                                                                               |
| resourceQuota.limitRange.max.cpu               | string | `"16"`    |                                                                               |
| resourceQuota.limitRange.max.memory            | string | `"32Gi"`  |                                                                               |
| resourceQuota.limitRange.pvcMax                | string | `"500Gi"` | Maximum PVC size                                                              |
| resourceQuota.limitRange.pvcMin                | string | `"1Gi"`   | Minimum PVC size                                                              |
| resourceQuota.limits.cpu                       | string | `"40"`    | Total CPU limits                                                              |
| resourceQuota.limits.memory                    | string | `"80Gi"`  | Total memory limits                                                           |
| resourceQuota.persistentvolumeclaims           | string | `"20"`    | Maximum PVCs in namespace                                                     |
| resourceQuota.pods                             | string | `"25"`    | Maximum pods (adjust based on sizing profile: XS=10, S=15, M=25, L=40, XL=60) |
| resourceQuota.requests.cpu                     | string | `"20"`    | Total CPU requests limit                                                      |
| resourceQuota.requests.memory                  | string | `"40Gi"`  | Total memory requests limit                                                   |
| resourceQuota.requests.storage                 | string | `"500Gi"` | Total storage requests limit                                                  |
| resourceQuota.secrets                          | string | `"50"`    | Maximum Secrets in namespace                                                  |
| resourceQuota.services                         | string | `"20"`    | Maximum Services in namespace                                                 |

## Examples

### Minimal Deployment

```yaml
sizing:
  profile: S

secrets:
  wazuhApi:
    password: "MySecurePassword123!"
  indexerAdmin:
    password: "MySecurePassword456!"
  wazuhAuthd:
    password: "MySecurePassword789!"
```

### Production with External Secrets (Vault)

```yaml
sizing:
  profile: L

# Disable inline secrets
secrets:
  wazuhApi:
    password: ""
  indexerAdmin:
    password: ""

# Use External Secrets Operator
externalSecrets:
  enabled: true
  indexerAdmin:
    name: wazuh-indexer-credentials
    secretStoreRef:
      name: vault-backend
      kind: SecretStore
    remoteRef:
      key: secret/data/wazuh/indexer
  wazuhApi:
    name: wazuh-api-credentials
    secretStoreRef:
      name: vault-backend
      kind: SecretStore
    remoteRef:
      key: secret/data/wazuh/api
```

### HPA and High Availability

```yaml
sizing:
  profile: L

cluster:
  spec:
    indexer:
      antiAffinity:
        enabled: true
        type: required
        topologyKey: topology.kubernetes.io/zone
    manager:
      workers:
        hpa:
          enabled: true
          minReplicas: 2
          maxReplicas: 10
          targetCPUUtilizationPercentage: 80
    dashboard:
      hpa:
        enabled: true
        minReplicas: 2
        maxReplicas: 5
```

### Gateway API Configuration

```yaml
cluster:
  spec:
    dashboard:
      gatewayAPI:
        enabled: true
        gatewayRef:
          name: wazuh-gateway
          namespace: gateway-system
        hostnames:
          - dashboard.wazuh.example.com
        http:
          pathPrefix: /
    manager:
      workers:
        gatewayAPI:
          enabled: true
          gatewayRef:
            name: wazuh-gateway
          tcp:
            enabled: true
            enrollmentEnabled: true
            eventsEnabled: true
```

## Security Considerations

**IMPORTANT**: The default passwords in this chart are for demonstration purposes only.

For production use, you **MUST**:

1. Change all default passwords
2. Use External Secrets Operator for credential management
3. Enable TLS for all communications
4. Review and apply appropriate RBAC policies
5. Enable anti-affinity for high availability
6. Configure network policies

## Support

- GitHub Issues: https://github.com/MaximeWewer/wazuh-operator/issues
- Documentation: https://documentation.wazuh.com/
