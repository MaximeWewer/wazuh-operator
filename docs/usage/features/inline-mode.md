# Inline Mode Configuration

## Overview

Inline mode is the **default and recommended** deployment pattern where all cluster components (Manager, Indexer, Dashboard) are defined directly within a single `WazuhCluster` Custom Resource.

## Example

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh-production
  namespace: wazuh
spec:
  version: "4.9.2"

  # All components defined INLINE within this CR
  manager:
    master:
      resources: { ... }
      storageSize: "50Gi"
    workers:
      replicas: 3
      resources: { ... }
      storageSize: "50Gi"

  indexer:
    replicas: 3
    resources: { ... }
    storageSize: "100Gi"

  dashboard:
    replicas: 2
    resources: { ... }
```

## Benefits

| Benefit | Description |
|---------|-------------|
| **Single Resource** | Manage entire cluster as one unit |
| **Atomic Updates** | All changes applied together |
| **Simple RBAC** | Only need `WazuhCluster` permissions |
| **GitOps-Friendly** | One manifest file per cluster |
| **Easy to Understand** | Clear component hierarchy |

## When to Use

Inline mode covers **90% of deployment scenarios**:

- Standard single-cluster deployments
- Development and testing environments
- GitOps workflows with single manifests
- Multi-tenant setups (one cluster per namespace)
- Production clusters with simple topology

## Benefits of Inline Mode

| Feature | Description |
|---------|-------------|
| **Configuration** | All in one CR |
| **Updates** | Atomic |
| **RBAC** | Cluster-level permissions only |
| **Complexity** | Low |
| **CRs Count** | 1 |
| **Use Case** | All deployments |

## How It Works

1. **WazuhCluster reconciliation** triggered by CR create/update
2. **Inline spec extraction** - Reconciler reads `spec.manager`, `spec.indexer`, `spec.dashboard`
3. **Resource creation** - Operator creates StatefulSets, Services, ConfigMaps, Secrets
4. **Owner references** - All resources owned by the WazuhCluster CR
5. **Garbage collection** - Deleting the cluster removes all resources

The operator creates StatefulSets, Services, ConfigMaps, and Secrets directly from the inline specs.

## Sample Manifests

All operator samples use inline mode:

- `config/samples/wazuh_v1_wazuhcluster_minimal.yaml` - Minimal deployment
- `config/samples/wazuh_v1_wazuhcluster_inline_mode.yaml` - Full inline example
- `config/samples/wazuh_v1_wazuhcluster_advanced_indexer.yaml` - Advanced topology

```bash
kubectl apply -f config/samples/wazuh_v1_wazuhcluster_inline_mode.yaml
```

## Troubleshooting

### Components Not Created

**Symptom**: WazuhCluster created but no StatefulSets/Deployments appear

**Solution**: Verify inline specs are present:

```bash
kubectl get wazuhcluster -n wazuh -o yaml | grep -E "manager:|indexer:|dashboard:"
```

## See Also

- [Quick Start Guide](../getting-started/quick-start.md)
- [CRD Reference](../CRD-REFERENCE.md)
