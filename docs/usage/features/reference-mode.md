# Reference Mode

Reference mode allows defining Wazuh cluster components as separate CRs that are referenced by the `WazuhCluster` CR.

## Overview

For most deployments, use [Inline Mode](./inline-mode.md) (the default). Reference mode is for advanced scenarios requiring:

- **Shared components** across multiple clusters
- **Independent lifecycle** for different components
- **Granular RBAC** with different teams managing different components
- **Multi-cluster architectures**

## When to Use Reference Mode

| Use Case | Mode | Reason |
|----------|------|--------|
| Simple deployment | Inline | Fewer CRs, atomic updates |
| Shared indexer | Reference | Component independence |
| Different teams manage components | Reference | Granular RBAC |
| Independent component upgrades | Reference | Decouple versions |
| Multi-cluster logging | Reference | Centralized indexer |

## How to Use

### Step 1: Create Component CRs

```yaml
# WazuhManager CR
apiVersion: resources.wazuh.com/v1
kind: WazuhManager
metadata:
  name: shared-manager
  namespace: wazuh
spec:
  version: "4.9.2"
  master:
    storageSize: "10Gi"
  workers:
    replicas: 0
---
# OpenSearchIndexer CR
apiVersion: resources.wazuh.com/v1
kind: OpenSearchIndexer
metadata:
  name: shared-indexer
  namespace: wazuh
spec:
  version: "2.18.0"
  replicas: 3
  storageSize: "50Gi"
---
# OpenSearchDashboard CR
apiVersion: resources.wazuh.com/v1
kind: OpenSearchDashboard
metadata:
  name: shared-dashboard
  namespace: wazuh
spec:
  version: "2.18.0"
  indexerRef: "shared-indexer"
  replicas: 1
```

### Step 2: Create WazuhCluster with References

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh-cluster-ref
  namespace: wazuh
spec:
  version: "4.9.2"

  # Reference mode - use *Ref fields
  managerRef:
    name: shared-manager
  indexerRef:
    name: shared-indexer
  dashboardRef:
    name: shared-dashboard
```

### Step 3: Deploy

```bash
# Create components first
kubectl apply -f wazuhmanager.yaml
kubectl apply -f opensearchindexer.yaml
kubectl apply -f opensearchdashboard.yaml

# Then create cluster
kubectl apply -f wazuhcluster-ref.yaml

# Verify
kubectl get wazuhcluster,wazuhmanager,opensearchindexer,opensearchdashboard -n wazuh
```

## Sharing Components

Multiple clusters can share the same indexer:

```yaml
# Cluster 1 - Production
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: prod-cluster
spec:
  indexerRef:
    name: shared-indexer  # Shared
  managerRef:
    name: prod-manager    # Unique
---
# Cluster 2 - Staging
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: staging-cluster
spec:
  indexerRef:
    name: shared-indexer  # Same shared indexer
  managerRef:
    name: staging-manager # Unique
```

## Cross-Namespace References

Components can be in different namespaces:

```yaml
spec:
  managerRef:
    name: shared-manager
    namespace: wazuh-components  # Cross-namespace
  indexerRef:
    name: shared-indexer
    namespace: opensearch-cluster
```

**Note**: The operator's ServiceAccount must have permissions to read resources in the referenced namespaces.

## Validation Rules

### Cannot Mix Modes

```yaml
# INVALID - mixing inline and reference
spec:
  manager:           # Inline spec
    master: { ... }
  indexerRef:        # Reference
    name: shared-indexer
```

**Error**: `invalid configuration: cannot mix inline mode and reference mode`

### Referenced CRs Must Exist

If a referenced CR doesn't exist:

```text
Condition: Progressing=False
Reason: ManagerRefResolutionFailed
Message: referenced WazuhManager wazuh/shared-manager not found
```

**Solution**: Create the component CR first.

## Troubleshooting

### Referenced CR Not Found

```bash
# Verify component exists
kubectl get wazuhmanager -n wazuh

# Check reference in cluster
kubectl get wazuhcluster -n wazuh -o jsonpath='{.spec.managerRef}'
```

### Cross-Namespace RBAC Issues

Create RoleBinding for cross-namespace access:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: wazuh-operator-cross-ns
  namespace: other-namespace
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: wazuh-operator-role
subjects:
- kind: ServiceAccount
  name: wazuh-operator-controller-manager
  namespace: wazuh-operator-system
```

## Migration

### From Inline to Reference Mode

1. Extract component specs from WazuhCluster
2. Create separate component CRs
3. Update WazuhCluster to use `*Ref` fields
4. Remove inline specs

### From Reference to Inline Mode

1. Copy specs from referenced CRs
2. Update WazuhCluster with inline specs
3. Remove `*Ref` fields
4. Optionally delete component CRs

## See Also

- [Inline Mode](./inline-mode.md) - Default, recommended pattern
- [CRD Reference](../CRD-REFERENCE.md) - API documentation
