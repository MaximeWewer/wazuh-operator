# Upgrade Guide

This guide covers upgrading the Wazuh Operator and managed Wazuh clusters.

## Breaking change: cross-namespace cluster references

All resource CRDs now use explicit (name, namespace) cluster references and
support targeting clusters that live in a different namespace from the CR.

| Field shape | CRDs |
|-------------|------|
| `spec.clusterRefs: [{name, namespace}]` (list, both required, MinItems=1) | WazuhAgentGroup, WazuhRule, WazuhDecoder, WazuhIntegration, WazuhFilebeat, OpenSearchUser, OpenSearchRole, OpenSearchRoleMapping, OpenSearchTenant, OpenSearchActionGroup, OpenSearchAuthConfig, OpenSearchISMPolicy, OpenSearchIndexTemplate, OpenSearchComponentTemplate, OpenSearchIndex, OpenSearchSnapshotPolicy, OpenSearchSnapshotRepository, OpenSearchSnapshot, OpenSearchRestore |
| `spec.clusterRef: {name, namespace}` (single, both required) | WazuhBackup, WazuhRestore, WazuhCertificate |

Migrate every existing CR before upgrading the operator:

```yaml
# Before
spec:
  clusterRef:
    name: wazuh-cluster      # namespace was optional, defaulted to CR namespace

# After (multi-cluster CRs)
spec:
  clusterRefs:
    - name: wazuh-cluster
      namespace: wazuh        # mandatory

# After (Backup/Restore/Certificate)
spec:
  clusterRef:
    name: wazuh-cluster
    namespace: wazuh          # mandatory
```

For multi-cluster CRs, `status.clusterStatuses[]` reports per-target-cluster
sync state; the top-level `status.phase` becomes the worst-case aggregate
(`Failed` if any cluster fails, `Pending` if any is pending, `Ready` only
when every target is ready).

## Overview

| Component | Upgrade Method | Downtime |
|-----------|---------------|----------|
| Operator | Helm upgrade / kubectl apply | None (rolling) |
| Wazuh Cluster | CR version field update | None (rolling) |
| CRDs | Helm upgrade / kubectl apply | None |

## Pre-Upgrade Checklist

Before upgrading, complete these steps:

```bash
# 1. Check current versions
helm list -n wazuh-operator
kubectl get wazuhcluster -A -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.version}{"\n"}{end}'

# 2. Review release notes for breaking changes
# https://github.com/MaximeWewer/wazuh-operator/releases

# 3. Create backup of OpenSearch indices
kubectl apply -f - <<EOF
apiVersion: resources.wazuh.com/v1
kind: OpenSearchSnapshot
metadata:
  name: pre-upgrade-$(date +%Y%m%d)
  namespace: wazuh
spec:
  clusterRefs:
    - name: wazuh-cluster
      namespace: wazuh
  repository:
    name: backup-repo
  indices:
    - "*"
EOF

# 4. Create backup of Wazuh Manager data
kubectl apply -f - <<EOF
apiVersion: resources.wazuh.com/v1
kind: WazuhBackup
metadata:
  name: pre-upgrade-$(date +%Y%m%d)
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
    namespace: wazuh
  oneShot: true
  components:
    agentKeys: true
    fimDatabase: true
    agentDatabase: true
EOF

# 5. Verify backups completed
kubectl get opensearchsnapshot,wazuhbackup -n wazuh

# 6. Check cluster health
kubectl get wazuhcluster -n wazuh -o jsonpath='{.items[0].status.conditions}' | jq
```

## Upgrading the Operator

### Method 1: Helm Upgrade (Recommended)

```bash
# Update chart repository (if using OCI)
# helm pull oci://ghcr.io/maximewewer/charts/wazuh-operator --version <new-version>

# Upgrade with existing values
helm template wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-operator \
  | kubectl apply --server-side -f -

# Or upgrade with custom values
helm template wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-operator \
  -f custom-values.yaml \
  | kubectl apply --server-side -f -

# Verify upgrade
kubectl rollout status deployment/wazuh-operator-controller-manager -n wazuh-operator
```

### Method 2: kubectl Apply

```bash
# Update CRDs first
kubectl apply -f config/crd/

# Update RBAC
kubectl apply -f config/rbac/

# Update operator deployment
kubectl apply -f config/manager/
```

### Operator Upgrade Verification

```bash
# Check operator logs
kubectl logs -n wazuh-operator deploy/wazuh-operator-controller-manager --tail=50

# Verify all clusters are reconciling
kubectl get wazuhcluster -A

# Check for errors
kubectl get events -n wazuh-operator --sort-by='.lastTimestamp' | tail -10
```

## Upgrading Wazuh Clusters

### Minor Version Upgrade (e.g., 4.9.0 → 4.9.1)

```bash
# Update the version in WazuhCluster spec
kubectl patch wazuhcluster wazuh-cluster -n wazuh \
  --type='merge' -p='{"spec":{"version":"4.9.1"}}'

# Or edit directly
kubectl edit wazuhcluster wazuh-cluster -n wazuh
```

### Major Version Upgrade (e.g., 4.8.x → 4.9.x)

Major upgrades require more careful planning:

1. **Review compatibility matrix**:
   - Check Wazuh-OpenSearch version compatibility
   - Review API changes

2. **Upgrade in stages**:

```bash
# Stage 1: Upgrade indexer first (if required)
kubectl patch wazuhcluster wazuh-cluster -n wazuh \
  --type='json' -p='[{"op":"replace","path":"/spec/indexer/version","value":"2.13.0"}]'

# Wait for indexer upgrade
kubectl rollout status statefulset/wazuh-cluster-indexer -n wazuh

# Stage 2: Upgrade manager
kubectl patch wazuhcluster wazuh-cluster -n wazuh \
  --type='merge' -p='{"spec":{"version":"4.9.0"}}'

# Wait for manager upgrade
kubectl rollout status statefulset/wazuh-cluster-manager-master -n wazuh
kubectl rollout status statefulset/wazuh-cluster-manager-worker -n wazuh

# Stage 3: Upgrade dashboard
kubectl rollout status deployment/wazuh-cluster-dashboard -n wazuh
```

### Monitoring Upgrade Progress

```bash
# Watch pod status
watch kubectl get pods -n wazuh

# Monitor rollout
kubectl rollout status statefulset/wazuh-cluster-indexer -n wazuh
kubectl rollout status statefulset/wazuh-cluster-manager-master -n wazuh

# Check cluster conditions
kubectl get wazuhcluster wazuh-cluster -n wazuh -o yaml | grep -A 20 'conditions:'
```

## Quorum-Safe Rolling Restart Behavior

The operator uses a **RollingUpdate** StatefulSet update strategy by default. Kubernetes handles
rolling restarts automatically when the pod template changes (e.g., configuration, certificate,
or spec hash updates).

When a configuration or certificate change is detected:

1. **Indexer, Manager Master, Manager Workers**: Kubernetes performs a rolling update, replacing pods
   one at a time (highest ordinal first)
2. **Dashboard**: Standard rolling deployment (Deployment, not StatefulSet)

> **Note:** You can switch to `OnDelete` strategy via the `updateStrategy` field if you need manual
> control over pod restarts.

Rolling restart progress is tracked in `.status.rollingRestart` and visible via:

```bash
kubectl get wazuhcluster wazuh-cluster -n wazuh -o jsonpath='{.status.rollingRestart}'
```

### Drain Configuration

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
spec:
  # Drain configuration for safe scale-down operations
  drain:
    indexer:
      timeout: 30m
      healthCheckInterval: 10s
    manager:
      timeout: 15m
      queueCheckInterval: 5s
```

## Rollback Procedures

### Operator Rollback

```bash
# Helm rollback
helm rollback wazuh-operator -n wazuh-operator

# Or rollback to specific revision
helm history wazuh-operator -n wazuh-operator
helm rollback wazuh-operator <revision> -n wazuh-operator
```

### Cluster Rollback

```bash
# Revert to previous version
kubectl patch wazuhcluster wazuh-cluster -n wazuh \
  --type='merge' -p='{"spec":{"version":"4.8.2"}}'
```

### Data Rollback (if needed)

```bash
# Restore from pre-upgrade snapshot
kubectl apply -f - <<EOF
apiVersion: resources.wazuh.com/v1
kind: OpenSearchRestore
metadata:
  name: rollback-restore
  namespace: wazuh
spec:
  clusterRefs:
    - name: wazuh-cluster
      namespace: wazuh
  repository:
    name: backup-repo
  snapshotName: pre-upgrade-20260118
  indices:
    - "*"
EOF
```

## Troubleshooting Upgrades

### Pods Stuck in Terminating

```bash
# Check for stuck finalizers
kubectl get pods -n wazuh -o json | jq '.items[] | select(.metadata.deletionTimestamp != null) | .metadata.name'

# Force delete if necessary (use with caution)
kubectl delete pod <pod-name> -n wazuh --force --grace-period=0
```

### Upgrade Not Progressing

```bash
# Check operator logs
kubectl logs -n wazuh-operator deploy/wazuh-operator-controller-manager -f

# Check cluster conditions
kubectl describe wazuhcluster wazuh-cluster -n wazuh

# Check pod events
kubectl describe pod -n wazuh <pod-name>
```

### CRD Conflicts

```bash
# Check CRD versions
kubectl get crd wazuhclusters.resources.wazuh.com -o yaml | grep -A 5 'storedVersions'

# Force CRD update if needed
kubectl replace -f config/crd/ --force
```

### Namespace Stuck Terminating After API Version Change

If you previously deployed with an older API version (e.g., `v1alpha1`) and upgraded
CRDs to `v1`, Kubernetes cannot convert or delete old resources stored with the
previous version. The namespace stays in `Terminating` with an error like:

```text
failed to list resources.wazuh.com/v1, Kind=WazuhCluster: request to convert
CR from an invalid group/version: resources.wazuh.com/v1alpha1
```

To resolve:

```bash
# 1. Delete all Wazuh/OpenSearch CRDs to clear stored version tracking
kubectl delete $(kubectl get crds -o name | grep resources.wazuh.com)

# 2. Remove the finalizer from the stuck namespace
kubectl get namespace <namespace> -o json \
  | jq '.spec.finalizers = []' \
  | kubectl replace --raw "/api/v1/namespaces/<namespace>/finalize" -f -

# 3. Reinstall CRDs with the current version
helm template wazuh-operator ./charts/wazuh-operator \
  --set operator.enabled=false | kubectl apply --server-side -f -
```

> **Prevention:** Always delete all WazuhCluster resources and CRDs before
> upgrading across API versions (e.g., `v1alpha1` to `v1`).

## Best Practices

1. **Always backup before upgrading**
2. **Test upgrades in staging first**
3. **Upgrade during maintenance windows**
4. **Monitor metrics during upgrade**
5. **Keep rollback plan ready**
6. **Document your upgrade path**

## See Also

- [Backup & Restore Guide](../features/backup-restore.md)
- [Troubleshooting Guide](../troubleshooting/common-issues.md)
- [Release Notes](https://github.com/MaximeWewer/wazuh-operator/releases)
