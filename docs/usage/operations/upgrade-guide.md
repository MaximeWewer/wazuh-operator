# Upgrade Guide

This guide covers upgrading the Wazuh Operator and managed Wazuh clusters.

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
helm list -n wazuh-system
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
  clusterRef:
    name: wazuh-cluster
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
helm upgrade wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-system \
  --reuse-values

# Or upgrade with new values
helm upgrade wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-system \
  -f custom-values.yaml

# Verify upgrade
kubectl rollout status deployment/wazuh-operator-controller-manager -n wazuh-system
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
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager --tail=50

# Verify all clusters are reconciling
kubectl get wazuhcluster -A

# Check for errors
kubectl get events -n wazuh-system --sort-by='.lastTimestamp' | tail -10
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

## Rolling Update Behavior

The operator performs rolling updates automatically:

1. **Indexer**: One pod at a time, waits for green cluster health
2. **Manager Workers**: One pod at a time, drains queue first
3. **Manager Master**: Updated last, after all workers
4. **Dashboard**: Standard rolling deployment

### Customizing Update Strategy

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
spec:
  # Update strategy for StatefulSets
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      partition: 0  # Update all pods

  # Drain configuration for safe updates
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
helm rollback wazuh-operator -n wazuh-system

# Or rollback to specific revision
helm history wazuh-operator -n wazuh-system
helm rollback wazuh-operator <revision> -n wazuh-system
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
  clusterRef:
    name: wazuh-cluster
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
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager -f

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
