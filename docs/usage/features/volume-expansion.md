# PVC Volume Expansion

This guide explains how to expand storage volumes for Wazuh cluster components.

## Overview

The Wazuh Operator supports online PVC (PersistentVolumeClaim) expansion for:

- **Indexer**: OpenSearch data nodes
- **Manager Master**: Wazuh Manager master node
- **Manager Workers**: Wazuh Manager worker nodes

Volume expansion allows you to increase storage capacity without downtime, provided your StorageClass supports it.

## Prerequisites

### StorageClass Requirements

Your StorageClass must have `allowVolumeExpansion: true` enabled:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: expandable-storage
provisioner: kubernetes.io/aws-ebs # or your CSI driver
allowVolumeExpansion: true # Required for volume expansion
parameters:
  type: gp3
```

To check if your StorageClass supports expansion:

```bash
kubectl get storageclass -o custom-columns=NAME:.metadata.name,ALLOW_EXPANSION:.allowVolumeExpansion
```

### Kubernetes Version

Volume expansion is supported in Kubernetes 1.11+ (beta) and stable in 1.24+.

## Expanding Storage

### Method 1: Update WazuhCluster Spec

Simply update the `storageSize` field in your WazuhCluster spec:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  indexer:
    storageSize: 100Gi # Increased from 50Gi
  manager:
    master:
      storageSize: 40Gi # Increased from 20Gi
    workers:
      replicas: 2
      storageSize: 40Gi # Increased from 20Gi
```

Apply the changes:

```bash
kubectl apply -f wazuhcluster.yaml
```

### Method 2: Helm Upgrade

If using Helm, update your values:

```bash
helm upgrade wazuh-cluster ./charts/wazuh-cluster \
  --set cluster.spec.indexer.storageSize=100Gi \
  --set cluster.spec.manager.master.storageSize=40Gi \
  --set cluster.spec.manager.workers.storageSize=40Gi \
  --namespace wazuh
```

## Monitoring Expansion Progress

### Check WazuhCluster Status

The expansion progress is tracked in the `status.volumeExpansion` field:

```bash
kubectl get wazuhcluster wazuh -o jsonpath='{.status.volumeExpansion}' | jq
```

Example output during expansion:

```json
{
  "indexerExpansion": {
    "phase": "InProgress",
    "requestedSize": "100Gi",
    "currentSize": "50Gi",
    "message": "Expanding PVCs: 2 completed, 1 pending",
    "pvcsExpanded": ["data-wazuh-indexer-0", "data-wazuh-indexer-1"],
    "pvcsPending": ["data-wazuh-indexer-2"],
    "lastTransitionTime": "2025-01-15T10:30:00Z"
  },
  "managerMasterExpansion": {
    "phase": "Completed",
    "requestedSize": "40Gi",
    "currentSize": "40Gi",
    "message": "All 1 PVC(s) expanded successfully to 40Gi",
    "pvcsExpanded": ["data-wazuh-manager-master-0"],
    "lastTransitionTime": "2025-01-15T10:28:00Z"
  }
}
```

### Expansion Phases

| Phase        | Description                                  |
| ------------ | -------------------------------------------- |
| `Pending`    | Expansion request received, waiting to start |
| `InProgress` | Expansion in progress for one or more PVCs   |
| `Completed`  | All PVCs have been expanded successfully     |
| `Failed`     | Expansion failed for one or more PVCs        |

### Check PVC Status

Monitor individual PVC expansion:

```bash
kubectl get pvc -l app.kubernetes.io/instance=wazuh -o wide
```

Check PVC conditions:

```bash
kubectl describe pvc data-wazuh-indexer-0
```

Look for these conditions:

- `Resizing`: Volume is being resized by the storage provider
- `FileSystemResizePending`: Volume resized, waiting for filesystem resize (requires pod restart)

### View Events

Check for expansion-related events:

```bash
kubectl get events --field-selector involvedObject.kind=WazuhCluster,involvedObject.name=wazuh --sort-by='.lastTimestamp'
```

Event types:

| Event                         | Description                            |
| ----------------------------- | -------------------------------------- |
| `VolumeExpansionStarted`      | Expansion initiated for a PVC          |
| `VolumeExpansionCompleted`    | All PVCs expanded successfully         |
| `VolumeExpansionFailed`       | Expansion failed for a PVC             |
| `StorageClassNotExpandable`   | StorageClass doesn't support expansion |
| `StorageSizeDecreaseRejected` | Shrinking is not supported             |

## Limitations

### No Volume Shrinking

Kubernetes does not support PVC shrinking. Attempting to decrease `storageSize` will:

- Be rejected by the operator
- Generate a `StorageSizeDecreaseRejected` warning event
- Leave the current size unchanged

If you need to reduce storage, you must:

1. Create a new cluster with smaller volumes
2. Migrate data to the new cluster
3. Delete the old cluster

### StatefulSet VolumeClaimTemplates

StatefulSet VolumeClaimTemplates are immutable. The operator handles this by:

- Patching existing PVCs directly
- Not modifying the StatefulSet VolumeClaimTemplate

New pods created after expansion will still use the old template size until the StatefulSet is recreated.

### Filesystem Resize

Some storage providers require a pod restart for filesystem resize:

- The operator tracks this via the `FileSystemResizePending` condition
- Pods may need to be restarted manually or via rolling update

```bash
# Force pod restart for filesystem resize
kubectl rollout restart statefulset wazuh-indexer -n wazuh
```

## Troubleshooting

### Expansion Not Starting

1. **Check StorageClass**:

   ```bash
   kubectl get storageclass $(kubectl get pvc data-wazuh-indexer-0 -o jsonpath='{.spec.storageClassName}') -o yaml
   ```

   Ensure `allowVolumeExpansion: true` is set.

2. **Check operator RBAC**:
   The operator needs permissions to patch PVCs and read StorageClasses.

3. **Check operator logs**:
   ```bash
   kubectl logs -l app.kubernetes.io/name=wazuh-operator -n wazuh-system
   ```

### Expansion Stuck

1. **Check PVC conditions**:

   ```bash
   kubectl describe pvc data-wazuh-indexer-0
   ```

2. **Check CSI driver logs**:

   ```bash
   kubectl logs -l app=csi-controller -n kube-system
   ```

3. **Restart pods for filesystem resize**:
   ```bash
   kubectl delete pod wazuh-indexer-0 -n wazuh
   ```

### Expansion Failed

1. **Check events**:

   ```bash
   kubectl get events -n wazuh --sort-by='.lastTimestamp' | grep -i expansion
   ```

2. **Check storage provider quotas**:
   Ensure you haven't exceeded cloud provider storage limits.

3. **Verify available storage**:
   Some providers require available capacity in the storage pool.

## Example: Production Expansion

### Initial Deployment

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh-prod
spec:
  version: "4.9.0"
  indexer:
    replicas: 3
    storageSize: 100Gi
  manager:
    master:
      storageSize: 50Gi
    workers:
      replicas: 2
      storageSize: 50Gi
```

### Expansion After 6 Months

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh-prod
spec:
  version: "4.9.0"
  indexer:
    replicas: 3
    storageSize: 200Gi # Doubled
  manager:
    master:
      storageSize: 100Gi # Doubled
    workers:
      replicas: 2
      storageSize: 100Gi # Doubled
```

### Monitor Progress

```bash
# Watch expansion status
watch -n 5 'kubectl get wazuhcluster wazuh-prod -o jsonpath="{.status.volumeExpansion}" | jq'

# Check all PVC sizes
kubectl get pvc -l app.kubernetes.io/instance=wazuh-prod \
  -o custom-columns=NAME:.metadata.name,SIZE:.spec.resources.requests.storage,STATUS:.status.phase
```

## See Also

- [Cluster Sizing Profiles](./sizing.md)
- [CRD Reference](../CRD-REFERENCE.md)
- [Troubleshooting Guide](../troubleshooting/common-issues.md)
