# Reconciliation Flow

This document describes how the WazuhCluster reconciliation loop works.

## Overview

The reconciliation loop is triggered when:

- A WazuhCluster resource is created, updated, or deleted
- A watched child resource (StatefulSet, Service, etc.) changes
- A requeue timer fires (default: 30 seconds)

## Main Reconciliation Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        Reconcile() Entry Point                             │
│                   (wazuhcluster_controller.go)                             │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 1. Fetch WazuhCluster                                                      │
│    - Get from cache                                                        │
│    - Handle not found (deleted)                                            │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 2. Handle Deletion                                                         │
│    - Check DeletionTimestamp                                               │
│    - Run finalizers if needed                                              │
│    - Clean up owned resources                                              │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 3. Reconcile Certificates                                                  │
│    - Check CA expiry, renew if needed                                      │
│    - Check node certs expiry, renew if needed                              │
│    - Return cert hashes for pod annotations                                │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 4. Reconcile Indexer                                                       │
│    - Build ConfigMap, Secrets, Service, StatefulSet                        │
│    - Create or Update resources                                            │
│    - Wait for StatefulSet ready (optional)                                 │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 5. Reconcile Manager Master                                                │
│    - Build ConfigMap, Secrets, Service, StatefulSet                        │
│    - Create or Update resources                                            │
│    - Wait for StatefulSet ready (optional)                                 │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 6. Reconcile Manager Workers                                               │
│    - Build ConfigMap, Secrets, Service, StatefulSet                        │
│    - Create or Update resources                                            │
│    - Wait for StatefulSet ready (optional)                                 │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 7. Reconcile Dashboard                                                     │
│    - Build ConfigMap, Service, Deployment                                  │
│    - Create or Update resources                                            │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 8. Reconcile Log Rotation CronJob                                          │
│    - Check if logRotation.enabled                                          │
│    - Build CronJob                                                         │
│    - Create or Update                                                      │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 9. Update Status                                                           │
│    - Set phase (Pending, Creating, Running, Failed)                        │
│    - Update component statuses                                             │
│    - Set conditions                                                        │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 10. Return Result                                                          │
│     - Requeue after 30s (default)                                          │
│     - Immediate requeue on error                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

## Certificate Reconciliation Sub-flow

```
ReconcileWithHashes()
    │
    ├─► reconcileCA()
    │       - Check if CA secret exists
    │       - Check CA expiry
    │       - Generate new CA if needed
    │       - Update secret
    │
    ├─► reconcileIndexerCerts()
    │       - Check if secret exists
    │       - Check cert expiry
    │       - Generate new certs signed by CA
    │       - Update secret
    │
    ├─► reconcileManagerMasterCerts()
    │       - Same pattern as indexer
    │
    ├─► reconcileManagerWorkerCerts()
    │       - Same pattern as indexer
    │
    ├─► reconcileDashboardCerts()
    │       - Same pattern as indexer
    │
    ├─► reconcileFilebeatCerts()
    │       - Same pattern as indexer
    │
    └─► Return CertHashResult
            - IndexerCertHash
            - ManagerMasterCertHash
            - ManagerWorkerCertHash
            - DashboardCertHash
```

## Resource Creation Pattern

Each component follows the same pattern:

```go
func (r *Reconciler) reconcileComponent(ctx context.Context, cluster *v1alpha1.WazuhCluster) error {
    // 1. Build desired state
    desired := builder.NewComponentBuilder(cluster).Build()

    // 2. Set owner reference
    if err := ctrl.SetControllerReference(cluster, desired, r.Scheme); err != nil {
        return err
    }

    // 3. Get current state
    current := &corev1.Resource{}
    err := r.Get(ctx, client.ObjectKeyFromObject(desired), current)

    if errors.IsNotFound(err) {
        // 4a. Create if not exists
        return r.Create(ctx, desired)
    } else if err != nil {
        return err
    }

    // 4b. Update if changed
    if !reflect.DeepEqual(current.Spec, desired.Spec) {
        current.Spec = desired.Spec
        return r.Update(ctx, current)
    }

    return nil
}
```

## Requeue Behavior

| Situation                  | Requeue Delay       |
| -------------------------- | ------------------- |
| Successful reconciliation  | 30 seconds          |
| Component not ready        | 10 seconds          |
| Transient error            | Exponential backoff |
| Certificate renewal needed | Immediate           |

## Watched Resources

The controller watches:

- WazuhCluster (primary)
- StatefulSets (owned)
- Deployments (owned)
- Services (owned)
- ConfigMaps (owned)
- Secrets (owned)
- CronJobs (owned)

Changes to any watched resource trigger reconciliation.

## Status Updates

Status is updated at the end of each reconciliation:

```go
cluster.Status.Phase = v1alpha1.ClusterPhaseRunning
cluster.Status.Manager = &v1alpha1.ComponentStatus{
    Phase:         "Running",
    ReadyReplicas: 3,
    Replicas:      3,
}
// ... other components

if err := r.Status().Update(ctx, cluster); err != nil {
    return ctrl.Result{}, err
}
```

## Error Handling

```go
// Transient error - requeue with backoff
if isTransient(err) {
    return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
}

// Permanent error - update status and don't requeue
cluster.Status.Phase = v1alpha1.ClusterPhaseFailed
cluster.Status.Conditions = append(cluster.Status.Conditions, metav1.Condition{
    Type:    "Ready",
    Status:  metav1.ConditionFalse,
    Reason:  "ReconcileError",
    Message: err.Error(),
})
r.Status().Update(ctx, cluster)
return ctrl.Result{}, nil
```
