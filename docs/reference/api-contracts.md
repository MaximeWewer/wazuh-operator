# API Contracts - Controllers & Reconcilers

## Overview

The Wazuh Operator implements **22 Kubernetes controllers** that watch Custom Resources and reconcile them to their desired state. Each controller follows the Kubernetes operator pattern with reconciliation loops. These controllers manage **22 Custom Resource Definitions (CRDs)**.

## Controller Architecture

### Main Controller

**controllers/wazuhcluster_controller.go** - `WazuhClusterReconciler`

The main orchestrating controller that manages the complete Wazuh cluster lifecycle.

**Responsibilities**:

- Orchestrates manager, indexer, and dashboard components
- Manages TLS certificates with hot reload
- Handles monitoring integration (ServiceMonitors/PodMonitors)
- Implements drain strategy for safe scale-down operations
- Delegates to specialized helper reconcilers

**Reconciliation Flow**:

1. Fetch WazuhCluster CR
2. Handle deletion with finalizers
3. Validate cluster spec
4. Reconcile certificates (CertificateReconciler)
5. Reconcile manager master + workers (ClusterReconciler)
6. Check worker scale-down drain (WorkerReconciler)
7. Reconcile indexer (IndexerReconciler)
8. Reconcile dashboard (DashboardReconciler)
9. Reconcile monitoring (MonitoringReconciler)
10. Update status conditions
11. Requeue based on state (normal: 30s, rollout: 5s, drain: 10s)

**Helper Reconcilers**:

- `ClusterReconciler`: Manager master + worker orchestration (ConfigMaps, Services, StatefulSets, spec hash change detection)
- `CertificateReconciler`: TLS cert generation/renewal
- `IndexerReconciler`: OpenSearch indexer management
- `DashboardReconciler`: Dashboard deployment
- `WorkerReconciler`: Worker drain operations (CheckScaleDownDrain, EvaluateDrainFeasibility)
- `MonitoringReconciler`: Prometheus integration

> **Note**: For WazuhCluster reconciliation, ClusterReconciler handles all manager/worker logic directly.

**RBAC Permissions**:

- WazuhCluster CRs (full access)
- StatefulSets, Deployments (full access)
- Services, ConfigMaps, Secrets (full access)
- PVCs (read + patch for volume expansion)
- ServiceMonitors (Prometheus integration)
- PodDisruptionBudgets (HA)
- RBAC roles/rolebindings

---

## Wazuh Configuration Controllers (5)

### WazuhRule Controller

**controllers/wazuhrule_controller.go**

Manages Wazuh detection rules declaratively.

**Reconciliation**:

1. Validate rule XML
2. Fetch target WazuhCluster
3. Create/update ConfigMap with rules
4. Mount ConfigMap to manager pods at `/var/ossec/etc/rules/`
5. Trigger rule reload via API (no pod restart)

**Targeting**:

- `all`: All manager nodes
- `master`: Master only
- `workers`: Workers only

**Priority**: Higher priority rules are applied later (overlay pattern)

### WazuhDecoder Controller

**controllers/wazuhdecoder_controller.go**

Manages Wazuh log decoders declaratively.

**Reconciliation**:

1. Validate decoder XML
2. Fetch target WazuhCluster
3. Create/update ConfigMap with decoders
4. Mount ConfigMap to manager pods at `/var/ossec/etc/decoders/`
5. Trigger decoder reload via API

### WazuhIntegration Controller

**controllers/wazuhintegration_controller.go**

Provisions Wazuh custom integrations (external API forwarding) declaratively.

**Reconciliation**:

1. Validate name/script (shebang, `custom-` prefix forced)
2. Create/update ConfigMap holding the script (`custom-<name>[.<ext>]`)
3. Resolve `hookURL`/`apiKey` from Secrets in the target cluster namespace
4. Mount the script read-only into `/var/ossec/integrations/` (`root:wazuh` 0750 via DefaultMode + fsGroup)
5. Inject the `<integration>` block into ossec.conf and roll the targeted manager pods (integratord reads config at start)

**Targeting**: `all` / `master` / `workers`

### WazuhCertificate Controller

**controllers/wazuhcertificate_controller.go**

Manages TLS certificates with auto-generation and renewal.

**Reconciliation**:

1. Check existing certificates
2. Generate CA if missing
3. Generate node certificates (indexer, manager, dashboard, filebeat)
4. Store in Secrets
5. Monitor expiry and renew automatically
6. Trigger hot reload (Wazuh 4.9+) or rolling restart

**Certificate Types**:

- Root CA
- Admin certificate (for security plugin)
- Node certificates (per component)
- Filebeat certificate

**Renewal**:

- Automatic renewal N days before expiry (default: 30 days)
- Configurable renewal threshold
- Non-blocking rollouts (production mode)

### WazuhFilebeat Controller

**controllers/wazuhfilebeat_controller.go**

Manages Filebeat configuration for log forwarding.

**Reconciles**:

- ConfigMap (filebeat.yml)
- Index templates (sent to OpenSearch)
- Ingest pipelines (sent to OpenSearch)

---

## Wazuh Backup/Restore Controllers (2)

### WazuhBackup Controller

**controllers/wazuhbackup_controller.go**

Manages Wazuh Manager backups to S3/MinIO.

**Reconciles**:

- CronJob (for scheduled backups) or Job (for one-shot)
- Backups components: agent keys, FIM database, agent database, integrations, alert logs
- Stores as tar.gz in S3/MinIO bucket
- Applies retention policy

**Backup Process**:

1. Create backup Job/CronJob
2. Job mounts manager PVC
3. Tar selected components from `/var/ossec/`
4. Upload to S3/MinIO with configured prefix
5. Update backup status

### WazuhRestore Controller

**controllers/wazuhrestore_controller.go**

Restores Wazuh Manager data from S3/MinIO.

**Reconciles**:

- Restore Job
- Optional pre-restore backup (safety net)
- Stop manager during restore, restart after

**Restore Process**:

1. (Optional) Create pre-restore backup
2. Scale manager to 0 replicas
3. Download tar.gz from S3/MinIO
4. Extract to `/var/ossec/`
5. Scale manager back up
6. Update restore status

---

## OpenSearch Security Controllers (5)

All OpenSearch security controllers interact with the OpenSearch Security Plugin API (`/_plugins/_security/api/`).

### OpenSearchUser Controller

**controllers/opensearchuser_controller.go**

**API Endpoint**: `PUT /_plugins/_security/api/internalusers/{username}`

**Reconciles**:

- Create/update user in OpenSearch
- Hash password from Secret
- Set backend roles and attributes

### OpenSearchRole Controller

**controllers/opensearchrole_controller.go**

**API Endpoint**: `PUT /_plugins/_security/api/roles/{role}`

**Reconciles**:

- Create/update role with cluster/index permissions
- Define allowed actions per index pattern
- Set tenant permissions

### OpenSearchRoleMapping Controller

**controllers/opensearchrolemapping_controller.go**

**API Endpoint**: `PUT /_plugins/_security/api/rolesmapping/{role}`

**Reconciles**:

- Map backend roles to OpenSearch roles
- Map users to roles
- Host-based mapping

### OpenSearchActionGroup Controller

**controllers/opensearchactiongroup_controller.go**

**API Endpoint**: `PUT /_plugins/_security/api/actiongroups/{group}`

**Reconciles**:

- Create reusable action groups
- Bundle permissions for easy role assignment

### OpenSearchTenant Controller

**controllers/opensearchtenant_controller.go**

**API Endpoint**: `PUT /_plugins/_security/api/tenants/{tenant}`

**Reconciles**:

- Create multi-tenancy tenants
- Isolate dashboards and visualizations

### OpenSearchAuthConfig Controller

**controllers/opensearchauthconfig_controller.go**

Manages OpenSearch authentication configuration (LDAP, OIDC, SAML).

**Reconciles**:

- Update `config.yml` in security plugin
- Configure authentication domains
- Reload security configuration

---

## OpenSearch Index Management Controllers (5)

### OpenSearchIndex Controller

**controllers/opensearchindex_controller.go**

**API Endpoint**: `PUT /{index}`

**Reconciles**:

- Create index with settings (shards, replicas, refresh interval)
- Define mappings
- Set aliases

### OpenSearchIndexTemplate Controller

**controllers/opensearchindextemplate_controller.go**

**API Endpoint**: `PUT /_index_template/{template}`

**Reconciles**:

- Create composable index templates
- Define index patterns and priority
- Include component templates

### OpenSearchComponentTemplate Controller

**controllers/opensearchcomponenttemplate_controller.go**

**API Endpoint**: `PUT /_component_template/{template}`

**Reconciles**:

- Create reusable template components
- Share settings/mappings across index templates

### OpenSearchISMPolicy Controller

**controllers/opensearchpolicy_controller.go**

**API Endpoint**: `PUT /_plugins/_ism/policies/{policy}`

**Reconciles**:

- Create Index State Management policies
- Define states, transitions, actions (rollover, delete, snapshot)
- Attach to indices

### OpenSearchSnapshotPolicy Controller

**controllers/opensearchsnapshotpolicy_controller.go**

**API Endpoint**: `PUT /_plugins/_sm/policies/{policy}`

**Reconciles**:

- Create automated snapshot policies
- Schedule snapshots with cron expressions
- Apply retention rules

---

## OpenSearch Backup/Restore Controllers (3)

### OpenSearchSnapshotRepository Controller

**controllers/opensearchsnapshotrepository_controller.go**

**API Endpoint**: `PUT /_snapshot/{repository}`

**Reconciles**:

- Register snapshot repositories (S3, MinIO, Azure, FS)
- Verify repository accessibility
- Configure bucket, endpoint, credentials

### OpenSearchSnapshot Controller

**controllers/opensearchsnapshot_controller.go**

**API Endpoint**: `PUT /_snapshot/{repository}/{snapshot}`

**Reconciles**:

- Trigger manual snapshots
- Auto-generate snapshot names with timestamps
- Monitor snapshot progress
- Update status with completion/failure

### OpenSearchRestore Controller

**controllers/opensearchrestore_controller.go**

**API Endpoint**: `POST /_snapshot/{repository}/{snapshot}/_restore`

**Reconciles**:

- Restore indices from snapshots
- Rename indices during restore (pattern + replacement)
- Close indices before restore if needed
- Monitor restore progress

---

## Reconciliation Patterns

### Standard Reconciliation Loop

```go
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    // 1. Fetch the Custom Resource
    resource := &v1.MyResource{}
    if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // 2. Handle deletion (finalizers)
    if resource.DeletionTimestamp != nil {
        return r.handleDeletion(ctx, resource)
    }

    // 3. Add finalizer if missing
    if !controllerutil.ContainsFinalizer(resource, finalizer) {
        controllerutil.AddFinalizer(resource, finalizer)
        return ctrl.Result{}, r.Update(ctx, resource)
    }

    // 4. Reconcile desired state
    if err := r.reconcileResources(ctx, resource); err != nil {
        r.updateStatusCondition(resource, "Ready", "False", err.Error())
        return ctrl.Result{RequeueAfter: 30*time.Second}, err
    }

    // 5. Update status
    r.updateStatusCondition(resource, "Ready", "True", "Reconciliation successful")

    // 6. Requeue
    return ctrl.Result{RequeueAfter: 30*time.Second}, nil
}
```

### Status Update Pattern

All controllers update status conditions following Kubernetes conventions:

```go
condition := metav1.Condition{
    Type:               "Ready",
    Status:             metav1.ConditionTrue,  // or False/Unknown
    ObservedGeneration: resource.Generation,
    LastTransitionTime: metav1.Now(),
    Reason:             "ReconciliationSucceeded",
    Message:            "All resources reconciled successfully",
}
```

### Finalizer Pattern

All controllers use finalizers to ensure clean deletion:

```go
if resource.DeletionTimestamp != nil {
    if controllerutil.ContainsFinalizer(resource, finalizer) {
        // Cleanup external resources
        if err := r.cleanupResources(ctx, resource); err != nil {
            return ctrl.Result{}, err
        }

        // Remove finalizer
        controllerutil.RemoveFinalizer(resource, finalizer)
        return ctrl.Result{}, r.Update(ctx, resource)
    }
    return ctrl.Result{}, nil
}
```

## Common Requeue Intervals

- **Normal reconciliation**: 30 seconds
- **Rollout in progress**: 5 seconds
- **Drain in progress**: 10 seconds
- **Certificate test mode**: 5 seconds
- **Error/retry**: Exponential backoff (controller-runtime default)

## Metrics

All controllers export Prometheus metrics via `internal/metrics/`:

- `wazuh_reconcile_total`: Total reconciliation count
- `wazuh_reconcile_errors_total`: Error count
- `wazuh_reconcile_duration_seconds`: Reconciliation duration

## RBAC Requirements

Controllers require RBAC permissions for:

- Custom Resources (full CRUD)
- Status subresources (update)
- Finalizers (update)
- Managed Kubernetes resources (StatefulSets, Services, ConfigMaps, Secrets, etc.)

RBAC markers are defined via `+kubebuilder:rbac` comments in controller files.
