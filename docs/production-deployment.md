# Wazuh Operator - Production Deployment Guide

This guide covers best practices for deploying the Wazuh Operator in production environments.

## Table of Contents

- [High Availability](#high-availability)
- [Observability](#observability)
- [Security](#security)
- [Scaling](#scaling)
- [Backup and Restore](#backup-and-restore)
- [External Secrets Integration](#external-secrets-integration)
- [Multi-Cluster Support](#multi-cluster-support)
- [Webhook Validation](#webhook-validation)
- [Finalizers](#finalizers)
- [Health Checks](#health-checks)
- [Troubleshooting](#troubleshooting)

---

## High Availability

### Leader Election

The operator supports leader election for high availability deployments with multiple replicas.

```yaml
# deployment.yaml
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: manager
        args:
        - --leader-elect=true
        - --leader-election-id=wazuh-operator-leader
```

**Flags:**

- `--leader-elect`: Enable leader election (default: false)
- `--leader-election-id`: Unique identifier for the leader election lock (default: "wazuh-operator-leader")

### Pod Disruption Budget

The operator automatically creates PDBs for managed components. You can configure PDBs via the CRD:

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
spec:
  indexer:
    replicas: 3
    podDisruptionBudget:
      minAvailable: 2  # Or use maxUnavailable: 1
```

### Anti-Affinity

Ensure pods are spread across nodes/zones:

```yaml
spec:
  indexer:
    antiAffinity:
      enabled: true
      type: preferredDuringSchedulingIgnoredDuringExecution  # or requiredDuringSchedulingIgnoredDuringExecution
      topologyKey: topology.kubernetes.io/zone  # Spread across zones
```

---

## Observability

### Prometheus Metrics

The operator exposes metrics on `:8080/metrics`. Key metrics include:

**Reconciliation Metrics:**

- `wazuh_reconciler_reconciliations_total` - Total reconciliations by CRD/namespace/result
- `wazuh_reconciler_reconciliation_duration_seconds` - Duration histogram
- `wazuh_reconciler_errors_total` - Error counts by type

**Cluster Health Metrics:**

- `wazuh_cluster_health` - Overall cluster status (0=unknown, 1=red, 2=yellow, 3=green)
- `wazuh_cluster_component_health` - Individual component health
- `wazuh_cluster_ready_replicas` - Ready replicas per component

**Certificate Metrics:**

- `wazuh_certificate_expiry_seconds` - Seconds until certificate expiry
- `wazuh_certificate_renewals_total` - Certificate renewal count

**ServiceMonitor Example:**

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: wazuh-operator
spec:
  selector:
    matchLabels:
      control-plane: controller-manager
  endpoints:
  - port: metrics
    interval: 30s
```

### OpenTelemetry Tracing

Configure tracing via environment variables:

```yaml
env:
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: "http://jaeger-collector:4317"
- name: OTEL_SERVICE_NAME
  value: "wazuh-operator"
- name: OTEL_TRACES_EXPORTER
  value: "otlp"
```

### Structured Logging

Logs are output in JSON format with trace correlation:

```yaml
env:
- name: LOG_FORMAT
  value: "json"  # or "console"
- name: LOG_LEVEL
  value: "info"  # debug, info, warn, error
```

**Log Fields:**

- `timestamp`, `level`, `logger`, `caller`, `message`
- `trace_id`, `span_id`, `trace_sampled` (when tracing enabled)
- `cluster`, `namespace`, `component` (context fields)

### Grafana Dashboard

Recommended dashboard panels:

1. **Reconciliation Rate** - `rate(wazuh_reconciler_reconciliations_total[5m])`
2. **Error Rate** - `rate(wazuh_reconciler_errors_total[5m])`
3. **Cluster Health** - `wazuh_cluster_health`
4. **Certificate Expiry** - `wazuh_certificate_expiry_seconds / 86400` (days)
5. **Component Readiness** - `wazuh_cluster_ready_replicas / wazuh_cluster_desired_replicas`

### Alerting Rules

```yaml
groups:
- name: wazuh-operator
  rules:
  - alert: WazuhClusterUnhealthy
    expr: wazuh_cluster_health < 3
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Wazuh cluster {{ $labels.cluster }} is unhealthy"

  - alert: WazuhCertificateExpiringSoon
    expr: wazuh_certificate_expiry_seconds < 604800  # 7 days
    labels:
      severity: warning
    annotations:
      summary: "Certificate {{ $labels.certificate }} expires in less than 7 days"

  - alert: WazuhReconcileErrors
    expr: rate(wazuh_reconciler_errors_total[5m]) > 0.1
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Wazuh operator experiencing reconciliation errors"
```

---

## Security

### RBAC

The operator requires the following permissions (auto-generated via kubebuilder):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wazuh-operator-manager-role
rules:
- apiGroups: ["resources.wazuh.com"]
  resources: ["*"]
  verbs: ["*"]
- apiGroups: ["apps"]
  resources: ["statefulsets", "deployments"]
  verbs: ["*"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["*"]
# ... see config/rbac/role.yaml for complete list
```

### Network Policies

Example network policy for the operator:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: wazuh-operator
spec:
  podSelector:
    matchLabels:
      control-plane: controller-manager
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - port: 8080  # metrics
  egress:
  - to:
    - namespaceSelector: {}  # Allow to all namespaces (for API access)
```

### Pod Security Standards

The operator is compatible with restricted Pod Security Standards:

```yaml
securityContext:
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault
containers:
- securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop: ["ALL"]
    readOnlyRootFilesystem: true
```

---

## Scaling

### Horizontal Pod Autoscaler

HPA is supported for Dashboard, Wazuh Workers, and Indexer.

**Dashboard HPA:**

```yaml
spec:
  dashboard:
    replicas: 2
    hpa:
      enabled: true
      minReplicas: 2
      maxReplicas: 10
      targetCPUUtilizationPercentage: 80
      targetMemoryUtilizationPercentage: 80
```

**Wazuh Manager Workers HPA:**

```yaml
spec:
  manager:
    workers:
      replicas: 2
      hpa:
        enabled: true
        minReplicas: 2
        maxReplicas: 10
        targetCPUUtilizationPercentage: 80
        targetMemoryUtilizationPercentage: 70
```

> **Note:** The Manager Master cannot be scaled (single instance). Only workers support HPA.

**Indexer HPA (Use with Caution):**

```yaml
spec:
  indexer:
    replicas: 3
    hpa:
      enabled: true
      minReplicas: 3
      maxReplicas: 9
      targetCPUUtilizationPercentage: 70
      behavior:
        scaleDown:
          stabilizationWindowSeconds: 300  # 5 minutes
        scaleUp:
          stabilizationWindowSeconds: 120  # 2 minutes
```

> **Warning:** HPA for Indexer (StatefulSet) requires careful consideration as OpenSearch needs shard rebalancing after scaling. Ensure you have a proper shard allocation strategy.

**HPA Spec Options:**

| Field                                           | Description                         | Default |
| ----------------------------------------------- | ----------------------------------- | ------- |
| `enabled`                                       | Enable HPA                          | `false` |
| `minReplicas`                                   | Minimum replicas                    | `1`     |
| `maxReplicas`                                   | Maximum replicas                    | `10`    |
| `targetCPUUtilizationPercentage`                | Target CPU %                        | `80`    |
| `targetMemoryUtilizationPercentage`             | Target memory %                     | -       |
| `behavior.scaleDown.stabilizationWindowSeconds` | Stabilization window for scale down | -       |
| `behavior.scaleUp.stabilizationWindowSeconds`   | Stabilization window for scale up   | -       |

### Rate Limiting

Configure reconciliation rate limiting via environment variables:

```yaml
env:
- name: RATE_LIMIT_ENABLED
  value: "true"
- name: RATE_LIMIT_MAX_CONCURRENT
  value: "3"
- name: RATE_LIMIT_QPS
  value: "10.0"
- name: RATE_LIMIT_BURST
  value: "100"
- name: RATE_LIMIT_BASE_DELAY
  value: "5ms"
- name: RATE_LIMIT_MAX_DELAY
  value: "1000s"
```

### Resource Recommendations

**Operator:**

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

**Indexer Nodes (per pod):**

```yaml
resources:
  requests:
    cpu: 1000m
    memory: 2Gi
  limits:
    cpu: 2000m
    memory: 4Gi
```

---

## Backup and Restore

### Scheduled Backups

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhBackup
metadata:
  name: daily-backup
spec:
  clusterRef:
    name: my-wazuh-cluster
  schedule: "0 2 * * *"  # Daily at 2 AM
  components:
  - AgentKeys
  - FIMDatabase
  - AlertLogs
  retention:
    keepLast: 7
    keepDaily: 7
    keepWeekly: 4
```

### One-Shot Backup

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhBackup
metadata:
  name: pre-upgrade-backup
spec:
  clusterRef:
    name: my-wazuh-cluster
  # No schedule = one-shot Job
  components:
  - AgentKeys
  - FIMDatabase
  - AgentDatabase
```

### Restore

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhRestore
metadata:
  name: restore-from-backup
spec:
  clusterRef:
    name: my-wazuh-cluster
  backupRef:
    name: daily-backup
  components:
  - AgentKeys
  - FIMDatabase
```

---

## External Secrets Integration

The operator supports External Secrets Operator (ESO) for integration with external secret providers (Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).

### Setup ESO

1. Install External Secrets Operator:

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets
```

1. Create a SecretStore (example for Vault):

```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "wazuh-operator"
```

### Use External Secrets in WazuhCluster

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
spec:
  indexer:
    credentials:
      externalSecretRef:
        name: wazuh-indexer-credentials
        secretStoreRef:
          name: vault-backend
          kind: SecretStore
        remoteRef:
          key: "secret/data/wazuh/indexer"
        refreshInterval: "1h"
      usernameKey: "username"
      passwordKey: "password"
```

The operator will read credentials from the K8s Secret created by ESO.

---

## Multi-Cluster Support

### Namespace-Scoped Watching

By default, the operator watches all namespaces. To restrict to specific namespaces:

```yaml
env:
- name: WATCH_NAMESPACES
  value: "wazuh-prod,wazuh-staging"
```

### Multiple Clusters in Same Namespace

Multiple WazuhCluster resources can coexist in the same namespace. Each cluster is isolated via labels:

- `wazuh.com/cluster: <cluster-name>` - Applied to all managed resources
- `app.kubernetes.io/instance: <cluster-name>` - Standard Kubernetes label

**Best Practices:**

1. Use unique cluster names within each namespace
2. Configure anti-affinity to spread across nodes
3. Use ResourceQuotas to limit resource consumption per cluster

### Cross-Namespace References

Components can reference resources in other namespaces:

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  namespace: wazuh-prod
spec:
  managerRef:
    name: shared-manager
    namespace: wazuh-shared
```

> **Note:** Ensure the operator has RBAC permissions in referenced namespaces.

---

## Webhook Validation

The operator includes admission webhooks for validating WazuhCluster resources.

### Validation Rules

The webhook validates:

- **Version format:** Must be semver (e.g., `4.9.2`)
- **Configuration mode:** Cannot mix inline and reference modes
- **Component specifications:** Manager, Indexer, Dashboard configs
- **TLS configuration:** custom certificates and auto-generated certs
- **Topology changes:** Prevents invalid mode transitions

### Example Validation Errors

```bash
# Mixed mode error
Error: spec: cannot mix inline configuration (manager, indexer, dashboard)
       with references (managerRef, indexerRef, dashboardRef)

# Invalid version
Error: spec.version: must be in semver format (e.g., 4.9.2)
```

### Webhook Configuration

Webhooks require a CA bundle for TLS. Configure it in the Helm values:

```yaml
webhook:
  enabled: true
  failurePolicy: Fail
  caBundle: "<base64-encoded-CA-bundle>"
```

---

## Finalizers

The operator uses finalizers to ensure proper cleanup of resources.

### Managed Finalizers

Each CRD has a dedicated finalizer:

| Resource            | Finalizer                                           |
| ------------------- | --------------------------------------------------- |
| WazuhCluster        | `wazuhcluster.resources.wazuh.com/finalizer`        |
| WazuhManager        | `wazuhmanager.resources.wazuh.com/finalizer`        |
| WazuhBackup         | `wazuhbackup.resources.wazuh.com/finalizer`         |
| OpenSearchIndexer   | `opensearchindexer.resources.wazuh.com/finalizer`   |
| OpenSearchDashboard | `opensearchdashboard.resources.wazuh.com/finalizer` |

### Cleanup Behavior

When a resource is deleted:

1. Finalizer prevents immediate deletion
2. Operator performs cleanup (PVCs, secrets, etc.)
3. Finalizer is removed
4. Resource is deleted

### Force Deletion

If cleanup is stuck, you can remove the finalizer manually:

```bash
kubectl patch wazuhcluster my-cluster -p '{"metadata":{"finalizers":[]}}' --type=merge
```

> **Warning:** This skips cleanup and may leave orphaned resources.

---

## Health Checks

The operator implements health checks for OpenSearch components.

### Indexer Health

The operator monitors cluster health via the OpenSearch API:

```bash
# Check cluster health
curl -k -u admin:password https://indexer:9200/_cluster/health
```

Health states:

- **Green:** All primary and replica shards allocated
- **Yellow:** All primary shards allocated, some replicas missing
- **Red:** Some primary shards not allocated

### Dashboard Health

Dashboard health is checked via the status endpoint:

```bash
curl -k https://dashboard:5601/api/status
```

### Health Check Configuration

Health checks run automatically during reconciliation. The operator:

1. Waits for green/yellow status before applying settings
2. Reports health via metrics (`wazuh_cluster_health`)
3. Updates status conditions based on health

---

## Troubleshooting

### Common Issues

1. **Cluster stuck in Provisioning:**

   - Check operator logs: `kubectl logs -l control-plane=controller-manager`
   - Verify PVCs are bound: `kubectl get pvc`
   - Check events: `kubectl get events --sort-by='.lastTimestamp'`

2. **Certificate errors:**

   - Verify TLS secrets exist: `kubectl get secrets -l app.kubernetes.io/managed-by=wazuh-operator`
   - Check certificate expiry in operator logs
   - Verify certificate files in pods: `kubectl exec <pod> -- ls /etc/ssl/certs/`

3. **Indexer cluster health red:**
   - Check shard allocation: `curl -k https://indexer:9200/_cluster/allocation/explain`
   - Verify all nodes are up: `kubectl get pods -l app.kubernetes.io/component=indexer`

### Debug Mode

Enable debug logging:

```yaml
env:
- name: LOG_LEVEL
  value: "debug"
```

### Metrics Endpoint

Check operator health via metrics:

```bash
kubectl port-forward svc/wazuh-operator-controller-manager-metrics 8080:8080
curl localhost:8080/metrics | grep wazuh_
```

---

## Support

- GitHub Issues: <https://github.com/MaximeWewer/wazuh-operator/issues>
- Documentation: <https://github.com/MaximeWewer/wazuh-operator/tree/main/docs>
