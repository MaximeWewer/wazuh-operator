# wazuh-operator

## Prerequisites

- Kubernetes 1.25+
- Helm 3
- (Optional) Prometheus Operator for ServiceMonitor support
- (Optional) Custom CA bundle for webhook TLS

## Documentation

| Resource                                             | Description                  |
| ---------------------------------------------------- | ---------------------------- |
| [User Documentation](../../docs/usage/README.md)     | Full usage guide             |
| [Getting Started](../../docs/usage/getting-started/) | Installation and quick start |
| [CRD Reference](../../docs/usage/CRD-REFERENCE.md)   | Complete API documentation   |

## Installation

### Quick Start (CRDs + Operator)

> **Note:** Some CRDs exceed 256 KB and require `--server-side` apply.
> Use `helm template | kubectl apply --server-side` instead of `helm install`.

```bash
helm template wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-operator | kubectl apply --server-side -f -
```

### Install CRDs Only

```bash
helm template wazuh-operator ./charts/wazuh-operator \
  --set operator.enabled=false \
  --namespace wazuh-operator | kubectl apply --server-side -f -
```

### Install Operator Only

```bash
helm template wazuh-operator ./charts/wazuh-operator \
  --set crds.install=false \
  --namespace wazuh-operator | kubectl apply --server-side -f -
```

## Upgrading

```bash
helm template wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-operator | kubectl apply --server-side -f -
```

### Upgrade CRDs

CRDs are managed as regular templates and are upgraded with `helm template | kubectl apply --server-side`.
To upgrade CRDs separately:

```bash
helm template wazuh-operator ./charts/wazuh-operator \
  --set operator.enabled=false | kubectl apply --server-side -f -
```

## Uninstallation

```bash
kubectl delete -f <(helm template wazuh-operator ./charts/wazuh-operator --namespace wazuh-operator)
```

> **Warning:** If `crds.keep=true` (default), CRDs will not be deleted automatically.

## Values

### Name Overrides

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| fullnameOverride | string | `""` | Override the full name of the release |
| nameOverride | string | `""` | Override the name of the chart |

### CRD Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| crds.install | bool | `true` | Install CRDs as part of the chart. Set to false if CRDs are managed separately. |

### Operator Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| operator.affinity | object | `{}` | Affinity for operator pod |
| operator.clusterDomain | string | `"cluster.local"` | Kubernetes cluster DNS domain. Change if using custom CoreDNS configuration. |
| operator.enabled | bool | `true` | Enable operator deployment. Set to false for CRD-only deployment. |
| operator.env | list | `[]` | Environment variables for operator container |
| operator.extraVolumeMounts | list | `[]` | Extra volume mounts |
| operator.extraVolumes | list | `[]` | Extra volumes |
| operator.healthProbe.livenessProbe.initialDelaySeconds | int | `15` | Initial delay before liveness probing |
| operator.healthProbe.livenessProbe.periodSeconds | int | `20` | Liveness probe interval |
| operator.healthProbe.port | int | `8081` | Health probe port |
| operator.healthProbe.readinessProbe.initialDelaySeconds | int | `5` | Initial delay before readiness probing |
| operator.healthProbe.readinessProbe.periodSeconds | int | `10` | Readiness probe interval |
| operator.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| operator.image.repository | string | `"ghcr.io/maximewewer/wazuh-operator"` | Operator image repository |
| operator.image.tag | string | `""` | Image tag (defaults to chart appVersion) |
| operator.imagePullSecrets | list | `[]` | Image pull secrets for private registries |
| operator.logging.format | string | `"json"` | Log format: "json" (production) or "console" (human-readable) |
| operator.logging.level | string | `"info"` | Log level: "debug", "info", "warn", "error" |
| operator.metrics.enabled | bool | `true` | Enable Prometheus metrics |
| operator.metrics.port | int | `8080` | Metrics port |
| operator.metrics.service.annotations | object | `{}` | Metrics service annotations |
| operator.metrics.service.type | string | `"ClusterIP"` | Metrics service type |
| operator.name | string | `"wazuh-operator"` | Operator name |
| operator.nodeSelector | object | `{}` | Node selector for operator pod |
| operator.podAnnotations | object | `{}` | Pod annotations |
| operator.podSecurityContext.runAsNonRoot | bool | `true` | Run as non-root user |
| operator.podSecurityContext.seccompProfile.type | string | `"RuntimeDefault"` | Seccomp profile type |
| operator.prometheusRules.alerts.certExpired.for | string | `"5m"` |  |
| operator.prometheusRules.alerts.certExpired.severity | string | `"critical"` |  |
| operator.prometheusRules.alerts.certExpiringSoon.for | string | `"1h"` |  |
| operator.prometheusRules.alerts.certExpiringSoon.severity | string | `"warning"` |  |
| operator.prometheusRules.alerts.certExpiringSoon.threshold | int | `30` |  |
| operator.prometheusRules.alerts.certExpiryCritical.for | string | `"1h"` |  |
| operator.prometheusRules.alerts.certExpiryCritical.severity | string | `"critical"` |  |
| operator.prometheusRules.alerts.certExpiryCritical.threshold | int | `7` |  |
| operator.prometheusRules.alerts.clusterCritical.for | string | `"2m"` |  |
| operator.prometheusRules.alerts.clusterCritical.labels | object | `{}` |  |
| operator.prometheusRules.alerts.clusterCritical.runbookUrl | string | `""` |  |
| operator.prometheusRules.alerts.clusterCritical.severity | string | `"critical"` |  |
| operator.prometheusRules.alerts.clusterUnhealthy.for | string | `"5m"` |  |
| operator.prometheusRules.alerts.clusterUnhealthy.labels | object | `{}` |  |
| operator.prometheusRules.alerts.clusterUnhealthy.runbookUrl | string | `""` |  |
| operator.prometheusRules.alerts.clusterUnhealthy.severity | string | `"warning"` |  |
| operator.prometheusRules.alerts.componentUnhealthy.for | string | `"5m"` |  |
| operator.prometheusRules.alerts.componentUnhealthy.severity | string | `"warning"` |  |
| operator.prometheusRules.alerts.operatorDown.for | string | `"5m"` |  |
| operator.prometheusRules.alerts.operatorDown.severity | string | `"critical"` |  |
| operator.prometheusRules.alerts.reconcileDuration.for | string | `"15m"` |  |
| operator.prometheusRules.alerts.reconcileDuration.severity | string | `"warning"` |  |
| operator.prometheusRules.alerts.reconcileDuration.threshold | int | `60` |  |
| operator.prometheusRules.alerts.reconcileErrors.for | string | `"10m"` |  |
| operator.prometheusRules.alerts.reconcileErrors.severity | string | `"warning"` |  |
| operator.prometheusRules.alerts.reconcileErrors.threshold | float | `0.1` |  |
| operator.prometheusRules.alerts.replicasMismatch.for | string | `"10m"` |  |
| operator.prometheusRules.alerts.replicasMismatch.severity | string | `"warning"` |  |
| operator.prometheusRules.enabled | bool | `false` | Enable PrometheusRule resource |
| operator.prometheusRules.labels | object | `{}` | Additional labels for PrometheusRule |
| operator.rateLimiting.baseDelay | string | `"5ms"` | Base delay for exponential backoff on failures |
| operator.rateLimiting.burst | int | `100` | Burst size for rate limiter bucket |
| operator.rateLimiting.enabled | bool | `true` | Enable rate limiting |
| operator.rateLimiting.maxConcurrentReconciles | int | `3` | Maximum concurrent reconciliations per controller |
| operator.rateLimiting.maxDelay | string | `"1000s"` | Maximum delay for exponential backoff |
| operator.rateLimiting.qps | int | `10` | Queries per second limit |
| operator.resources.limits.cpu | string | `"500m"` | CPU limit |
| operator.resources.limits.memory | string | `"512Mi"` | Memory limit |
| operator.resources.requests.cpu | string | `"100m"` | CPU request |
| operator.resources.requests.memory | string | `"128Mi"` | Memory request |
| operator.securityContext.allowPrivilegeEscalation | bool | `false` | Prevent privilege escalation |
| operator.securityContext.capabilities.drop | list | `["ALL"]` | Drop all capabilities |
| operator.securityContext.readOnlyRootFilesystem | bool | `true` | Read-only root filesystem |
| operator.serviceAccount.annotations | object | `{}` | Service account annotations |
| operator.serviceAccount.create | bool | `true` | Create service account |
| operator.serviceAccount.name | string | `""` | Service account name (auto-generated if empty) |
| operator.serviceMonitor.enabled | bool | `false` | Enable ServiceMonitor for Prometheus Operator |
| operator.serviceMonitor.interval | string | `"30s"` | Scrape interval |
| operator.serviceMonitor.labels | object | `{}` | Additional labels for ServiceMonitor |
| operator.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout |
| operator.tolerations | list | `[]` | Tolerations for operator pod |
| operator.vmMaxMapCount | int | `262144` | vm.max_map_count kernel parameter for OpenSearch. Init container sets this if system value is lower. |
| operator.watchNamespaces | list | `[]` | List of namespaces to watch. Empty list watches all namespaces (cluster-scoped RBAC). Non-empty list watches only listed namespaces (namespace-scoped RBAC). |

### RBAC Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| rbac.create | bool | `true` | Create RBAC resources |
| rbac.extraRules | list | `[]` | Additional rules for the operator role |
| rbac.roleName | string | `""` | Role name (auto-generated if empty) |

### Namespace Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| namespace.annotations | object | `{}` | Namespace annotations |
| namespace.create | bool | `false` | Create namespace for operator |
| namespace.labels | object | `{}` | Namespace labels |
| namespace.name | string | `""` | Namespace name (defaults to Release.Namespace) |

### Common Labels & Annotations

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| commonAnnotations | object | `{}` | Additional annotations to add to all resources |
| commonLabels | object | `{}` | Additional labels to add to all resources |

### OpenTelemetry Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| telemetry.enabled | bool | `false` | Enable OpenTelemetry distributed tracing |
| telemetry.endpoint | string | `""` | OTLP exporter endpoint (gRPC). Examples: "jaeger-collector.observability:4317", "otel-collector.monitoring:4317" |
| telemetry.insecure | bool | `true` | Use insecure connection (no TLS). Set to true for local development or service mesh. |
| telemetry.samplingRatio | string | `"1.0"` | Trace sampling ratio (0.0-1.0). 1.0 = sample all, 0.5 = 50%. |
| telemetry.serviceName | string | `"wazuh-operator"` | Service name reported in traces |
| telemetry.serviceVersion | string | `""` | Service version reported in traces (defaults to chart appVersion) |

### Gateway API Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| gatewayAPI.enabled | bool | `false` | Enable Gateway API support. When enabled, operator watches HTTPRoute, TCPRoute, UDPRoute resources. |

### Advanced Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| extraArgs | list | `[]` |  |
| nonBlockingRollouts | bool | `true` | Enable non-blocking rollouts for parallel certificate renewals |
| terminationGracePeriodSeconds | int | `10` | Termination grace period in seconds |

### High Availability Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| leaderElection.enabled | bool | `false` | Enable leader election (REQUIRED when replicaCount > 1) |
| leaderElection.id | string | `"wazuh-operator-leader"` | Leader election lease name |
| replicaCount | int | `1` | Number of operator replicas. For HA, set > 1 AND enable leaderElection. |

### Update Strategy Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| updateStrategy.rollingUpdate.maxSurge | int | `1` | Max extra pods during update |
| updateStrategy.rollingUpdate.maxUnavailable | int | `0` | Max unavailable pods during update |
| updateStrategy.type | string | `"RollingUpdate"` | Update strategy type |

### Network Policy Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| networkPolicy.apiServer.cidr | string | `"0.0.0.0/0"` | CIDR for API server access |
| networkPolicy.enabled | bool | `false` | Enable NetworkPolicy for operator namespace |
| networkPolicy.managedNamespaces | list | `[]` | Managed namespaces (where Wazuh clusters run). If empty, allows egress to all namespaces. |
| networkPolicy.prometheus.namespaceSelector | object | `{}` | Namespace selector for Prometheus pods |
| networkPolicy.prometheus.podSelector | object | `{}` | Pod selector for Prometheus pods |

### Resource Quota Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| resourceQuota.configmaps | string | `"20"` | Maximum ConfigMaps in namespace |
| resourceQuota.enabled | bool | `false` | Enable ResourceQuota and LimitRange for operator namespace |
| resourceQuota.limitRange.default.cpu | string | `"500m"` | Default CPU limit |
| resourceQuota.limitRange.default.memory | string | `"512Mi"` | Default memory limit |
| resourceQuota.limitRange.defaultRequest.cpu | string | `"100m"` | Default CPU request |
| resourceQuota.limitRange.defaultRequest.memory | string | `"128Mi"` | Default memory request |
| resourceQuota.limitRange.max.cpu | string | `"2"` | Maximum CPU per container |
| resourceQuota.limitRange.max.memory | string | `"4Gi"` | Maximum memory per container |
| resourceQuota.limitRange.min.cpu | string | `"50m"` | Minimum CPU per container |
| resourceQuota.limitRange.min.memory | string | `"64Mi"` | Minimum memory per container |
| resourceQuota.limits.cpu | string | `"4"` | Total CPU limits |
| resourceQuota.limits.memory | string | `"8Gi"` | Total memory limits |
| resourceQuota.pods | string | `"10"` | Maximum number of pods in namespace |
| resourceQuota.requests.cpu | string | `"2"` | Total CPU requests limit |
| resourceQuota.requests.memory | string | `"4Gi"` | Total memory requests limit |
| resourceQuota.secrets | string | `"20"` | Maximum Secrets in namespace |
| resourceQuota.services | string | `"10"` | Maximum Services in namespace |

### Admission Webhook Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| webhook.caBundle | string | `""` | CA bundle for webhook TLS |
| webhook.enabled | bool | `false` | Enable admission webhooks for CR validation |
| webhook.failurePolicy | string | `"Fail"` | Failure policy: Fail or Ignore |
| webhook.namespaceSelector | object | `{}` | Namespace selector to limit webhook scope |

## Examples

### High Availability Deployment

```yaml
replicaCount: 3

leaderElection:
  enabled: true
  id: "wazuh-operator-leader"

operator:
  resources:
    limits:
      cpu: 1
      memory: 1Gi
    requests:
      cpu: 200m
      memory: 256Mi
```

### With Prometheus Monitoring

```yaml
operator:
  metrics:
    enabled: true
    port: 8080

  serviceMonitor:
    enabled: true
    labels:
      prometheus: kube-prometheus
    interval: "30s"

  prometheusRules:
    enabled: true
    alerts:
      clusterUnhealthy:
        for: "5m"
        severity: warning
      operatorDown:
        for: "5m"
        severity: critical
```

### With Gateway API Support

```yaml
gatewayAPI:
  enabled: true
```

> **Note:** Requires Gateway API CRDs to be installed:
>
> ```bash
> kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml
> kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/experimental-install.yaml
> ```

### With OpenTelemetry Tracing

```yaml
telemetry:
  enabled: true
  endpoint: "jaeger-collector.observability:4317"
  insecure: true
  serviceName: "wazuh-operator"
```

### With Network Policy

```yaml
networkPolicy:
  enabled: true
  prometheus:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: monitoring
    podSelector:
      matchLabels:
        app.kubernetes.io/name: prometheus
  managedNamespaces:
    - wazuh
    - wazuh-prod
```

### Namespace-Scoped Deployment

```yaml
operator:
  watchNamespaces:
    - wazuh-prod
    - wazuh-staging
    - wazuh-dev
```

> **Note:** When `operator.watchNamespaces` is set, the operator creates namespace-scoped
> Role/RoleBinding per namespace instead of cluster-wide ClusterRole/ClusterRoleBinding.

## Deployment Modes

| Configuration                                     | Description            | Use Case                                     |
| ------------------------------------------------- | ---------------------- | -------------------------------------------- |
| `crds.install=true, operator.enabled=true`        | Deploy CRDs + Operator | First-time installation, single deployment   |
| `crds.install=true, operator.enabled=false`       | Deploy CRDs only       | Centralized CRD management, GitOps workflows |
| `crds.install=false, operator.enabled=true`       | Deploy Operator only   | CRDs already exist, operator-only updates    |

## Architecture

- **One Operator** manages multiple **WazuhCluster** resources across namespaces
- **High Availability** via `replicaCount > 1` + `leaderElection.enabled`
- **Leader Election** ensures only one active replica (others standby)
- **Automatic Namespace Detection** from WazuhCluster resource location

## Troubleshooting

### CRDs Not Found

```bash
# Verify CRDs
kubectl get crds | grep resources.wazuh.com

# Install if missing
helm template wazuh-operator ./charts/wazuh-operator \
  --set operator.enabled=false | kubectl apply --server-side -f -
```

### Operator Not Starting

```bash
# Check logs
kubectl logs -n wazuh-operator deployment/wazuh-operator-controller-manager

# Check events
kubectl describe pod -n wazuh-operator -l app.kubernetes.io/name=wazuh-operator

# Verify RBAC
kubectl auth can-i create wazuhclusters.resources.wazuh.com \
  --as=system:serviceaccount:wazuh-operator:wazuh-operator
```

### Namespace Stuck Terminating After CRD API Version Upgrade

If you previously deployed with an older API version (e.g., `v1alpha1`) and upgraded
CRDs to `v1`, Kubernetes may fail to delete old resources stored with the previous
version, causing the namespace to stay in `Terminating` state with an error like:

```text
failed to list resources.wazuh.com/v1, Kind=WazuhCluster: request to convert
CR from an invalid group/version: resources.wazuh.com/v1alpha1
```

To resolve this:

```bash
# 1. Delete all Wazuh CRDs to remove the stored version tracking
kubectl delete crds $(kubectl get crds -o name | grep resources.wazuh.com)

# 2. If the namespace is still stuck, remove its finalizer
kubectl get namespace <namespace> -o json \
  | jq '.spec.finalizers = []' \
  | kubectl replace --raw "/api/v1/namespaces/<namespace>/finalize" -f -

# 3. Reinstall CRDs with the current version
helm template wazuh-operator ./charts/wazuh-operator \
  --set operator.enabled=false | kubectl apply --server-side -f -
```

### Metrics Not Available

```bash
# Verify metrics enabled
helm get values wazuh-operator -n wazuh-operator

# Test endpoint
kubectl port-forward -n wazuh-operator svc/wazuh-operator-metrics 8080:8080
curl http://localhost:8080/metrics
```

## Support

- [GitHub Issues](https://github.com/MaximeWewer/wazuh-operator/issues)
- [Wazuh Documentation](https://documentation.wazuh.com/)
