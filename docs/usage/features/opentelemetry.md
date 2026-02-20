# OpenTelemetry Distributed Tracing

## Overview

The Wazuh Operator supports OpenTelemetry distributed tracing, allowing you to monitor and debug operator behavior by collecting traces of reconciliation loops and API calls.

## Features

- **Automatic HTTP tracing**: All HTTP calls to OpenSearch and Wazuh APIs are automatically traced
- **Reconciliation spans**: Each controller reconciliation loop creates a root span with cluster information
- **Helper reconciler spans**: Child spans for all helper reconcilers (indexer, dashboard, manager, certificates, monitoring, networking, etc.) with error recording
- **Trace-log correlation**: All logs within a traced reconciliation automatically include `trace_id` and `span_id` fields for cross-referencing with your tracing backend
- **Error recording**: Reconciliation errors are automatically attached to their spans via `RecordError`
- **Configurable sampling**: Control trace volume with a sampling ratio (0.0 to 1.0)
- **OTLP export**: Traces are exported via gRPC to any OTLP-compatible collector
- **Conditional activation**: Tracing is only enabled when an endpoint is configured

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (disabled) | OTLP gRPC endpoint (e.g., `jaeger-collector:4317`) |
| `OTEL_EXPORTER_OTLP_INSECURE` | `false` | Use insecure connection (no TLS) |
| `OTEL_SERVICE_NAME` | `wazuh-operator` | Service name in traces |
| `OTEL_SERVICE_VERSION` | `0.1.0` | Service version in traces |
| `OTEL_TRACES_SAMPLER_ARG` | `1.0` | Sampling ratio (0.0-1.0). `1.0` = sample all, `0.5` = 50%, `0.0` = sample none |

### Helm Configuration

```yaml
# values.yaml
telemetry:
  # Enable OpenTelemetry tracing
  enabled: true

  # OTLP exporter endpoint (gRPC)
  endpoint: "jaeger-collector.observability:4317"

  # Use insecure connection (no TLS)
  insecure: true

  # Service name reported in traces
  serviceName: "wazuh-operator"

  # Service version reported in traces
  serviceVersion: ""  # Defaults to chart appVersion

  # Trace sampling ratio (0.0-1.0)
  # 1.0 = sample all traces, 0.5 = 50%, 0.0 = none
  samplingRatio: "1.0"
```

## Deployment Examples

### With Jaeger

Deploy Jaeger in your cluster:

```bash
# Install Jaeger operator
kubectl create namespace observability
kubectl apply -f https://github.com/jaegertracing/jaeger-operator/releases/download/v1.65.0/jaeger-operator.yaml -n observability

# Create Jaeger instance
kubectl apply -f - <<EOF
apiVersion: jaegertracing.io/v1
kind: Jaeger
metadata:
  name: jaeger
  namespace: observability
spec:
  strategy: allInOne
  allInOne:
    image: jaegertracing/all-in-one:latest
EOF
```

Configure the operator:

```yaml
# values.yaml
telemetry:
  enabled: true
  endpoint: "jaeger-collector.observability:4317"
  insecure: true
  samplingRatio: "1.0"  # Sample all traces (default)
```

Access Jaeger UI:

```bash
kubectl port-forward -n observability svc/jaeger-query 16686:16686
# Open http://localhost:16686
```

### With Grafana Tempo

```yaml
# values.yaml
telemetry:
  enabled: true
  endpoint: "tempo.monitoring:4317"
  insecure: true
```

### With OpenTelemetry Collector

```yaml
# values.yaml
telemetry:
  enabled: true
  endpoint: "otel-collector.monitoring:4317"
  insecure: true
```

## Trace Sampling

The operator uses `OTEL_TRACES_SAMPLER_ARG` to control the sampling strategy:

| Value | Sampler | Description |
|-------|---------|-------------|
| `1.0` (default) | `AlwaysSample` | Every reconciliation is traced |
| `0.5` | `ParentBased(TraceIDRatioBased(0.5))` | 50% of traces are sampled |
| `0.0` | `NeverSample` | Tracing disabled (no spans exported) |

For production environments with high reconciliation rates, set a lower ratio to reduce trace volume:

```yaml
telemetry:
  enabled: true
  endpoint: "tempo.monitoring:4317"
  samplingRatio: "0.1"  # Sample 10% of traces
```

## Traced Operations

### Controller Spans (Root)

Each controller reconciliation creates a root span with:

- **Name**: `<Controller>.Reconcile` (e.g., `WazuhCluster.Reconcile`, `OpenSearchUser.Reconcile`)
- **Attributes**:
  - `namespace`: Cluster namespace
  - `name`: Cluster name
  - `cluster.version`: Wazuh version (WazuhCluster only)
  - `cluster.phase`: Current cluster phase (WazuhCluster only)
- **Error recording**: Reconciliation errors are automatically attached to the span

### Helper Reconciler Spans (Children)

Helper reconcilers create child spans nested under the controller span:

| Span Name | Source |
|-----------|--------|
| `IndexerReconciler.Reconcile` | Indexer StatefulSet reconciliation |
| `IndexerReconciler.ReconcileNonBlocking` | Indexer ISM policies, templates, etc. |
| `IndexerReconciler.OrchestrateRollingRestart` | Indexer rolling restart |
| `DashboardReconciler.Reconcile` | Dashboard Deployment reconciliation |
| `ClusterReconciler.ReconcileManager` | Manager master StatefulSet |
| `ClusterReconciler.ReconcileManagerNonBlocking` | Manager volume expansion, etc. |
| `ClusterReconciler.ReconcileCertificates` | Certificate reconciliation |
| `ClusterReconciler.ReconcileLogRotation` | Log rotation ConfigMaps |
| `WorkerReconciler.ReconcileStandalone` | Worker StatefulSet (standalone mode) |
| `UserReconciler.Reconcile` | OpenSearch internal user |
| `RoleReconciler.Reconcile` | OpenSearch role |
| `RoleMappingReconciler.Reconcile` | OpenSearch role mapping |
| `ActionGroupReconciler.Reconcile` | OpenSearch action group |
| `TenantReconciler.Reconcile` | OpenSearch tenant |
| `AuthConfigReconciler.Reconcile` | OpenSearch auth config |
| `PolicyReconciler.Reconcile` | ISM policy |
| `IndexReconciler.Reconcile` | OpenSearch index |
| `TemplateReconciler.Reconcile` | Index template |
| `ComponentTemplateReconciler.Reconcile` | Component template |
| `SnapshotPolicyReconciler.Reconcile` | Snapshot policy (SLM) |
| `SnapshotRepositoryReconciler.Reconcile` | Snapshot repository |
| `ManualSnapshotReconciler.Reconcile` | Manual snapshot |
| `RestoreReconciler.Reconcile` | Snapshot restore |
| `CertificateReconciler.ReconcileWithHashes` | Certificate generation |
| `GatewayReconciler.Reconcile` | Gateway API resources |
| `IngressReconciler.Reconcile` | Ingress resources |
| `NetworkPolicyReconciler.Reconcile` | NetworkPolicy resources |
| `MonitoringReconciler.Reconcile` | ServiceMonitor resources |

### Trace-Log Correlation

All logs emitted during a traced reconciliation automatically include `trace_id` and `span_id` fields. This allows you to jump from a log line to the corresponding trace in your backend.

Example log output:

```json
{"level":"info","ts":"...","msg":"Reconciling indexer","trace_id":"abc123...","span_id":"def456..."}
```

In Grafana, use the Tempo/Loki integration to correlate logs and traces automatically.

### HTTP Client Spans

All HTTP calls are automatically traced:

| Client | Span Name Pattern |
|--------|-------------------|
| OpenSearch API | `opensearch-api GET /path` |
| Wazuh API | `wazuh-api POST /path` |
| OpenSearch HTTP | `opensearch-http GET /path` |

## Viewing Traces

### In Jaeger

1. Select service: `wazuh-operator`
2. Filter by operation: `WazuhCluster.Reconcile`
3. View trace timeline with nested HTTP calls

### In Grafana (with Tempo)

1. Go to Explore > Tempo
2. Search: `service.name="wazuh-operator"`
3. View trace details and service graph

## Troubleshooting

For tracing issues, see [Common Issues](../troubleshooting/common-issues.md).

**Quick checks:**

```bash
# Check operator logs for OTEL
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager | grep -i otel

# Verify environment variables
kubectl get deploy wazuh-operator-controller-manager -n wazuh-system -o yaml | grep -A5 OTEL
```

### High Trace Volume

Reduce the sampling ratio to control trace volume:

```yaml
telemetry:
  samplingRatio: "0.1"  # Only sample 10% of traces
```

Alternatively, configure sampling rules on your collector side.

## Integration with Prometheus Metrics

OpenTelemetry traces complement Prometheus metrics:

| Metric Type | Use Case |
|-------------|----------|
| **Prometheus** | Aggregated counts, rates, latencies |
| **OpenTelemetry** | Individual request traces, debugging |

Both can be enabled simultaneously for full observability.

## Security Considerations

- Use TLS in production (`insecure: false`)
- Ensure network policies allow egress to collector
- Traces may contain sensitive resource names - secure your tracing backend

## Related Documentation

- [Monitoring](./monitoring.md) - Prometheus metrics integration
- [Debugging Guide](../troubleshooting/debugging.md) - Troubleshooting techniques
