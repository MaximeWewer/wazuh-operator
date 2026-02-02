# OpenTelemetry Distributed Tracing

## Overview

The Wazuh Operator supports OpenTelemetry distributed tracing, allowing you to monitor and debug operator behavior by collecting traces of reconciliation loops and API calls.

## Features

- **Automatic HTTP tracing**: All HTTP calls to OpenSearch and Wazuh APIs are automatically traced
- **Reconciliation spans**: Each reconciliation loop creates a span with cluster information
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
```

## Deployment Examples

### With Jaeger

Deploy Jaeger in your cluster:

```bash
# Install Jaeger operator
kubectl create namespace observability
kubectl apply -f https://github.com/jaegertracing/jaeger-operator/releases/download/v1.51.0/jaeger-operator.yaml -n observability

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
    image: jaegertracing/all-in-one:1.51
EOF
```

Configure the operator:

```yaml
# values.yaml
telemetry:
  enabled: true
  endpoint: "jaeger-collector.observability:4317"
  insecure: true
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

## Traced Operations

### Reconciliation Spans

Each `WazuhCluster` reconciliation creates a span with:

- **Name**: `WazuhCluster.Reconcile`
- **Attributes**:
  - `namespace`: Cluster namespace
  - `name`: Cluster name
  - `cluster.version`: Wazuh version
  - `cluster.phase`: Current cluster phase

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

For production, configure your collector to sample traces.

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
