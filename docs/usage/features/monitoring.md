# Prometheus Monitoring

The Wazuh Operator supports Prometheus monitoring through two exporters and ServiceMonitor integration.

## Overview

Monitoring can be enabled for both Wazuh Manager and OpenSearch Indexer components:

- **Wazuh Exporter**: Sidecar container that exposes Wazuh API metrics
- **Indexer Exporter**: OpenSearch Prometheus plugin for cluster metrics
- **ServiceMonitor**: Prometheus Operator integration for automatic scraping

## Configuration

Enable monitoring in the WazuhCluster spec:

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.9.0"
  monitoring:
    enabled: true
    wazuhExporter:
      enabled: true
      image: "kennyopennix/wazuh-exporter:latest"
      port: 9090
      apiProtocol: "https"
      apiVerifySSL: false
      logLevel: "INFO"
    indexerExporter:
      enabled: true
    serviceMonitor:
      enabled: true
      labels:
        release: prometheus
      interval: "30s"
      scrapeTimeout: "10s"
```

## Wazuh Exporter

The Wazuh exporter is deployed as a sidecar container on the manager master pod. It queries the Wazuh API and exposes metrics in Prometheus format.

### Configuration Options

| Field                     | Type                 | Default                                     | Description                        |
| ------------------------- | -------------------- | ------------------------------------------- | ---------------------------------- |
| `enabled`                 | bool                 | `false`                                     | Enable Wazuh exporter sidecar      |
| `image`                   | string               | `kennyopennix/wazuh-exporter:latest` | Exporter image                     |
| `port`                    | int32                | `9090`                                      | Metrics port                       |
| `apiProtocol`             | string               | `https`                                     | Wazuh API protocol                 |
| `apiVerifySSL`            | bool                 | `false`                                     | Verify SSL certificates            |
| `logLevel`                | string               | `INFO`                                      | Log level                          |
| `resources`               | ResourceRequirements | -                                           | Container resources                |
| `skipLastLogs`            | bool                 | `false`                                     | Skip last logs metrics             |
| `skipLastRegisteredAgent` | bool                 | `false`                                     | Skip last registered agent metrics |
| `skipWazuhAPIInfo`        | bool                 | `false`                                     | Skip Wazuh API info metrics        |

### Available Metrics

The Wazuh exporter provides metrics including:

- Agent status (active, disconnected, pending, never connected)
- Agent count by OS and version
- Cluster node status
- API request statistics
- Alert statistics

Example metrics:

```text
wazuh_agents_active_total 150
wazuh_agents_disconnected_total 5
wazuh_cluster_nodes_total 3
wazuh_api_requests_total{method="GET"} 1234
```

## Indexer Exporter

The OpenSearch Prometheus plugin exposes cluster health, node stats, and index metrics.

### Configuration Options

| Field     | Type   | Default       | Description                         |
| --------- | ------ | ------------- | ----------------------------------- |
| `enabled` | bool   | `false`       | Enable OpenSearch Prometheus plugin |
| `version` | string | Auto-detected | Plugin version                      |

### Available Metrics

The indexer exporter provides metrics including:

- Cluster health and status
- Node statistics (JVM, filesystem, network)
- Index statistics (document count, size, operations)
- Thread pool statistics
- Circuit breaker status

Example metrics:

```text
opensearch_cluster_health_status{cluster="wazuh"} 1
opensearch_indices_docs_total{index="wazuh-alerts-*"} 1000000
opensearch_jvm_memory_used_bytes{node="indexer-0"} 536870912
```

## ServiceMonitor

When enabled, the operator creates ServiceMonitor resources for automatic Prometheus scraping.

### Configuration Options

| Field           | Type              | Default | Description                     |
| --------------- | ----------------- | ------- | ------------------------------- |
| `enabled`       | bool              | `false` | Create ServiceMonitor resources |
| `labels`        | map[string]string | -       | Labels for service discovery    |
| `interval`      | string            | `30s`   | Scrape interval                 |
| `scrapeTimeout` | string            | `10s`   | Scrape timeout                  |

### Prometheus Operator Integration

The ServiceMonitor requires the Prometheus Operator to be installed. Configure the labels to match your Prometheus selector:

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: prometheus # Match your Prometheus selector
```

## Grafana Dashboards

Example Grafana dashboards are available in `config/monitoring/`:

- `wazuh-overview.json` - Wazuh cluster overview
- `opensearch-cluster.json` - OpenSearch cluster health

## Verifying Monitoring

### Check Exporter Pods

```bash
# Check Wazuh exporter sidecar
kubectl get pods -n wazuh -l app.kubernetes.io/component=wazuh-manager -o yaml | grep wazuh-exporter

# Check indexer pods
kubectl get pods -n wazuh -l app.kubernetes.io/component=wazuh-indexer
```

### Check ServiceMonitors

```bash
kubectl get servicemonitors -n wazuh
```

### Test Metrics Endpoint

```bash
# Port-forward to exporter
kubectl port-forward -n wazuh svc/wazuh-cluster-manager-master 9090:9090

# Query metrics
curl http://localhost:9090/metrics
```

### Check Prometheus Targets

In the Prometheus UI, navigate to Status > Targets to verify the Wazuh targets are being scraped.

## Troubleshooting

For monitoring issues, see [Common Issues](../troubleshooting/common-issues.md).

**Quick checks:**

```bash
# Check exporter logs
kubectl logs -n wazuh <manager-pod> -c wazuh-exporter

# Verify ServiceMonitor
kubectl get servicemonitor -n wazuh

# Test metrics endpoint
kubectl exec -n wazuh <manager-pod> -c wazuh-exporter -- wget -qO- http://localhost:9090/metrics
```

## Operator Health Probes

The operator itself exposes health endpoints on port `8081` used by Kubernetes liveness and readiness probes.

| Endpoint | Probe | Description |
|----------|-------|-------------|
| `/healthz` | Liveness | Returns OK if the process is running (`ping` check) |
| `/readyz` | Readiness | Returns OK when all checks pass (see below) |

### Readiness Checks

| Check | Description |
|-------|-------------|
| `ping` | Always passes |
| `informer-sync` | Kubernetes informer cache has fully synced |
| `reconcile-watchdog` | Reconcile loop has run within the last 5 minutes |
| `leader-election` | Instance is the elected leader (only when `--leader-elect` is enabled) |

### Verifying Health

```bash
kubectl port-forward -n wazuh-operator deploy/wazuh-operator-controller-manager 8081:8081
curl http://localhost:8081/readyz?verbose
```

Expected output:

```text
[+]informer-sync ok
[+]ping ok
[+]reconcile-watchdog ok
healthz check passed
```

### Helm Configuration

Health probe timing is configurable in `values.yaml`:

```yaml
operator:
  healthProbe:
    port: 8081
    livenessProbe:
      initialDelaySeconds: 15
      periodSeconds: 20
    readinessProbe:
      initialDelaySeconds: 30
      periodSeconds: 10
```

## Operator Metrics

The operator exposes its own Prometheus metrics (reconciliation counts, queue depth, etc.) on a configurable port.

### Configuration

```yaml
operator:
  metrics:
    enabled: true
    port: 8080
    secure: false  # Serve metrics over HTTPS (default: false)
  serviceMonitor:
    enabled: true
    interval: "30s"
    scrapeTimeout: "10s"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `metrics.enabled` | bool | `true` | Enable operator metrics endpoint |
| `metrics.port` | int | `8080` | Metrics port |
| `metrics.secure` | bool | `false` | Serve metrics over HTTPS instead of HTTP |
| `serviceMonitor.enabled` | bool | `false` | Create a ServiceMonitor for the operator |

> **Note:** When `metrics.secure` is `true`, the ServiceMonitor is automatically configured with
> `scheme: https` and `insecureSkipVerify: true`. When `false` (default), Prometheus scrapes
> over plain HTTP.
>
> If you see `http: TLS handshake error ... client sent an HTTP request to an HTTPS server` in
> operator logs, it means Prometheus is scraping with HTTP but the operator is serving HTTPS.
> Set `metrics.secure: false` to resolve this.

## Related Documentation

- [OpenTelemetry](./opentelemetry.md) - Distributed tracing for debugging reconciliation loops and API calls
