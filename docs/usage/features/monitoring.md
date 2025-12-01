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
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.9.0"
  monitoring:
    enabled: true
    wazuhExporter:
      enabled: true
      image: "pytoshka/wazuh-prometheus-exporter:latest"
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
| `image`                   | string               | `pytoshka/wazuh-prometheus-exporter:latest` | Exporter image                     |
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

```
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

```
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

### Exporter Not Starting

1. Check pod logs:

   ```bash
   kubectl logs -n wazuh <manager-pod> -c wazuh-exporter
   ```

2. Verify API credentials are correct

### ServiceMonitor Not Discovered

1. Verify labels match Prometheus selector:

   ```bash
   kubectl get prometheus -o yaml | grep serviceMonitorSelector
   ```

2. Check ServiceMonitor in correct namespace:
   ```bash
   kubectl get servicemonitor -n wazuh
   ```

### Metrics Not Available

1. Check exporter is running:

   ```bash
   kubectl exec -n wazuh <manager-pod> -c wazuh-exporter -- wget -qO- http://localhost:9090/metrics
   ```

2. Verify network connectivity between Prometheus and pods
