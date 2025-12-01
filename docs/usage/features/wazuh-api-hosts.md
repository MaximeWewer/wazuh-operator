# Wazuh Multi-API Hosts Configuration

This guide explains how to configure multiple Wazuh Manager API endpoints in the Dashboard.

## Overview

The Wazuh Dashboard can connect to multiple Wazuh Manager APIs simultaneously. This is useful for:

- **Multi-cluster monitoring**: Monitor multiple Wazuh clusters from a single dashboard
- **High availability**: Configure fallback API endpoints
- **Distributed deployments**: Connect to geographically distributed managers

## Configuration

### Basic Configuration (Default API Endpoint)

For simple deployments, use `defaultApiEndpoint` to automatically configure the dashboard to connect to the manager API:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.9.0"
  dashboard:
    wazuhPlugin:
      defaultApiEndpoint:
        credentialsSecret:
          secretName: wazuh-api-credentials
          usernameKey: username
          passwordKey: password
        port: 55000
        runAs: false
```

The operator automatically generates the API URL based on the manager service name.

### Multi-API Hosts Configuration

For advanced deployments with multiple API endpoints:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.9.0"
  dashboard:
    wazuhPlugin:
      # Multiple API endpoints
      apiEndpoints:
        # Primary manager (master)
        - id: "wazuh-master"
          url: "https://wazuh-manager-master"
          port: 55000
          credentialsSecretRef:
            secretName: wazuh-api-credentials
            usernameKey: username
            passwordKey: password
          runAs: false

        # Secondary manager (worker or external)
        - id: "wazuh-worker-1"
          url: "https://wazuh-manager-worker-0"
          port: 55000
          credentialsSecretRef:
            secretName: wazuh-api-credentials
          runAs: false

        # External Wazuh cluster
        - id: "external-wazuh"
          url: "https://external-wazuh.example.com"
          port: 55000
          username: "wazuh-wui"
          password: "MyPassword123"
          runAs: true
```

### Configuration Options

#### WazuhPluginConfig

| Field                | Type   | Default             | Description                                |
| -------------------- | ------ | ------------------- | ------------------------------------------ |
| `enabled`            | bool   | `true`              | Enable Wazuh plugin                        |
| `defaultApiEndpoint` | object | -                   | Default API endpoint config                |
| `apiEndpoints`       | array  | -                   | Multiple API endpoints (overrides default) |
| `pattern`            | string | `wazuh-alerts-*`    | Default index pattern                      |
| `timeout`            | int    | `20000`             | API response timeout (ms, min: 1500)       |
| `ipSelector`         | bool   | `true`              | Allow index pattern change from menu       |
| `ipIgnore`           | array  | -                   | Index patterns to hide                     |
| `hideManagerAlerts`  | bool   | `false`             | Hide manager alerts in visualizations      |
| `alertsSamplePrefix` | string | `wazuh-alerts-4.x-` | Sample alert index prefix                  |
| `enrollmentDns`      | string | -                   | Agent enrollment server                    |
| `enrollmentPassword` | string | -                   | Agent enrollment password                  |
| `cronPrefix`         | string | `wazuh`             | Cron job index prefix                      |
| `updatesDisabled`    | bool   | `false`             | Disable update check                       |

#### WazuhAPIEndpoint

| Field                  | Type   | Default      | Description                          |
| ---------------------- | ------ | ------------ | ------------------------------------ |
| `id`                   | string | **Required** | Unique endpoint identifier           |
| `url`                  | string | **Required** | API URL (without port)               |
| `port`                 | int    | `55000`      | API port                             |
| `username`             | string | `wazuh-wui`  | Username (plain text)                |
| `password`             | string | -            | Password (plain text, prefer secret) |
| `credentialsSecretRef` | object | -            | Credentials from Kubernetes Secret   |
| `runAs`                | bool   | `false`      | Enable RBAC run_as                   |

#### DefaultAPIEndpointConfig

| Field               | Type   | Default | Description             |
| ------------------- | ------ | ------- | ----------------------- |
| `credentialsSecret` | object | -       | Credentials from Secret |
| `port`              | int    | `55000` | API port                |
| `runAs`             | bool   | `false` | Enable RBAC run_as      |

## Credentials Management

### Auto-Generated Credentials

When monitoring with Wazuh exporter is enabled, the operator automatically generates a **20-character random password** with special characters for the Wazuh API.

```bash
# Get auto-generated API password
kubectl get secret -n wazuh wazuh-api-credentials \
  -o jsonpath='{.data.password}' | base64 -d

# Get API username (always "wazuh")
kubectl get secret -n wazuh wazuh-api-credentials \
  -o jsonpath='{.data.username}' | base64 -d
```

> **Security Note:** The operator never uses hardcoded default passwords like "wazuh". All passwords are cryptographically generated and include at least one special character from: `. * + ? -`

For more details, see the [Credentials Management Guide](credentials.md).

### Using Kubernetes Secrets (Custom Credentials)

```yaml
# Create a custom secret
apiVersion: v1
kind: Secret
metadata:
  name: wazuh-api-credentials
  namespace: wazuh
type: Opaque
stringData:
  username: wazuh-wui
  password: MySecurePassword.123
---
# Reference in WazuhCluster
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  dashboard:
    wazuhPlugin:
      apiEndpoints:
        - id: "default"
          url: "https://wazuh-manager-master"
          credentialsSecretRef:
            secretName: wazuh-api-credentials
            usernameKey: username
            passwordKey: password
```

### Custom Secret Keys

```yaml
credentialsSecretRef:
  secretName: my-wazuh-secret
  usernameKey: api_user # Custom key for username
  passwordKey: api_pass # Custom key for password
```

## Monitoring Configuration

Configure monitoring settings for the Wazuh plugin:

```yaml
dashboard:
  wazuhPlugin:
    monitoring:
      enabled: true
      frequency: 900 # Seconds between API requests (min: 60)
      pattern: "wazuh-monitoring-*"
      creation: "w" # h=hourly, d=daily, w=weekly, m=monthly
      shards: 1
      replicas: 0
```

## Health Checks Configuration

Control which health checks are performed:

```yaml
dashboard:
  wazuhPlugin:
    checks:
      pattern: true # Validate index patterns
      template: true # Verify index template
      api: true # Test API connectivity
      setup: true # Confirm version compatibility
      fields: true # Verify document fields
      metaFields: true # Check metadata fields
      timeFilter: true # Ensure time range is configured
      maxBuckets: true # Verify aggregation limits
```

## Cron Statistics Configuration

Configure statistics collection:

```yaml
dashboard:
  wazuhPlugin:
    cronStatistics:
      status: true
      apis: [] # Specific APIs for stats (empty = all)
      interval: "0 */5 * * * *" # Cron expression
      indexName: "statistics"
      indexCreation: "w" # h, d, w, or m
      shards: 1
      replicas: 0
```

## Use Cases

### Scenario 1: Single Manager with Workers

```yaml
dashboard:
  wazuhPlugin:
    apiEndpoints:
      - id: "master"
        url: "https://wazuh-manager-master"
        port: 55000
        credentialsSecretRef:
          secretName: wazuh-api-creds
```

The dashboard connects to the master API which provides cluster-wide information.

### Scenario 2: Multiple Independent Clusters

```yaml
dashboard:
  wazuhPlugin:
    apiEndpoints:
      - id: "production"
        url: "https://wazuh-prod.internal"
        port: 55000
        credentialsSecretRef:
          secretName: prod-api-creds
      - id: "staging"
        url: "https://wazuh-staging.internal"
        port: 55000
        credentialsSecretRef:
          secretName: staging-api-creds
      - id: "development"
        url: "https://wazuh-dev.internal"
        port: 55000
        credentialsSecretRef:
          secretName: dev-api-creds
```

### Scenario 3: External Wazuh Servers

```yaml
dashboard:
  wazuhPlugin:
    apiEndpoints:
      # Local cluster managed by operator
      - id: "local"
        url: "https://wazuh-manager-master"
        credentialsSecretRef:
          secretName: local-api-creds
      # External on-premise Wazuh
      - id: "on-premise-dc1"
        url: "https://wazuh.dc1.company.com"
        port: 55000
        username: "api-user"
        password: "SecurePass"
      # Cloud-hosted Wazuh
      - id: "cloud-wazuh"
        url: "https://wazuh.cloud.company.com"
        port: 55000
        credentialsSecretRef:
          secretName: cloud-api-creds
```

## Generated Configuration

The operator generates `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`:

```yaml
hosts:
  - wazuh-master:
      url: https://wazuh-manager-master
      port: 55000
      username: wazuh-wui
      password: <from-secret>
      run_as: false
  - external-wazuh:
      url: https://external-wazuh.example.com
      port: 55000
      username: wazuh-wui
      password: <password>
      run_as: true
```

## Troubleshooting

### API Connection Failed

```bash
# Check dashboard logs
kubectl logs -n wazuh -l app.kubernetes.io/component=wazuh-dashboard

# Verify manager API is accessible
kubectl exec -n wazuh wazuh-dashboard-xxx -- \
  curl -sk -u wazuh-wui:password https://wazuh-manager-master:55000/

# Check generated wazuh.yml
kubectl exec -n wazuh wazuh-dashboard-xxx -- \
  cat /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

### Credentials Not Applied

```bash
# Verify secret exists
kubectl get secret -n wazuh wazuh-api-credentials -o yaml

# Check secret is mounted correctly
kubectl describe pod -n wazuh wazuh-dashboard-xxx
```

## See Also

- [Dashboard Configuration](../CRD-REFERENCE.md#wazuhdashboardclusterspec)
- [Monitoring Guide](monitoring.md)
- [TLS Configuration](tls.md)
