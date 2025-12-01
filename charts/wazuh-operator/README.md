# Wazuh Operator Helm Chart

This Helm chart deploys the Wazuh Kubernetes Operator for managing Wazuh clusters.

## Documentation

For complete documentation, examples, and guides, see:

- **[User Documentation](../../docs/usage/README.md)** - Full usage guide
- **[Getting Started](../../docs/usage/getting-started/)** - Installation and quick start
- **[CRD Reference](../../docs/usage/CRD-REFERENCE.md)** - Complete API documentation

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Deployment Modes](#deployment-modes)
- [Values](#values)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

## Features

- **Flexible Deployment Modes**: Deploy CRDs only, operator only, or both
- **Simple Architecture**: One operator manages one WazuhCluster per namespace
- **Metrics & Monitoring**: Prometheus metrics with ServiceMonitor support
- **Security**: Pod security contexts, RBAC, and security best practices
- **Customizable**: Extensive configuration options via values.yaml

## Prerequisites

- Kubernetes 1.24+
- Helm 3.10+
- (Optional) Prometheus Operator for ServiceMonitor support

## Quick Start

### Install with Default Settings (CRDs + Operator)

```bash
helm install wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-operator \
  --create-namespace
```

### Install CRDs Only

```bash
helm install wazuh-crds ./charts/wazuh-operator \
  --set deploymentMode=crds \
  --namespace wazuh-system \
  --create-namespace
```

### Install Operator Only (CRDs already exist)

```bash
helm install wazuh-operator ./charts/wazuh-operator \
  --set deploymentMode=operator \
  --set crds.install=false \
  --namespace wazuh-operator \
  --create-namespace
```

## Deployment Modes

The chart supports three deployment modes via the `deploymentMode` value.

### Mode 1: `all` (Default)

Deploys both CRDs and the operator.

```yaml
deploymentMode: "all"
crds:
  install: true
operator:
  enabled: true
```

**Use when:**

- First time installation
- Single deployment for everything

### Mode 2: `crds`

Deploys only CRDs (no operator).

```yaml
deploymentMode: "crds"
crds:
  install: true
operator:
  enabled: false
```

**Use when:**

- Centralized CRD management
- You want to manage CRDs separately from the operator

### Mode 3: `operator`

Deploys only the operator (assumes CRDs already exist).

```yaml
deploymentMode: "operator"
crds:
  install: false
operator:
  enabled: true
```

**Use when:**

- CRDs are already installed
- You want to manage the operator independently

## Values

### Deployment Mode

| Parameter        | Description                                   | Default |
| ---------------- | --------------------------------------------- | ------- |
| `deploymentMode` | Deployment mode: `all`, `crds`, or `operator` | `"all"` |

### CRD Configuration

| Parameter          | Description            | Default |
| ------------------ | ---------------------- | ------- |
| `crds.install`     | Install CRDs           | `true`  |
| `crds.keep`        | Keep CRDs on uninstall | `true`  |
| `crds.annotations` | Annotations for CRDs   | `{}`    |

### Operator Configuration

| Parameter                   | Description                | Default                |
| --------------------------- | -------------------------- | ---------------------- |
| `operator.enabled`          | Enable operator deployment | `true`                 |
| `operator.image.repository` | Operator image repository  | `wazuh/wazuh-operator` |
| `operator.image.tag`        | Operator image tag         | `""` (uses appVersion) |
| `operator.image.pullPolicy` | Image pull policy          | `IfNotPresent`         |
| `operator.name`             | Operator name              | `"wazuh-operator"`     |

**Note**: Operator replicas is hardcoded to `1` in the deployment template. The operator is designed to manage one WazuhCluster per instance.

### Resources

| Parameter                            | Description    | Default |
| ------------------------------------ | -------------- | ------- |
| `operator.resources.limits.cpu`      | CPU limit      | `500m`  |
| `operator.resources.limits.memory`   | Memory limit   | `512Mi` |
| `operator.resources.requests.cpu`    | CPU request    | `100m`  |
| `operator.resources.requests.memory` | Memory request | `128Mi` |

### Metrics

| Parameter                       | Description          | Default     |
| ------------------------------- | -------------------- | ----------- |
| `operator.metrics.enabled`      | Enable metrics       | `true`      |
| `operator.metrics.bindAddress`  | Metrics bind address | `":8080"`   |
| `operator.metrics.service.type` | Metrics service type | `ClusterIP` |
| `operator.metrics.service.port` | Metrics service port | `8080`      |

### ServiceMonitor

| Parameter                               | Description           | Default |
| --------------------------------------- | --------------------- | ------- |
| `operator.serviceMonitor.enabled`       | Enable ServiceMonitor | `false` |
| `operator.serviceMonitor.labels`        | ServiceMonitor labels | `{}`    |
| `operator.serviceMonitor.interval`      | Scrape interval       | `30s`   |
| `operator.serviceMonitor.scrapeTimeout` | Scrape timeout        | `10s`   |

### RBAC

| Parameter         | Description           | Default               |
| ----------------- | --------------------- | --------------------- |
| `rbac.create`     | Create RBAC resources | `true`                |
| `rbac.roleName`   | Role name             | `""` (auto-generated) |
| `rbac.extraRules` | Additional RBAC rules | `[]`                  |

### Service Account

| Parameter                             | Description                 | Default               |
| ------------------------------------- | --------------------------- | --------------------- |
| `operator.serviceAccount.create`      | Create service account      | `true`                |
| `operator.serviceAccount.name`        | Service account name        | `""` (auto-generated) |
| `operator.serviceAccount.annotations` | Service account annotations | `{}`                  |

## Upgrading

### Upgrade with Helm

```bash
helm upgrade wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-operator
```

### Upgrade CRDs

CRDs are not automatically upgraded by Helm. To upgrade CRDs:

```bash
# Method 1: Using Helm template
helm template wazuh-operator ./charts/wazuh-operator \
  --set deploymentMode=crds \
  --namespace wazuh-system | kubectl apply -f -

# Method 2: Using kubectl
kubectl apply -f charts/wazuh-operator/crds/
```

## Uninstalling

### Uninstall Operator

```bash
helm uninstall wazuh-operator --namespace wazuh-operator
```

### Uninstall CRDs (if installed separately)

```bash
helm uninstall wazuh-crds --namespace wazuh-system
```

**Warning**: If `crds.keep=true` (default), CRDs will not be deleted automatically. To manually delete:

```bash
# Wazuh Core CRDs
kubectl delete crd wazuhclusters.resources.wazuh.com
kubectl delete crd wazuhmanagers.resources.wazuh.com
kubectl delete crd wazuhindexers.resources.wazuh.com
kubectl delete crd wazuhdashboards.resources.wazuh.com
kubectl delete crd wazuhcertificates.resources.wazuh.com
kubectl delete crd wazuhdecoders.resources.wazuh.com
kubectl delete crd wazuhrules.resources.wazuh.com

# OpenSearch CRDs
kubectl delete crd opensearchusers.resources.wazuh.com
kubectl delete crd opensearchroles.resources.wazuh.com
kubectl delete crd opensearchrolemappings.resources.wazuh.com
kubectl delete crd opensearchactiongroups.resources.wazuh.com
kubectl delete crd opensearchtenants.resources.wazuh.com
kubectl delete crd opensearchindextemplates.resources.wazuh.com
kubectl delete crd opensearchcomponenttemplates.resources.wazuh.com
kubectl delete crd opensearchismpolicies.resources.wazuh.com
kubectl delete crd opensearchindices.resources.wazuh.com
kubectl delete crd opensearchsnapshotpolicies.resources.wazuh.com
```

## Troubleshooting

### 1. CRDs Not Found

**Error**: CRDs are not installed

**Solution**:

```bash
# Verify CRDs are installed
kubectl get crds | grep resources.wazuh.com

# If missing, install CRDs
helm upgrade wazuh-operator ./charts/wazuh-operator --set crds.install=true --force
```

### 2. Operator Not Starting

**Error**: Operator pod is not starting

**Solution**:

```bash
# Check operator logs
kubectl logs -n wazuh-operator deployment/wazuh-operator-controller-manager

# Check pod events
kubectl describe pod -n wazuh-operator -l app.kubernetes.io/name=wazuh-operator

# Verify RBAC permissions
kubectl auth can-i create wazuhclusters.resources.wazuh.com --as=system:serviceaccount:wazuh-operator:wazuh-operator
```

### 3. Metrics Not Available

**Error**: Metrics endpoint not accessible

**Solution**:

```bash
# Verify metrics are enabled
helm get values wazuh-operator -n wazuh-operator

# Check metrics service
kubectl get svc -n wazuh-operator

# Test metrics endpoint
kubectl port-forward -n wazuh-operator svc/wazuh-operator-metrics 8080:8080
curl http://localhost:8080/metrics
```

## Architecture

The operator follows a simple architecture:

- **One Operator** → **One WazuhCluster** per namespace
- **No High Availability** (single replica, hardcoded)
- **No Leader Election** (disabled in code)
- **Automatic Namespace Detection** (from WazuhCluster resource location)

For managing multiple Wazuh clusters, deploy separate operator instances in different namespaces.

## License

Apache 2.0

## Links

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh GitHub](https://github.com/wazuh/wazuh-kubernetes)
- [Support Forum](https://groups.google.com/g/wazuh)
