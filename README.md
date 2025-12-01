# Wazuh Kubernetes Operator

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.24+-blue.svg)](https://kubernetes.io/)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://golang.org/)

A Kubernetes operator for managing Wazuh clusters, providing a declarative way to deploy and configure Wazuh security monitoring platforms.

## Features

- **Declarative Cluster Management**: Define your entire Wazuh cluster using Kubernetes custom resources
- **Automated Deployment**: Automatically provisions Manager (master/workers), Indexer, and Dashboard components
- **Rule & Decoder Management**: Manage Wazuh detection rules and log decoders as Kubernetes resources
- **OpenSearch Security CRDs**: Manage users, roles, role mappings, and tenants declaratively
- **Index Lifecycle Management**: Configure ISM policies, index templates, and snapshot policies via CRDs
- **TLS Automation**: Auto-generated certificates with hot reload support (Wazuh 4.9+)
- **Log Rotation**: Automated log cleanup via CronJob with configurable retention
- **High Availability**: Built-in support for multi-node deployments with pod disruption budgets
- **Monitoring Ready**: Prometheus exporters and ServiceMonitor integration
- **Upgrade Management**: Rolling updates with zero-downtime upgrades
- **Helm Charts**: Both operator and cluster deployment via Helm

## Architecture

The Wazuh operator manages three main components:

```
┌───────────────────────────────────────────────────┐
│                  WazuhCluster                     │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐   │
│  │  Manager   │  │  Indexer   │  │ Dashboard  │   │
│  │ Master+    │  │  (Modified │  │ (Modified  │   │
│  │ Workers    │  │ OpenSearch)│  │ OpenSearch │   │
│  └────────────┘  └────────────┘  │ Dashboard) │   │
│                                  └────────────┘   │
└───────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Kubernetes 1.24+
- kubectl configured to access your cluster
- 16GB+ RAM recommended
- Storage provisioner for PersistentVolumeClaims

### Installation

#### Using Helm (Recommended)

The Helm charts are published to GitHub Container Registry (GHCR):

- **Operator chart**: `oci://ghcr.io/maximewewer/charts/wazuh-operator`
- **Cluster chart**: `oci://ghcr.io/maximewewer/charts/wazuh-cluster`

1. **Install the operator**:

```bash
# From OCI registry (recommended)
helm install wazuh-operator oci://ghcr.io/maximewewer/charts/wazuh-operator \
  -n wazuh-system --create-namespace

# Or from local chart
helm install wazuh-operator ./charts/wazuh-operator -n wazuh-system --create-namespace
```

2. **Verify installation**:

```bash
kubectl get pods -n wazuh-system
```

3. **Deploy a Wazuh cluster**:

```bash
# From OCI registry (recommended)
helm install wazuh-cluster oci://ghcr.io/maximewewer/charts/wazuh-cluster \
  -n wazuh --create-namespace

# Or from local chart
helm install wazuh-cluster ./charts/wazuh-cluster -n wazuh --create-namespace
```

> **Note:** Credentials (OpenSearch admin, Wazuh API) are automatically generated. See [Credentials Management](docs/usage/features/credentials.md) for details.

#### Using kubectl

1. **Install the operator CRDs**:

```bash
kubectl apply -f config/crd/
```

2. **Install RBAC resources**:

```bash
kubectl apply -f config/rbac/
```

3. **Deploy the operator**:

```bash
kubectl apply -f config/manager/manager.yaml
```

4. **Verify installation**:

```bash
kubectl get pods -n wazuh-system
```

### Deploy a Wazuh Cluster

1. **Create a WazuhCluster resource**:

```bash
kubectl apply -f config/samples/wazuh_v1alpha1_wazuhcluster.yaml
```

2. **Check deployment status**:

```bash
# Watch the cluster status
kubectl get wazuhcluster -w

# Get detailed status
kubectl describe wazuhcluster wazuh-cluster-sample

# Check all pods
kubectl get pods -l app.kubernetes.io/instance=wazuh-cluster-sample
```

3. **Access the Dashboard**:

```bash
# Port-forward to dashboard
kubectl port-forward svc/wazuh-cluster-sample-dashboard 5601:5601
```

Open https://localhost:5601 in your browser.

Credentials:

- Username: `admin`
- Password: Auto-generated. Retrieve from secret:

```bash
# Get the auto-generated admin password
kubectl get secret wazuh-cluster-sample-indexer-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d && echo
```

> **Security:** All passwords are cryptographically generated. There are no default passwords like "admin" or "wazuh".

## Custom Resource Definitions

**API Group**: `resources.wazuh.com/v1alpha1`

The operator provides 17 CRDs organized into categories:

| Category                | CRDs                                                                                                                 | Short Names                            |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| **Wazuh Core**          | WazuhCluster, WazuhManager, WazuhIndexer, WazuhDashboard                                                             | wc, wmgr, widx, wdash                  |
| **Wazuh Config**        | WazuhRule, WazuhDecoder, WazuhCertificate                                                                            | wrule, wdec, wcert                     |
| **OpenSearch Security** | OpenSearchUser, OpenSearchRole, OpenSearchRoleMapping, OpenSearchActionGroup, OpenSearchTenant                       | osuser, osrole, osrmap, osag, ostenant |
| **OpenSearch Index**    | OpenSearchIndexTemplate, OpenSearchComponentTemplate, OpenSearchISMPolicy, OpenSearchIndex, OpenSearchSnapshotPolicy | osidxt, osctpl, osism, osidx, ossnap   |

### WazuhCluster

The main CRD for deploying a complete Wazuh cluster. Supports inline or reference mode.

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: my-wazuh
spec:
  version: "4.14.0"

  # Inline mode - define components directly
  manager:
    master:
      storageSize: 50Gi
      resources:
        requests:
          cpu: 500m
          memory: 512Mi
    workers:
      replicas: 2
      storageSize: 50Gi

  indexer:
    replicas: 3
    storageSize: 50Gi
    resources:
      requests:
        cpu: 500m
        memory: 1Gi

  dashboard:
    replicas: 2
    resources:
      requests:
        cpu: 500m
        memory: 512Mi
```

Or use **reference mode** with separate component CRDs:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: my-wazuh
spec:
  version: "4.14.0"
  managerRef:
    name: my-wazuh-manager
  indexerRef:
    name: my-wazuh-indexer
  dashboardRef:
    name: my-wazuh-dashboard
```

### WazuhManager, WazuhIndexer, WazuhDashboard (Separate CRDs)

For complex deployments, use individual component CRDs:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhManager
metadata:
  name: my-wazuh-manager
spec:
  version: "4.14.0"
  master:
    storageSize: "50Gi"
  workers:
    replicas: 2
    storageSize: "50Gi"
---
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhIndexer
metadata:
  name: my-wazuh-indexer
spec:
  version: "4.14.0"
  replicas: 3
  storageSize: "50Gi"
---
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhDashboard
metadata:
  name: my-wazuh-dashboard
spec:
  version: "4.14.0"
  replicas: 2
  indexerRef:
    name: my-wazuh-indexer
```

### WazuhRule

Manage Wazuh detection rules declaratively.

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhRule
metadata:
  name: ssh-brute-force
spec:
  clusterRef:
    name: my-wazuh
  group: ssh
  targetNodes: all
  priority: 100
  rules: |
    <group name="ssh,syslog,">
      <rule id="100001" level="10" frequency="5" timeframe="360">
        <if_matched_sid>5710</if_matched_sid>
        <description>SSH brute force detected</description>
      </rule>
    </group>
```

### WazuhDecoder

Manage Wazuh log decoders declaratively.

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhDecoder
metadata:
  name: nginx-logs
spec:
  clusterRef:
    name: my-wazuh
  decoderName: nginx
  targetNodes: all
  priority: 100
  decoders: |
    <decoder name="nginx-access">
      <program_name>^nginx</program_name>
      <type>nginx-access</type>
    </decoder>
```

### OpenSearch Security CRDs

Manage OpenSearch security resources declaratively:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchUser
metadata:
  name: wazuh-admin
spec:
  clusterRef:
    name: my-wazuh
  username: wazuh_admin
  passwordSecretRef:
    name: wazuh-admin-secret
    key: password
  backendRoles:
    - admin
---
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRole
metadata:
  name: wazuh-alerts-reader
spec:
  clusterRef:
    name: my-wazuh
  indexPermissions:
    - indexPatterns:
        - "wazuh-alerts-*"
      allowedActions:
        - read
        - search
```

## Documentation

### User Documentation (`docs/usage/`)

- **Getting Started**:
  - [Installation Guide](docs/usage/getting-started/installation.md) - How to install the operator
  - [Quick Start](docs/usage/getting-started/quick-start.md) - Deploy your first cluster
- **Feature Guides**:
  - [Credentials Management](docs/usage/features/credentials.md) - Auto-generated passwords, secrets
  - [TLS Configuration](docs/usage/features/tls.md) - Certificate management
  - [Monitoring](docs/usage/features/monitoring.md) - Prometheus integration
  - [Log Rotation](docs/usage/features/log-rotation.md) - Automated log cleanup
- **Examples**:
  - [Quick Start Examples](docs/usage/examples/quick-start/) - Minimal deployment
  - [Production Examples](docs/usage/examples/production/) - Production configuration
  - [OpenSearch CRDs](docs/usage/examples/opensearch-crds/) - Security and index management
- **Reference**:
  - [CRD Reference](docs/usage/CRD-REFERENCE.md) - Complete API documentation
- **Troubleshooting**:
  - [Common Issues](docs/usage/troubleshooting/common-issues.md) - Frequently encountered problems
  - [Debugging Guide](docs/usage/troubleshooting/debugging.md) - How to debug issues

### Developer Documentation (`docs/dev/`)

- **Architecture**:
  - [Operator Design](docs/dev/architecture/operator-design.md) - Overall architecture
  - [Reconciliation Flow](docs/dev/architecture/reconciliation-flow.md) - How reconciliation works
  - [Certificate Reconciliation](docs/dev/architecture/certificate-reconciliation.md) - TLS internals
- **Testing**:
  - [Testing Guide](docs/dev/testing/testing-guide.md) - How to run and write tests
  - [Certificate Renewal Scenarios](docs/dev/testing/certificate-renewal-scenarios.md) - Certificate tests
- **Contributing**:
  - [Contributing Guide](docs/dev/contributing/CONTRIBUTING.md) - How to contribute
  - [Code Style](docs/dev/contributing/code-style.md) - Coding conventions

## Configuration Examples

### TLS Configuration

TLS is enabled by default with auto-generated certificates:

```yaml
spec:
  tls:
    enabled: true
    certConfig:
      organization: "My Organization"
      validityDays: 365 # Certificate validity
      renewalThresholdDays: 30 # Renew 30 days before expiry
      caValidityDays: 730 # CA validity (2 years)
    hotReload:
      enabled: true # Reload certs without restart (Wazuh 4.9+)
```

### Ingress Configuration

```yaml
spec:
  dashboard:
    ingress:
      enabled: true
      ingressClassName: nginx
      hosts:
        - host: wazuh.example.com
          paths:
            - path: /
              pathType: Prefix
      tls:
        - secretName: wazuh-tls
          hosts:
            - wazuh.example.com
```

### High Availability Setup

```yaml
spec:
  manager:
    workers:
      replicas: 3
      podDisruptionBudget:
        enabled: true
        maxUnavailable: 1
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: wazuh-manager
              topologyKey: kubernetes.io/hostname

  indexer:
    replicas: 3
    podDisruptionBudget:
      enabled: true
      maxUnavailable: 1

  dashboard:
    replicas: 2
    podDisruptionBudget:
      enabled: true
      maxUnavailable: 1
```

### Monitoring with Prometheus

```yaml
spec:
  monitoring:
    enabled: true
    wazuhExporter:
      enabled: true
      image: "pytoshka/wazuh-prometheus-exporter:latest"
      port: 9090
    indexerExporter:
      enabled: true
    serviceMonitor:
      enabled: true
      labels:
        release: prometheus
      interval: 30s
```

### Log Rotation

```yaml
spec:
  manager:
    logRotation:
      enabled: true
      schedule: "0 0 * * 1" # Weekly on Monday
      retentionDays: 7 # Keep logs for 7 days
      maxFileSizeMB: 100 # Delete files > 100MB
      combinationMode: "or" # Delete if old OR large
```

## Operations

### Scaling

```bash
# Scale indexer nodes
kubectl patch wazuhcluster my-wazuh --type=merge \
  -p '{"spec":{"indexer":{"replicas":5}}}'

# Scale manager workers
kubectl patch wazuhcluster my-wazuh --type=merge \
  -p '{"spec":{"manager":{"workers":{"replicas":4}}}}'

# Scale dashboard
kubectl patch wazuhcluster my-wazuh --type=merge \
  -p '{"spec":{"dashboard":{"replicas":3}}}'
```

### Upgrading

```bash
# Upgrade to new version
kubectl patch wazuhcluster my-wazuh --type=merge \
  -p '{"spec":{"version":"4.13.0"}}'

# Monitor upgrade
kubectl get wazuhcluster my-wazuh -w
```

### Backup

```bash
# Backup cluster configuration
kubectl get wazuhcluster my-wazuh -o yaml > wazuh-backup.yaml

# Backup rules and decoders
kubectl get wazuhrules,wazuhdecoders -o yaml > wazuh-config-backup.yaml
```

## Development

### Prerequisites

- Go 1.25+
- Docker
- kubectl
- Access to a Kubernetes cluster

### Project Structure

```
wazuh-operator/
├── api/v1alpha1/           # CRD type definitions (flat structure per Kubebuilder)
├── internal/controller/    # Controller implementations
│   ├── wazuhcluster/       # WazuhCluster reconciler
│   ├── certificate/        # Certificate management
│   ├── opensearch/         # OpenSearch CRD controllers
│   ├── wazuh/              # Rule and Decoder controllers
│   └── shared/             # Shared utilities (metrics, status)
├── pkg/resources/          # Kubernetes resource builders
│   ├── indexer/            # Indexer resources
│   ├── manager/            # Manager resources
│   ├── dashboard/          # Dashboard resources
│   └── shared/             # Shared utilities (labels, common)
├── config/                 # Kubernetes manifests
│   ├── crd/                # Generated CRD manifests
│   ├── rbac/               # RBAC configuration
│   └── samples/            # Example resources
└── charts/                 # Helm charts
```

### Build

```bash
# Generate manifests and code
make manifests generate

# Build operator binary
make build

# Run tests
make test

# Build Docker image
make docker-build IMG=myregistry/wazuh-operator:dev
```

### Local Development

```bash
# Install CRDs
make install

# Run operator locally
make run

# In another terminal, create a test cluster
kubectl apply -f config/samples/wazuh_v1alpha1_wazuhcluster.yaml
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](docs\dev\contributing\CONTRIBUTING.md) for details.

## Comparison with Helm Chart

| Feature                    | Operator            | Helm Chart        |
| -------------------------- | ------------------- | ----------------- |
| Declarative Management     | ✅ Full             | ⚠️ Limited        |
| Dynamic Rule Management    | ✅ WazuhRule CRD    | ❌ ConfigMap only |
| Dynamic Decoder Management | ✅ WazuhDecoder CRD | ❌ ConfigMap only |
| Automatic Upgrades         | ✅ Yes              | ❌ Manual         |
| Self-Healing               | ✅ Yes              | ⚠️ Limited        |
| Status Reporting           | ✅ Rich Status      | ❌ No             |
| Configuration Validation   | ✅ Webhooks         | ❌ No             |
| Multi-Cluster Support      | ✅ Planned          | ❌ No             |

## Roadmap

- [x] Core operator functionality
- [x] WazuhCluster CRD
- [x] WazuhRule CRD
- [x] WazuhDecoder CRD
- [x] OpenSearch Security CRDs (User, Role, RoleMapping, Tenant, ActionGroup)
- [x] OpenSearch Index Management CRDs (IndexTemplate, ISMPolicy, ComponentTemplate, SnapshotPolicy)
- [x] TLS with auto-generated certificates and hot reload
- [x] Wazuh (master/worker) log rotation CronJob
- [x] Helm charts for operator and cluster
- [x] Prometheus monitoring integration
- [ ] Implementation of node type support (Cluster manager, Data, Ingest, etc)
- [ ] Drain strategy for scale up/down
- [ ] Scaling nodes disks - increase disk size.
- [ ] Ability to deploy multiple clusters
- [ ] More tests
- [ ] NetworkPolicies
- [ ] GatewayAPI support
- [ ] Validation webhooks
- [ ] Automatic backup/restore
- [ ] OLM/OperatorHub support

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- [GitHub Issues](https://github.com/MaximeWewer/wazuh-operator/issues)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Community Forum](https://groups.google.com/g/wazuh)

## Acknowledgments

- Built with [Kubebuilder](https://book.kubebuilder.io/)
- Inspired by [opensearch-k8s-operator](https://github.com/opensearch-project/opensearch-k8s-operator)
- Based on [Wazuh](https://wazuh.com/) security platform
