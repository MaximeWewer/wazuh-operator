# Installation Guide

This guide covers how to install the Wazuh Operator in your Kubernetes cluster.

## Prerequisites

See [Prerequisites and Requirements](../../requirements.md) for detailed requirements.

**Quick check:**

```bash
kubectl version --client  # 1.25+
helm version              # 3.0+
kubectl get storageclass  # StorageClass available
```

## Installation Methods

### Method 1: Helm (Recommended)

#### Install the Operator

```bash
# Add the Helm repository (if published)
# helm repo add wazuh https://charts.wazuh.com
# helm repo update

# Or install from local charts
helm install wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-system \
  --create-namespace
```

#### Verify Installation

```bash
# Check operator pod
kubectl get pods -n wazuh-system

# Expected output:
# NAME                                              READY   STATUS    RESTARTS   AGE
# wazuh-operator-controller-manager-xxxxx-xxxxx     1/1     Running   0          1m
```

#### Configuration Options

```bash
# Install with custom values
helm install wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-system \
  --create-namespace \
  --set operator.resources.limits.memory=1Gi \
  --set operator.image.tag=v1.0.0
```

Key values:

- `operator.image.repository`: Operator image
- `operator.image.tag`: Image tag
- `operator.resources`: Resource limits/requests
- `crds.install`: Install CRDs (default: true)
- `operator.clusterDomain`: Kubernetes DNS domain (default: `cluster.local`)

#### Custom Cluster Domain

If your Kubernetes cluster uses a custom DNS domain (e.g., custom CoreDNS configuration), configure the operator accordingly:

```bash
helm install wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-system \
  --create-namespace \
  --set operator.clusterDomain=svc.company.internal
```

This setting affects all generated TLS certificates and service discovery. Common custom domains include:

- `svc.company.local` - Corporate environments
- `k8s.prod.example.com` - Multi-cluster setups
- Custom domains mandated by security policies

### Method 2: kubectl

#### Install CRDs

```bash
kubectl apply -f config/crd/bases/
```

#### Install RBAC

```bash
kubectl apply -f config/rbac/
```

#### Deploy Operator

```bash
kubectl apply -f config/manager/manager.yaml
```

### Method 3: From Source

```bash
# Clone repository
git clone https://github.com/MaximeWewer/wazuh-operator.git
cd wazuh-operator

# Build and deploy
make docker-build IMG=wazuh-operator:dev
make deploy IMG=wazuh-operator:dev
```

## Post-Installation

### Verify CRDs

```bash
kubectl get crds | grep wazuh

# Expected:
# wazuhclusters.resources.wazuh.com
# wazuhrules.resources.wazuh.com
# wazuhdecoders.resources.wazuh.com
# opensearchusers.resources.wazuh.com
# ... (17 CRDs total)
```

### Check Operator Logs

```bash
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager -f
```

### Deploy a Test Cluster

```bash
# Using Helm
helm install wazuh-cluster ./charts/wazuh-cluster \
  --namespace wazuh \
  --create-namespace

# Or using kubectl
kubectl create namespace wazuh
kubectl apply -f config/samples/wazuh_v1_wazuhcluster_minimal.yaml
```

## Upgrading

### Helm Upgrade

```bash
helm upgrade wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-system \
  --set operator.image.tag=v1.1.0
```

### CRD Upgrade

CRDs are upgraded automatically with Helm. For manual upgrades:

```bash
kubectl apply -f config/crd/bases/
```

## Uninstalling

### Uninstall Operator

```bash
# Helm
helm uninstall wazuh-operator -n wazuh-system

# kubectl
kubectl delete -f config/manager/manager.yaml
kubectl delete -f config/rbac/
```

### Uninstall CRDs (Caution!)

**Warning**: This will delete all WazuhCluster resources!

```bash
kubectl delete -f config/crd/bases/
```

## Troubleshooting

### Operator Not Starting

```bash
# Check events
kubectl describe pod -n wazuh-system -l app.kubernetes.io/name=wazuh-operator

# Check logs
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager
```

### CRDs Not Found

```bash
# Verify CRDs are installed
kubectl get crds | grep wazuh

# Reinstall if needed
kubectl apply -f config/crd/bases/
```

### Permission Errors

Ensure RBAC resources are installed:

```bash
kubectl get clusterrole | grep wazuh
kubectl get clusterrolebinding | grep wazuh
```

## Next Steps

- [Quick Start](quick-start.md) - Deploy your first cluster
- [CRD Reference](../CRD-REFERENCE.md) - API documentation
- [Examples](../examples/) - Sample configurations
