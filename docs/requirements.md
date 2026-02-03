# Prerequisites and Requirements

This document is the single source of truth for all prerequisites and requirements needed to run the Wazuh Operator.

## Kubernetes Cluster Requirements

| Requirement            | Minimum                 | Recommended                   |
| ---------------------- | ----------------------- | ----------------------------- |
| **Kubernetes Version** | 1.25+                   | 1.28+                         |
| **RAM**                | 8GB                     | 16GB+                         |
| **Storage**            | Dynamic PV provisioning | SSD-backed StorageClass       |
| **Network**            | ClusterIP support       | Ingress controller (optional) |

## Required Tools

### For Users (Deployment)

| Tool                                               | Minimum Version | Purpose         |
| -------------------------------------------------- | --------------- | --------------- |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | 1.25+           | Kubernetes CLI  |
| [Helm](https://helm.sh/docs/intro/install/)        | 3.0+            | Package manager |

### For Developers (Contributing)

| Tool                                                 | Minimum Version | Purpose                  |
| ---------------------------------------------------- | --------------- | ------------------------ |
| [Go](https://go.dev/dl/)                             | 1.25+           | Build operator           |
| [Docker](https://docs.docker.com/get-docker/)        | 20.10+          | Container builds         |
| [Make](https://www.gnu.org/software/make/)           | 3.81+           | Build automation         |
| [Minikube](https://minikube.sigs.k8s.io/docs/start/) | 1.30+           | Local testing (optional) |

## Quick Verification

```bash
# Check Kubernetes
kubectl version --client

# Check Helm
helm version

# For developers
go version
docker --version
make --version
```

## Cluster Requirements

### Storage

The operator requires a StorageClass that supports dynamic provisioning:

```bash
# Check available StorageClasses
kubectl get storageclass

# Verify default StorageClass exists
kubectl get storageclass -o name | grep -q default && echo "Default StorageClass found"
```

### RBAC

The operator requires cluster-admin privileges to install CRDs. Ensure your user has sufficient permissions:

```bash
kubectl auth can-i create customresourcedefinitions --all-namespaces
```

### Resource Quotas

If your cluster has resource quotas, ensure sufficient resources are available:

| Profile         | CPU Requests | Memory Requests | Storage |
| --------------- | ------------ | --------------- | ------- |
| XS (testing)    | ~1.5 cores   | ~3Gi            | ~15Gi   |
| S (development) | ~3.5 cores   | ~7Gi            | ~40Gi   |
| M (staging)     | ~10 cores    | ~19Gi           | ~210Gi  |
| L (production)  | ~22 cores    | ~44Gi           | ~500Gi  |
| XL (enterprise) | ~70 cores    | ~140Gi          | ~1.7Ti  |

See [Sizing Guide](usage/features/sizing.md) for detailed resource planning.

## Optional Components

### Prometheus Operator

Required for ServiceMonitor/PodMonitor support:

```bash
# Check if Prometheus Operator is installed
kubectl get crd servicemonitors.monitoring.coreos.com
```

### Cert-Manager

Required for cert-manager TLS integration:

```bash
# Check if cert-manager is installed
kubectl get crd certificates.cert-manager.io
```

## Next Steps

- [Installation Guide](usage/getting-started/installation.md) - Install the operator
- [Quick Start](usage/getting-started/quick-start.md) - Deploy your first cluster
