# Prerequisites for Quick Start

Before deploying a Wazuh cluster, ensure your environment meets these requirements:

## Kubernetes Cluster

- [ ] Kubernetes version 1.25 or higher
- [ ] `kubectl` configured and connected to your cluster
- [ ] Cluster has at least 4GB RAM available
- [ ] Storage provisioner for PersistentVolumeClaims (e.g., default StorageClass)

## Wazuh Operator

- [ ] CRDs installed: `kubectl get crd wazuhclusters.resources.wazuh.com`
- [ ] Operator running: `kubectl get pods -n wazuh-operator`

### Install the Operator

If not already installed:

```bash
# Install CRDs
kubectl apply -f https://raw.githubusercontent.com/MaximeWewer/wazuh-operator/main/config/crd/bases/

# Install operator via Helm
helm template wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-operator | kubectl apply -f -
```

## Verify Prerequisites

```bash
# Check Kubernetes version
kubectl version --short

# Check available storage
kubectl get sc

# Check operator status
kubectl get pods -n wazuh-operator
kubectl logs -f deploy/wazuh-operator-controller-manager -n wazuh-operator
```

## Next Steps

Once prerequisites are met, proceed to [01-minimal-cluster.yaml](./01-minimal-cluster.yaml).
