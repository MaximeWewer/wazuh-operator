# Verify Deployment

After applying the minimal cluster manifest, use these steps to verify the deployment.

## Check Cluster Status

```bash
# Watch the WazuhCluster status
kubectl get wazuhcluster -n wazuh -w

# Expected output after a few minutes:
# NAME              VERSION   PHASE     MANAGER   INDEXER   DASHBOARD   AGE
# wazuh-quickstart  4.9.0     Running   Ready     Ready     Ready       5m
```

## Check Pods

```bash
# List all pods
kubectl get pods -n wazuh

# Expected pods:
# - wazuh-quickstart-manager-master-0    (1/1 Running)
# - wazuh-quickstart-indexer-0           (1/1 Running)
# - wazuh-quickstart-dashboard-xxx       (1/1 Running)
```

## Check Services

```bash
kubectl get svc -n wazuh

# Services created:
# - wazuh-quickstart-manager          (ClusterIP) - Wazuh API
# - wazuh-quickstart-indexer          (ClusterIP) - OpenSearch
# - wazuh-quickstart-dashboard        (NodePort)  - Web UI
```

## Access the Dashboard

### Option 1: Port Forward (Recommended)

```bash
kubectl port-forward svc/wazuh-quickstart-dashboard 5601:5601 -n wazuh
```

Then open: https://localhost:5601

### Option 2: NodePort (minikube)

```bash
minikube service wazuh-quickstart-dashboard -n wazuh
```

## Get Credentials

```bash
# Get the admin password
kubectl get secret wazuh-quickstart-indexer-credentials -n wazuh \
  -o jsonpath='{.data.admin-password}' | base64 -d && echo

# Default username: admin
```

## Troubleshooting

### Pods not starting

```bash
# Check pod events
kubectl describe pod <pod-name> -n wazuh

# Check operator logs
kubectl logs -f deploy/wazuh-operator-controller-manager -n wazuh-operator-system
```

### Dashboard not accessible

```bash
# Check dashboard logs
kubectl logs -l app.kubernetes.io/component=wazuh-dashboard -n wazuh
```

## Cleanup

```bash
# Delete the cluster
kubectl delete wazuhcluster wazuh-quickstart -n wazuh

# Delete PVCs (data will be lost)
kubectl delete pvc --all -n wazuh

# Delete namespace
kubectl delete namespace wazuh
```
