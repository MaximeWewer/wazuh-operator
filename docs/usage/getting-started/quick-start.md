# Quick Start Guide

Deploy a Wazuh cluster in minutes.

## Prerequisites

- Wazuh Operator installed ([Installation Guide](installation.md))
- kubectl access to your cluster
- At least 8GB RAM available in your cluster

## Step 1: Create a Namespace

```bash
kubectl create namespace wazuh
```

## Step 2: Deploy a Minimal Cluster

### Option A: Using Helm

```bash
helm install wazuh-cluster ./charts/wazuh-cluster \
  --namespace wazuh \
  --set sizing.profile=S  # Small profile for testing
```

### Option B: Using kubectl

Create a file `wazuh-cluster.yaml`:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh
  namespace: wazuh
spec:
  version: "4.9.0"

  manager:
    master:
      storageSize: "10Gi"
      resources:
        requests:
          cpu: "500m"
          memory: "1Gi"
        limits:
          cpu: "1"
          memory: "2Gi"
    workers:
      replicas: 0 # No workers for minimal cluster

  indexer:
    replicas: 1
    storageSize: "10Gi"
    javaOpts: "-Xms512m -Xmx512m"
    resources:
      requests:
        cpu: "500m"
        memory: "1Gi"
      limits:
        cpu: "1"
        memory: "2Gi"

  dashboard:
    replicas: 1
    resources:
      requests:
        cpu: "250m"
        memory: "512Mi"
      limits:
        cpu: "500m"
        memory: "1Gi"
```

Apply it:

```bash
kubectl apply -f wazuh-cluster.yaml
```

## Step 3: Monitor Deployment

```bash
# Watch cluster status
kubectl get wazuhcluster -n wazuh -w

# Watch pods
kubectl get pods -n wazuh -w
```

Expected output after ~2-5 minutes:

```
NAME    VERSION   PHASE     MANAGER   INDEXER   DASHBOARD   AGE
wazuh   4.9.0     Running   Running   Running   Running     5m
```

## Step 4: Access the Dashboard

### Get Admin Password

The operator automatically generates secure random passwords for all components. To retrieve the OpenSearch admin password:

```bash
# Get admin password (auto-generated 24-character random password)
kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d && echo
```

> **Note:** Passwords are cryptographically generated for each deployment. There are no default passwords like "admin" or "wazuh".

### Port Forward

```bash
kubectl port-forward -n wazuh svc/wazuh-dashboard 5601:5601
```

### Open Browser

Navigate to: https://localhost:5601

Login with:

- Username: `admin`
- Password: (from step above)

For more credential management options, see the [Credentials Management Guide](../features/credentials.md).

## Step 5: Verify Components

### Check Indexer Health

```bash
# Get password
PASSWORD=$(kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d)

# Check cluster health
kubectl exec -n wazuh wazuh-indexer-0 -- \
  curl -sk -u admin:$PASSWORD https://localhost:9200/_cluster/health?pretty
```

### Check Manager Status

```bash
kubectl exec -n wazuh wazuh-manager-master-0 -- \
  /var/ossec/bin/cluster_control -l
```

## Common Operations

### Scale Workers

```bash
kubectl patch wazuhcluster wazuh -n wazuh --type=merge \
  -p '{"spec":{"manager":{"workers":{"replicas":2}}}}'
```

### View Logs

```bash
# Manager logs
kubectl logs -n wazuh wazuh-manager-master-0

# Indexer logs
kubectl logs -n wazuh wazuh-indexer-0

# Operator logs
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager
```

### Delete Cluster

```bash
kubectl delete wazuhcluster wazuh -n wazuh
```

## Next Steps

- [Production Deployment](../examples/production/README.md) - Production configuration
- [TLS Configuration](../features/tls.md) - Certificate management
- [Monitoring](../features/monitoring.md) - Prometheus integration
- [CRD Reference](../CRD-REFERENCE.md) - Full API documentation

## Troubleshooting

### Pods Stuck in Pending

Check if there are enough resources:

```bash
kubectl describe pod -n wazuh <pod-name>
```

### Indexer Not Starting

Check if PVC is bound:

```bash
kubectl get pvc -n wazuh
```

### Dashboard Can't Connect

Verify indexer is healthy:

```bash
kubectl get pods -n wazuh -l app.kubernetes.io/component=wazuh-indexer
```
