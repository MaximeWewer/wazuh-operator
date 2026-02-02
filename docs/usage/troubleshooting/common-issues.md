# Common Issues and Solutions

This guide covers frequently encountered issues and their solutions.

## Cluster Deployment Issues

### Pods Stuck in Pending

**Symptoms**: Pods stay in `Pending` state.

**Causes**:

1. Insufficient cluster resources
2. No PersistentVolume available
3. Node selector doesn't match any nodes

**Solutions**:

```bash
# Check pod events
kubectl describe pod -n wazuh <pod-name>

# Check resource availability
kubectl describe nodes | grep -A 5 "Allocated resources"

# Check PVC status
kubectl get pvc -n wazuh
```

### Indexer CrashLoopBackOff

**Symptoms**: Indexer pods restart repeatedly.

**Causes**:

1. Insufficient memory for JVM
2. Permission issues on data directory
3. Certificate problems

**Solutions**:

```bash
# Check logs
kubectl logs -n wazuh wazuh-indexer-0

# Verify JVM settings match container memory
# javaOpts should be ~50% of memory limit
spec:
  indexer:
    javaOpts: "-Xms1g -Xmx1g"  # For 2Gi memory limit
    resources:
      limits:
        memory: "2Gi"
```

### Dashboard Can't Connect to Indexer

**Symptoms**: Dashboard shows "Wazuh API is not reachable" error.

**Causes**:

1. Indexer not ready
2. Certificate mismatch
3. Credentials incorrect

**Solutions**:

```bash
# Verify indexer is running
kubectl get pods -n wazuh -l app.kubernetes.io/component=wazuh-indexer

# Check indexer health
kubectl exec -n wazuh wazuh-indexer-0 -- \
  curl -sk https://localhost:9200/_cluster/health

# Check dashboard logs
kubectl logs -n wazuh -l app.kubernetes.io/component=wazuh-dashboard
```

## Certificate Issues

### Certificate Expired

**Symptoms**: Connection refused or SSL errors.

**Solutions**:

```bash
# Check certificate expiry
kubectl get secret -n wazuh wazuh-indexer-certs \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -dates

# Force certificate renewal by deleting secret
kubectl delete secret -n wazuh wazuh-indexer-certs

# Operator will regenerate certificates
```

### Certificate Verification Failed

**Symptoms**: `x509: certificate signed by unknown authority`

**Solutions**:

```bash
# Verify CA is consistent across components
kubectl get secret -n wazuh wazuh-ca -o yaml

# Restart affected pods to pick up new certs
kubectl rollout restart statefulset/wazuh-indexer -n wazuh
```

### Certificate Domain Mismatch

**Symptoms**: TLS handshake errors like:

- `x509: certificate is valid for *.svc.cluster.local, not *.svc.custom.domain`
- Components cannot communicate after changing cluster DNS domain
- Dashboard shows connection errors to indexer or manager

**Causes**:

1. Kubernetes cluster uses a custom DNS domain (not `cluster.local`)
2. Operator was deployed without matching `operator.clusterDomain` setting
3. Domain configuration changed after initial deployment

**Solutions**:

```bash
# 1. Check your cluster's DNS domain
kubectl get cm coredns -n kube-system -o yaml | grep -A5 "kubernetes"

# 2. Verify operator configuration
kubectl get deploy -n wazuh-system wazuh-operator-controller-manager -o yaml | grep KUBERNETES_CLUSTER_DOMAIN

# 3. If mismatch, upgrade operator with correct domain
helm upgrade wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-system \
  --set operator.clusterDomain=your.custom.domain

# 4. Force certificate regeneration
kubectl delete secret -n wazuh -l app.kubernetes.io/component=certificates

# 5. Operator will automatically regenerate certificates with correct SANs
```

**Verification**:

```bash
# Check certificate SANs match the configured domain
kubectl get secret wazuh-indexer-certs -n wazuh -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -text -noout | grep DNS
```

## Storage Issues

### PVC Not Bound

**Symptoms**: PVC stays in `Pending` state.

**Causes**:

1. No StorageClass available
2. No matching PV
3. StorageClass doesn't support dynamic provisioning

**Solutions**:

```bash
# Check StorageClasses
kubectl get storageclass

# Specify StorageClass in cluster spec
spec:
  storageClassName: "standard"  # or your storage class
```

### Disk Full

**Symptoms**: Indexer stops accepting data, errors in logs.

**Solutions**:

1. Enable log rotation:

```yaml
spec:
  manager:
    logRotation:
      enabled: true
      retentionDays: 7
```

2. Increase storage:

```bash
# If StorageClass supports expansion
kubectl patch pvc wazuh-indexer-data-wazuh-indexer-0 -n wazuh \
  -p '{"spec":{"resources":{"requests":{"storage":"100Gi"}}}}'
```

## Performance Issues

### High Memory Usage

**Solutions**:

1. Adjust JVM heap:

```yaml
spec:
  indexer:
    javaOpts: "-Xms2g -Xmx2g" # Reduce if needed
```

2. Enable ISM policy for index cleanup:

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchISMPolicy
metadata:
  name: cleanup-policy
spec:
  defaultState: hot
  states:
    - name: hot
      transitions:
        - stateName: delete
          conditions:
            minIndexAge: 30d
    - name: delete
      actions:
        - config:
            delete: {}
```

### Slow Queries

**Solutions**:

1. Check index size:

```bash
kubectl exec -n wazuh wazuh-indexer-0 -- \
  curl -sk -u admin:$PASSWORD \
  "https://localhost:9200/_cat/indices?v&s=store.size:desc"
```

2. Add more indexer replicas:

```yaml
spec:
  indexer:
    replicas: 3
```

## Operator Issues

### Operator Not Reconciling

**Symptoms**: Changes to WazuhCluster not applied.

**Solutions**:

```bash
# Check operator logs
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager

# Restart operator
kubectl rollout restart deployment/wazuh-operator-controller-manager -n wazuh-system
```

### "object has been modified" Errors

**Symptoms**: Reconciliation errors in operator logs.

**Cause**: Concurrent modifications to the same resource.

**Solution**: This is usually transient. The operator will retry automatically.

## Networking Issues

### Services Not Accessible

**Solutions**:

```bash
# Verify services exist
kubectl get svc -n wazuh

# Check endpoints
kubectl get endpoints -n wazuh

# Test internal connectivity
kubectl run test --rm -it --image=busybox -- \
  wget -qO- http://wazuh-dashboard.wazuh:5601
```

### Agents Can't Connect

**Solutions**:

1. Expose manager service:

```yaml
spec:
  manager:
    master:
      service:
        type: LoadBalancer # or NodePort
```

2. Check firewall rules for ports 1514, 1515

## Credential Issues

### Password Not Working

```bash
# Verify secret exists and get password
kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d && echo
```

### Secret Not Being Created

```bash
# Check operator logs
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager

# Check WazuhCluster status
kubectl describe wazuhcluster wazuh -n wazuh
```

### Dashboard Can't Connect to API

```bash
# Verify API credentials
kubectl get secret -n wazuh wazuh-api-credentials \
  -o jsonpath='{.data.password}' | base64 -d
```

## Monitoring Issues

### Exporter Not Starting

```bash
# Check exporter logs
kubectl logs -n wazuh <manager-pod> -c wazuh-exporter
```

### ServiceMonitor Not Discovered

```bash
# Verify labels match Prometheus selector
kubectl get prometheus -o yaml | grep serviceMonitorSelector

# Check ServiceMonitor exists
kubectl get servicemonitor -n wazuh
```

## OpenTelemetry Issues

### Traces Not Appearing

```bash
# Check endpoint connectivity
kubectl exec -it deploy/wazuh-operator-controller-manager -n wazuh-system -- \
  nc -zv jaeger-collector.observability 4317

# Check operator logs
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager | grep -i otel

# Verify environment variables
kubectl get deploy wazuh-operator-controller-manager -n wazuh-system -o yaml | grep -A5 OTEL
```

## Getting Help

If these solutions don't help:

1. Check operator logs for detailed errors
2. Review [Debugging Guide](debugging.md)
3. Search existing [GitHub Issues](https://github.com/MaximeWewer/wazuh-operator/issues)
4. Open a new issue with:
   - Operator version
   - Kubernetes version
   - WazuhCluster spec
   - Relevant logs
