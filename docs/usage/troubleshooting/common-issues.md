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
apiVersion: resources.wazuh.com/v1alpha1
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
