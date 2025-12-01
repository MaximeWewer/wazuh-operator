# Debugging Guide

This guide provides techniques for debugging Wazuh Operator issues.

## Gathering Information

### Cluster Status

```bash
# Get cluster status
kubectl get wazuhcluster -n wazuh -o yaml

# Check conditions
kubectl get wazuhcluster -n wazuh -o jsonpath='{.status.conditions}' | jq
```

### Pod Status

```bash
# List all pods with status
kubectl get pods -n wazuh -o wide

# Get pod details
kubectl describe pod -n wazuh <pod-name>

# Get all events
kubectl get events -n wazuh --sort-by='.lastTimestamp'
```

### Logs

```bash
# Operator logs
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager -f

# Indexer logs
kubectl logs -n wazuh wazuh-indexer-0 -f

# Manager logs
kubectl logs -n wazuh wazuh-manager-master-0 -f

# Dashboard logs
kubectl logs -n wazuh -l app.kubernetes.io/component=wazuh-dashboard -f

# Previous container logs (after crash)
kubectl logs -n wazuh <pod-name> --previous
```

## Debug Mode

### Enable Debug Logging

```bash
# Update operator with debug logging
helm upgrade wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-system \
  --set extraArgs[0]="--zap-log-level=debug"

# Or patch the deployment
kubectl patch deployment wazuh-operator-controller-manager -n wazuh-system \
  --type='json' -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--zap-log-level=debug"}]'
```

### View Debug Logs

```bash
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager -f | grep -E "(DEBUG|debug)"
```

## Component Debugging

### Indexer (OpenSearch)

```bash
# Get password
PASSWORD=$(kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d)

# Cluster health
kubectl exec -n wazuh wazuh-indexer-0 -- \
  curl -sk -u admin:$PASSWORD https://localhost:9200/_cluster/health?pretty

# Node stats
kubectl exec -n wazuh wazuh-indexer-0 -- \
  curl -sk -u admin:$PASSWORD https://localhost:9200/_nodes/stats?pretty

# Index list
kubectl exec -n wazuh wazuh-indexer-0 -- \
  curl -sk -u admin:$PASSWORD "https://localhost:9200/_cat/indices?v"

# Check security plugin
kubectl exec -n wazuh wazuh-indexer-0 -- \
  curl -sk -u admin:$PASSWORD https://localhost:9200/_plugins/_security/health
```

### Manager

```bash
# Cluster status
kubectl exec -n wazuh wazuh-manager-master-0 -- \
  /var/ossec/bin/cluster_control -l

# Agent list
kubectl exec -n wazuh wazuh-manager-master-0 -- \
  /var/ossec/bin/agent_control -l

# Check ossec.conf
kubectl exec -n wazuh wazuh-manager-master-0 -- \
  cat /var/ossec/etc/ossec.conf

# Check logs
kubectl exec -n wazuh wazuh-manager-master-0 -- \
  tail -100 /var/ossec/logs/ossec.log
```

### Dashboard

```bash
# Check configuration
kubectl exec -n wazuh -l app.kubernetes.io/component=wazuh-dashboard -- \
  cat /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml

# Check connectivity to indexer
kubectl exec -n wazuh -l app.kubernetes.io/component=wazuh-dashboard -- \
  curl -sk https://wazuh-indexer:9200
```

## Certificate Debugging

### Check Certificate Details

```bash
# Get certificate from secret
kubectl get secret -n wazuh wazuh-indexer-certs \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -text

# Check expiry
kubectl get secret -n wazuh wazuh-indexer-certs \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -dates

# Verify certificate chain
kubectl get secret -n wazuh wazuh-ca -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/ca.crt
kubectl get secret -n wazuh wazuh-indexer-certs -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/node.crt
openssl verify -CAfile /tmp/ca.crt /tmp/node.crt
```

### Certificate Hash Verification

```bash
# Check cert hash annotation on pods
kubectl get statefulset -n wazuh wazuh-indexer \
  -o jsonpath='{.spec.template.metadata.annotations}' | jq

# Compare with secret hash
kubectl get secret -n wazuh wazuh-indexer-certs \
  -o jsonpath='{.data}' | sha256sum
```

## Network Debugging

### Test Connectivity

```bash
# Create debug pod
kubectl run debug --rm -it --image=nicolaka/netshoot -n wazuh -- bash

# Inside the pod:
# Test DNS
nslookup wazuh-indexer.wazuh.svc.cluster.local

# Test TCP connectivity
nc -zv wazuh-indexer 9200
nc -zv wazuh-manager-master 1514

# Test HTTPS
curl -sk https://wazuh-indexer:9200
```

### Check Services

```bash
# List services
kubectl get svc -n wazuh

# Check endpoints
kubectl get endpoints -n wazuh

# Describe service
kubectl describe svc wazuh-indexer -n wazuh
```

## Resource Debugging

### Check Resource Usage

```bash
# Pod resources
kubectl top pods -n wazuh

# Node resources
kubectl top nodes

# Detailed resource requests/limits
kubectl get pods -n wazuh -o custom-columns=\
NAME:.metadata.name,\
CPU_REQ:.spec.containers[0].resources.requests.cpu,\
CPU_LIM:.spec.containers[0].resources.limits.cpu,\
MEM_REQ:.spec.containers[0].resources.requests.memory,\
MEM_LIM:.spec.containers[0].resources.limits.memory
```

### Check PVC Status

```bash
# List PVCs
kubectl get pvc -n wazuh

# Check PV binding
kubectl get pv

# Describe PVC
kubectl describe pvc -n wazuh wazuh-indexer-data-wazuh-indexer-0
```

## Common Debug Scenarios

### Scenario: Cluster Stuck in "Creating"

```bash
# 1. Check operator logs
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager | tail -50

# 2. Check which component is failing
kubectl get pods -n wazuh

# 3. Check failing pod events
kubectl describe pod -n wazuh <failing-pod>

# 4. Check failing pod logs
kubectl logs -n wazuh <failing-pod>
```

### Scenario: Reconciliation Errors

```bash
# 1. Enable debug logging
kubectl patch deployment wazuh-operator-controller-manager -n wazuh-system \
  --type='json' -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--zap-log-level=debug"}]'

# 2. Watch logs for errors
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager -f 2>&1 | grep -i error

# 3. Check cluster status conditions
kubectl get wazuhcluster -n wazuh -o yaml | grep -A 20 conditions:
```

### Scenario: Performance Issues

```bash
# 1. Check resource usage
kubectl top pods -n wazuh

# 2. Check indexer metrics
kubectl exec -n wazuh wazuh-indexer-0 -- \
  curl -sk -u admin:$PASSWORD https://localhost:9200/_nodes/stats/jvm?pretty

# 3. Check for GC issues
kubectl logs -n wazuh wazuh-indexer-0 | grep -i "gc"
```

## Diagnostic Script

Save and run this script for a complete diagnostic:

```bash
#!/bin/bash
echo "=== Wazuh Cluster Diagnostics ==="
echo ""
echo "=== Cluster Status ==="
kubectl get wazuhcluster -n wazuh
echo ""
echo "=== Pods ==="
kubectl get pods -n wazuh -o wide
echo ""
echo "=== Services ==="
kubectl get svc -n wazuh
echo ""
echo "=== PVCs ==="
kubectl get pvc -n wazuh
echo ""
echo "=== Recent Events ==="
kubectl get events -n wazuh --sort-by='.lastTimestamp' | tail -20
echo ""
echo "=== Operator Logs (last 20 lines) ==="
kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager --tail=20
```
