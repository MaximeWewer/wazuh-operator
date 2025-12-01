# Certificate Renewal Test Scenarios

This document describes test scenarios for validating certificate renewal functionality.

## Prerequisites

- Minikube or similar Kubernetes cluster
- Operator built and loaded: `make docker-build IMG=wazuh-operator:dev && minikube image load wazuh-operator:dev`
- Test mode enabled via `--cert-test-mode` flag

## Test Configuration

### Operator Deployment (Test Mode)

```bash
# Deploy operator with test mode enabled
helm upgrade --install wazuh-operator charts/wazuh-operator \
  --namespace wazuh-operator-system \
  --create-namespace \
  -f charts/wazuh-operator/examples/values-cert-test.yaml
```

### Test Cluster Deployment

```bash
# Deploy minimal test cluster
helm upgrade --install wazuh-test charts/wazuh-cluster \
  --namespace wazuh-test \
  --create-namespace \
  -f charts/wazuh-cluster/examples/values-cert-test.yaml
```

## Test Mode Timing

| Parameter          | Value      | Description                            |
| ------------------ | ---------- | -------------------------------------- |
| CA Validity        | 10 minutes | CA certificate lifetime                |
| Node Cert Validity | 5 minutes  | Node certificate lifetime              |
| Renewal Threshold  | 2 minutes  | Renew when this much time remains      |
| Expected Renewal   | ~3 minutes | Certificate renewed at 3 min remaining |

## Scenario 1: Initial Certificate Creation

**Objective**: Verify all certificates are created on cluster creation.

**Steps**:

1. Deploy a new WazuhCluster
2. Wait for cluster to be ready (60-90 seconds)
3. Check certificate secrets exist

**Verification**:

```bash
# List all certificate secrets
kubectl get secrets -n wazuh-test | grep -E "(cert|ca)"

# Expected secrets:
# - wazuh-test-ca
# - wazuh-test-indexer-certs
# - wazuh-test-manager-master-certs
# - wazuh-test-manager-worker-certs
# - wazuh-test-dashboard-certs
# - wazuh-test-filebeat-certs
# - wazuh-test-admin-certs
```

**Expected Result**: All 7 certificate secrets created with valid certificates.

## Scenario 2: Node Certificate Renewal

**Objective**: Verify node certificates renew before expiry.

**Steps**:

1. Deploy cluster and wait for ready
2. Note initial certificate expiry times
3. Wait 3 minutes (until renewal threshold)
4. Verify certificates are renewed

**Verification**:

```bash
# Check certificate expiry (run immediately after creation)
kubectl get secret -n wazuh-test wazuh-test-indexer-certs \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -dates

# Wait 3 minutes, then check again
# Expiry should be ~5 minutes from NOW (not from original creation)
```

**Expected Result**: Certificate `notAfter` date updates to ~5 minutes from current time.

## Scenario 3: CA Certificate Renewal

**Objective**: Verify CA renews and all node certs are re-signed.

**Steps**:

1. Deploy cluster and wait for ready
2. Wait 8 minutes (until CA renewal threshold at 2 min remaining)
3. Verify CA is renewed
4. Verify all node certificates are re-signed with new CA

**Verification**:

```bash
# Check CA expiry
kubectl get secret -n wazuh-test wazuh-test-ca \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -dates

# Verify node cert is signed by current CA
CA_CERT=$(kubectl get secret -n wazuh-test wazuh-test-ca \
  -o jsonpath='{.data.tls\.crt}' | base64 -d)
NODE_CERT=$(kubectl get secret -n wazuh-test wazuh-test-indexer-certs \
  -o jsonpath='{.data.tls\.crt}' | base64 -d)

echo "$CA_CERT" > /tmp/ca.crt
echo "$NODE_CERT" > /tmp/node.crt
openssl verify -CAfile /tmp/ca.crt /tmp/node.crt
```

**Expected Result**: CA renews and all node certs verify against new CA.

## Scenario 4: Pod Rollout on Certificate Renewal

**Objective**: Verify pods restart when certificates are renewed.

**Steps**:

1. Deploy cluster and wait for ready
2. Note pod creation timestamps
3. Wait for certificate renewal (3 minutes)
4. Verify pods have been restarted

**Verification**:

```bash
# Check pod ages before and after
kubectl get pods -n wazuh-test -o wide

# Check cert-hash annotation on statefulset
kubectl get statefulset -n wazuh-test wazuh-test-indexer \
  -o jsonpath='{.spec.template.metadata.annotations}'
```

**Expected Result**: Pods are restarted with updated certificate hash annotation.

## Scenario 5: Concurrent Certificate Renewal (Current Issue)

**Objective**: Identify blocking behavior during rollouts.

**Steps**:

1. Deploy cluster with multiple replicas
2. Enable debug logging
3. Watch operator logs during certificate renewal
4. Identify blocking wait patterns

**Verification**:

```bash
# Watch operator logs
kubectl logs -n wazuh-operator-system \
  deploy/wazuh-operator-controller-manager -f | \
  grep -E "(Waiting for|StatefulSet|certificate|renewal)"

# Look for patterns like:
# "Waiting for Master StatefulSet to be ready"
# followed by long gaps before:
# "Waiting for Worker StatefulSet to be ready"
```

**Expected Result (Current Behavior)**: Sequential blocking waits observed.

**Expected Result (After Fix)**: All components update in parallel.

## Scenario 6: Optimistic Locking Errors

**Objective**: Reproduce and verify handling of concurrent update errors.

**Steps**:

1. Deploy cluster
2. Trigger rapid reconciliation (multiple secret updates)
3. Watch for "object has been modified" errors in logs

**Verification**:

```bash
# Watch for conflict errors
kubectl logs -n wazuh-operator-system \
  deploy/wazuh-operator-controller-manager | \
  grep -i "modified"
```

**Expected Result (Current)**: Errors cause reconciliation failures.

**Expected Result (After Fix)**: Automatic retry succeeds.

## Scenario 7: Certificate Expiry Under Load

**Objective**: Verify certificates don't expire during slow rollouts.

**Steps**:

1. Deploy cluster with 3 indexer replicas
2. Add resource constraints to slow down pod startup
3. Watch for certificate expiry during rollout

**Configuration**:

```yaml
# values-slow-rollout.yaml
cluster:
  spec:
    indexer:
      replicas: 3
      resources:
        requests:
          cpu: 2000m # Request more than available
        limits:
          cpu: 2000m
```

**Verification**:

```bash
# Watch for certificate expiry errors
kubectl logs -n wazuh-test wazuh-test-indexer-0 | grep -i "expired"
```

**Expected Result (Current)**: Certificates may expire during long rollouts.

**Expected Result (After Fix)**: Certificates renewed before expiry regardless of rollout duration.

## Scenario 8: Recovery After Failure

**Objective**: Verify cluster recovers from certificate-related failures.

**Steps**:

1. Deploy cluster
2. Delete certificate secrets
3. Wait for operator to recreate them
4. Verify cluster becomes healthy

**Verification**:

```bash
# Delete a certificate secret
kubectl delete secret -n wazuh-test wazuh-test-indexer-certs

# Watch for recreation
kubectl get secrets -n wazuh-test -w

# Check cluster status
kubectl get wazuhcluster -n wazuh-test wazuh-test
```

**Expected Result**: Secrets recreated, pods restarted, cluster healthy.

## Monitoring Commands

### Watch Certificate Status

```bash
# Watch all certificate expiry times
watch -n 5 '
echo "=== Certificate Expiry Times ==="
for secret in ca indexer-certs manager-master-certs manager-worker-certs dashboard-certs; do
  echo -n "$secret: "
  kubectl get secret -n wazuh-test wazuh-test-$secret \
    -o jsonpath="{.data.tls\.crt}" 2>/dev/null | base64 -d | \
    openssl x509 -noout -enddate 2>/dev/null || echo "N/A"
done
echo ""
echo "Current time: $(date -u)"
'
```

### Watch Pod Rollouts

```bash
kubectl get pods -n wazuh-test -w
```

### Watch Operator Logs

```bash
kubectl logs -n wazuh-operator-system \
  deploy/wazuh-operator-controller-manager -f --tail=100
```

## Success Criteria

| Scenario           | Current Status | Target Status |
| ------------------ | -------------- | ------------- |
| Initial Creation   | PASS           | PASS          |
| Node Cert Renewal  | PARTIAL        | PASS          |
| CA Cert Renewal    | PARTIAL        | PASS          |
| Pod Rollout        | PARTIAL        | PASS          |
| Concurrent Renewal | FAIL           | PASS          |
| Optimistic Locking | FAIL           | PASS          |
| Expiry Under Load  | FAIL           | PASS          |
| Recovery           | PASS           | PASS          |

## Troubleshooting

### Certificate Shows Expired

```bash
# Check if secret was updated
kubectl get secret -n wazuh-test wazuh-test-indexer-certs \
  -o jsonpath='{.metadata.resourceVersion}'

# Check operator logs for renewal attempts
kubectl logs -n wazuh-operator-system \
  deploy/wazuh-operator-controller-manager | \
  grep -E "(renewal|renew|expired)"
```

### Pods Not Rolling Out

```bash
# Check cert-hash annotation
kubectl get statefulset -n wazuh-test wazuh-test-indexer \
  -o yaml | grep cert-hash

# Check if statefulset spec was updated
kubectl rollout status statefulset/wazuh-test-indexer -n wazuh-test
```

### Operator Stuck

```bash
# Check if reconciliation is blocked
kubectl logs -n wazuh-operator-system \
  deploy/wazuh-operator-controller-manager | \
  tail -50 | grep -E "(Waiting|blocked|timeout)"

# Check operator health
kubectl get pods -n wazuh-operator-system
```
