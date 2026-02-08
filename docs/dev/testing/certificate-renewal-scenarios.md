# Certificate Renewal Test Scenarios

This document describes test scenarios for validating certificate renewal functionality.

## Prerequisites

- Minikube or similar Kubernetes cluster
- Operator built and loaded: `make docker-build IMG=wazuh-operator:dev && minikube image load wazuh-operator:dev`

## Test Configuration

### Short-Lived Certificates for Testing

To test certificate renewal quickly, configure short validity periods via the WazuhCluster CRD:

```yaml
spec:
  tls:
    enabled: true
    certConfig:
      caValidity: "24h"        # 1 day CA validity
      validity: "1h"           # 1 hour node cert validity
      renewalThreshold: "30m"  # Renew 30 minutes before expiry
      caRenewalThreshold: "6h" # Renew CA 6 hours before expiry
```

Duration format supports: `d` (days), `h` (hours), `m` (minutes). For example:

- `365d` - 1 year
- `24h` - 1 day
- `30m` - 30 minutes (useful for quick tests)

For even shorter testing periods, you can use a minimal cluster with the operator's default configuration and simply wait for the renewal threshold to be reached.

### Operator Deployment

```bash
# Deploy operator
helm upgrade --install wazuh-operator charts/wazuh-operator \
  --namespace wazuh-operator-system \
  --create-namespace
```

### Test Cluster Deployment

```bash
# Deploy minimal test cluster
helm upgrade --install wazuh-test charts/wazuh-cluster \
  --namespace wazuh-system \
  -f charts/wazuh-cluster/examples/values-minimal.yaml
```

## Certificate Timing (Default Production Settings)

| Parameter          | Default Value | Description                            |
| ------------------ | ------------- | -------------------------------------- |
| CA Validity        | 3650 days     | CA certificate lifetime (10 years)     |
| Node Cert Validity | 365 days      | Node certificate lifetime (1 year)     |
| Renewal Threshold  | 30 days       | Renew when this much time remains      |

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
3. Wait until renewal threshold is reached
4. Verify certificates are renewed

**Verification**:

```bash
# Check certificate expiry (run immediately after creation)
kubectl get secret -n wazuh-test wazuh-test-indexer-certs \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -dates

# Check again after threshold is reached
# Expiry should be updated to a new date
```

**Expected Result**: Certificate `notAfter` date updates when renewal threshold is reached.

## Scenario 3: CA Certificate Renewal

**Objective**: Verify CA renews and all node certs are re-signed.

**Steps**:

1. Deploy cluster and wait for ready
2. Wait until CA renewal threshold is reached
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
3. Wait for certificate renewal
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

## Scenario 5: Concurrent Certificate Renewal

**Objective**: Verify parallel rollouts work correctly.

**Steps**:

1. Deploy cluster with multiple replicas
2. Enable debug logging
3. Watch operator logs during certificate renewal
4. Verify all components update correctly

**Verification**:

```bash
# Watch operator logs
kubectl logs -n wazuh-operator-system \
  deploy/wazuh-operator-controller-manager -f | \
  grep -E "(Waiting for|StatefulSet|certificate|renewal)"
```

**Expected Result**: All components update without blocking each other.

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

**Expected Result**: Automatic retry succeeds.

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

**Expected Result**: Certificates renewed before expiry regardless of rollout duration.

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

## Scenario 9: ECDSA Certificate Support

**Objective**: Verify ECDSA certificates work correctly.

**Steps**:

1. Deploy cluster with ECDSA key algorithm configured
2. Verify certificates are generated with ECDSA keys
3. Verify TLS connections work

**Configuration** (via CRD when supported):

```yaml
spec:
  tls:
    enabled: true
    certConfig:
      keyAlgorithm: ECDSA
      ecdsaCurve: P256  # or P384, P521
```

**Verification**:

```bash
# Check certificate key algorithm
kubectl get secret -n wazuh-test wazuh-test-indexer-certs \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -text | grep "Public Key Algorithm"

# Expected: ecdsa-with-SHA256 or similar
```

**Expected Result**: Certificates generated with ECDSA keys, TLS works correctly.

## Scenario 10: Hot Reload Validation (Zero Restarts)

**Objective**: Verify certificate hot reload works without pod restarts across Wazuh versions.

### Scenario 10a: API-Based Hot Reload (Wazuh 4.9.0 / OpenSearch 2.13)

**Steps**:

1. Deploy cluster with Wazuh 4.9.0 and hot reload enabled
2. Verify `plugins.security.ssl_cert_reload_enabled: true` is in opensearch.yml
3. Note indexer pod restart count
4. Trigger certificate renewal (delete cert secret or wait for threshold)
5. Verify indexer pod restart count is unchanged

**Configuration**:

```yaml
spec:
  version: "4.9.0"
  tls:
    enabled: true
    hotReload:
      enabled: true
    certConfig:
      validity: "1h"
      renewalThreshold: "30m"
```

**Verification**:

```bash
# Record restart count before renewal
kubectl get pods -n wazuh-test -o custom-columns=NAME:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount

# Trigger renewal
kubectl delete secret -n wazuh-test wazuh-test-indexer-certs

# Wait for operator to reconcile, then check restart count again
sleep 60
kubectl get pods -n wazuh-test -o custom-columns=NAME:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount

# Verify the operator called the SSL reload API (check operator logs)
kubectl logs -n wazuh-operator-system deploy/wazuh-operator-controller-manager | grep -i "ssl.*reload\|cert.*reload\|pods/exec"
```

**Expected Result**: Indexer pod restart count is **unchanged** (0 restarts). Operator logs show successful SSL reload API call.

### Scenario 10b: Inotify-Based Hot Reload (Wazuh 4.14.1 / OpenSearch 2.19+)

**Steps**:

1. Deploy cluster with Wazuh 4.14.1 and hot reload enabled
2. Verify `plugins.security.ssl.certificates_hot_reload.enabled: true` is in opensearch.yml
3. Note indexer pod restart count
4. Trigger certificate renewal
5. Verify indexer pod restart count is unchanged

**Configuration**:

```yaml
spec:
  version: "4.14.1"
  tls:
    enabled: true
    hotReload:
      enabled: true
    certConfig:
      validity: "1h"
      renewalThreshold: "30m"
```

**Verification**:

```bash
# Record restart count before renewal
kubectl get pods -n wazuh-test -o custom-columns=NAME:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount

# Trigger renewal
kubectl delete secret -n wazuh-test wazuh-test-indexer-certs

# Wait for kubelet to sync + inotify to detect, then check restart count
sleep 120
kubectl get pods -n wazuh-test -o custom-columns=NAME:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount

# Verify OpenSearch detected the file change (check indexer logs)
kubectl logs -n wazuh-test wazuh-test-indexer-0 | grep -i "certificate\|reload\|inotify"
```

**Expected Result**: Indexer pod restart count is **unchanged** (0 restarts). Indexer logs show certificate reload via file change detection.

## Scenario 11: Cross-Version Configuration Paths

**Objective**: Verify that `UsesIndexerConfigDir()` selects the correct single mount path per version (threshold: Wazuh 4.14.0).

**Steps**:

1. Deploy cluster with Wazuh 4.9.0 (below threshold)
2. Verify opensearch.yml is mounted at `/usr/share/wazuh-indexer/opensearch.yml`
3. Upgrade cluster to Wazuh 4.14.1 (above threshold)
4. Verify opensearch.yml is now mounted at `/usr/share/wazuh-indexer/config/opensearch.yml`

**Verification**:

```bash
# For Wazuh < 4.14.0: config lives at the root indexer directory
kubectl exec -n wazuh-test wazuh-test-indexer-0 -- ls -la /usr/share/wazuh-indexer/opensearch.yml

# For Wazuh >= 4.14.0: config lives under /config/
kubectl exec -n wazuh-test wazuh-test-indexer-0 -- ls -la /usr/share/wazuh-indexer/config/opensearch.yml

# Verify absolute certificate paths in opensearch.yml
kubectl exec -n wazuh-test wazuh-test-indexer-0 -- cat /usr/share/wazuh-indexer/config/opensearch.yml | grep "/usr/share/wazuh-indexer/config/certs"
```

**Expected Result**: Configuration is mounted at the version-appropriate single path. Certificate paths in opensearch.yml are absolute.

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

| Scenario                          | Expected Status |
| --------------------------------- | --------------- |
| Initial Creation                  | PASS            |
| Node Cert Renewal                 | PASS            |
| CA Cert Renewal                   | PASS            |
| Pod Rollout                       | PASS            |
| Concurrent Renewal                | PASS            |
| Optimistic Locking                | PASS            |
| Expiry Under Load                 | PASS            |
| Recovery                          | PASS            |
| ECDSA Support                     | PASS            |
| Hot Reload API (4.9.0)            | PASS            |
| Hot Reload Inotify (4.14.1)       | PASS            |
| Cross-Version Compatibility       | PASS            |

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
