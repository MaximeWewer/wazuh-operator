# Certificate Reconciliation Architecture

This document describes the certificate reconciliation flow in the Wazuh Operator.

## Overview

The Wazuh Operator manages TLS certificates for secure communication between cluster components:

- **CA Certificate**: Root certificate authority for the cluster
- **Indexer Certificates**: TLS certificates for OpenSearch indexer nodes
- **Manager Certificates**: TLS certificates for Wazuh manager (master and workers)
- **Dashboard Certificates**: TLS certificates for OpenSearch dashboard
- **Filebeat Certificates**: TLS certificates for Filebeat log shipping
- **Admin Certificates**: Admin certificates for OpenSearch security management

## Reconciliation Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         WazuhCluster Controller                                 │
│                    (controllers/wazuhcluster_controller.go)                     │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      1. Certificate Reconciliation                              │
│                (CertificateReconciler.ReconcileWithHashes)                      │
│                                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐     │
│  │  CA Cert     │──▶ │ Indexer Cert │──▶ │ Manager Cert │──▶ │ Dashboard  │     │
│  │  (10 min*)   │    │  (5 min*)    │    │  (5 min*)    │    │ (5 min*)   │     │
│  └──────────────┘    └──────────────┘    └──────────────┘    └────────────┘     │
│         │                   │                   │                   │           │
│         ▼                   ▼                   ▼                   ▼           │
│    Check Expiry        Check Expiry        Check Expiry        Check Expiry     │
│    Renew if < 2min*    Renew if < 2min*    Renew if < 2min*    Renew if < 2min* │
│                                                                                 │
│  Returns: CertHashResult { IndexerCertHash, ManagerMasterCertHash, ... }        │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      2. Component Reconciliation                                │
│                                                                                 │
│     ┌──────────────────────────────────────────────────────────────────────┐    │
│     │ IndexerReconciler.ReconcileWithCertHash(cluster, indexerCertHash)    │    │
│     │   - Updates StatefulSet with cert-hash annotation                    │    │
│     │   - BLOCKS waiting for rollout (current issue)                       │    │
│     └──────────────────────────────────────────────────────────────────────┘    │
│                                      │                                          │
│                                      ▼                                          │
│     ┌──────────────────────────────────────────────────────────────────────────┐│
│     │ ClusterReconciler.ReconcileManagerWithCertHashes(cluster, master, worker)││
│     │   - Updates Master StatefulSet with cert-hash annotation                 ││
│     │   - BLOCKS waiting for master rollout                                    ││
│     │   - Updates Worker StatefulSet with cert-hash annotation                 ││
│     │   - BLOCKS waiting for worker rollout                                    ││
│     └──────────────────────────────────────────────────────────────────────────┘│
│                                      │                                          │
│                                      ▼                                          │
│     ┌──────────────────────────────────────────────────────────────────────┐    │
│     │ DashboardReconciler.ReconcileWithCertHash(cluster, dashboardCertHash)│    │
│     │   - Updates Deployment with cert-hash annotation                     │    │
│     │   - BLOCKS waiting for rollout                                       │    │
│     └──────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘

* In test mode (--cert-test-mode): 10 min CA, 5 min node certs, 2 min renewal threshold
  In production: 1825 days CA (5 years), 365 days node certs, 30 days renewal threshold
```

## Key Components

### CertificateReconciler

**Location**: `internal/wazuh/reconciler/certificate_reconciler.go`

Responsible for:

- Creating and renewing the CA certificate
- Creating and renewing all node certificates
- Checking certificate expiry against configurable thresholds
- Returning certificate hashes for pod rollout triggers

Key methods:

- `ReconcileWithHashes()`: Main entry point, returns `CertHashResult`
- `reconcileCA()`: Manages CA certificate lifecycle
- `reconcileNodeCert()`: Generic node certificate creation/renewal
- `reconcileIndexerCerts()`: Indexer-specific certificate handling
- `reconcileManagerCerts()`: Manager master/worker certificate handling
- `reconcileDashboardCerts()`: Dashboard certificate handling

### RolloutWaiter

**Location**: `internal/utils/k8s_rollout.go`

Provides blocking wait functions for pod rollouts:

- `WaitForDeploymentReady()`: Blocks until Deployment is ready
- `WaitForStatefulSetReady()`: Blocks until StatefulSet is ready
- `IsDeploymentReady()`: Non-blocking readiness check
- `IsStatefulSetReady()`: Non-blocking readiness check

### CertHashResult

**Location**: `internal/wazuh/reconciler/certificate_reconciler.go`

Structure containing certificate hashes:

```go
type CertHashResult struct {
    CACertHash            string
    IndexerCertHash       string
    ManagerMasterCertHash string
    ManagerWorkerCertHash string
    DashboardCertHash     string
    FilebeatCertHash      string
}
```

## Certificate Hash Annotation

When certificates are renewed, the operator updates pod template annotations to trigger rollouts:

```yaml
metadata:
  annotations:
    wazuh.com/cert-hash: "sha256:abc123..."
```

The hash is computed from the certificate secret data. When this annotation changes, Kubernetes performs a rolling update of the pods.

## Current Issues

### 1. Blocking Waits During Reconciliation

**Problem**: The component reconcilers use `RolloutWaiter` to wait for pod rollouts to complete. This blocks the entire reconciliation loop, preventing other certificates from being renewed.

**Impact**: In test mode with 5-minute certificates:

- If indexer rollout takes 2+ minutes, manager certificates may expire before renewal
- If manager master rollout takes long, worker certificates may expire
- Serial blocking creates a cascade of timing issues

**Solution Needed**: Non-blocking rollout tracking that allows certificate renewal to continue for all components in parallel.

### 2. Optimistic Locking Conflicts

**Problem**: Multiple concurrent reconciliations (triggered by various events) can cause "object has been modified" errors when updating resources.

**Impact**: Reconciliation failures that require retry, adding delay to certificate renewal.

**Solution Needed**: Retry logic with exponential backoff for k8s API updates.

### 3. Requeue Interval in Test Mode

**Problem**: The default 30-second requeue interval may be too slow for 5-minute certificates with 2-minute renewal threshold.

**Impact**: Certificates may not be checked frequently enough to renew in time.

**Solution Needed**: Configurable, shorter requeue intervals in test mode.

## Configuration

### Test Mode (`--cert-test-mode`)

When enabled via the operator flag:

- CA validity: 10 minutes
- Node certificate validity: 5 minutes
- Renewal threshold: 2 minutes before expiry

### Production Mode (default)

- CA validity: 1825 days (5 years)
- Node certificate validity: 365 days (1 year)
- Renewal threshold: 30 days before expiry

### Custom Configuration via CRD

The `WazuhCluster` CRD supports custom certificate configuration:

```yaml
spec:
  tls:
    enabled: true
    certConfig:
      organization: "My Org"
      country: "US"
      validityDays: 365
      renewalThresholdDays: 30
```

## Secrets Created

| Secret Name                      | Contents           | Used By           |
| -------------------------------- | ------------------ | ----------------- |
| `{cluster}-ca`                   | CA cert, key       | All components    |
| `{cluster}-indexer-certs`        | Node cert, key, CA | Indexer pods      |
| `{cluster}-manager-master-certs` | Node cert, key, CA | Manager master    |
| `{cluster}-manager-worker-certs` | Node cert, key, CA | Manager workers   |
| `{cluster}-dashboard-certs`      | Node cert, key, CA | Dashboard         |
| `{cluster}-filebeat-certs`       | Node cert, key, CA | Filebeat sidecar  |
| `{cluster}-admin-certs`          | Admin cert, key    | Security init job |

## Events Emitted

| Event                    | Type    | Reason                   | When                       |
| ------------------------ | ------- | ------------------------ | -------------------------- |
| CertificateRenewing      | Normal  | CertificateRenewing      | Before renewal starts      |
| CertificateRenewed       | Normal  | CertificateRenewed       | After successful renewal   |
| CertificateRenewalFailed | Warning | CertificateRenewalFailed | When renewal fails         |
| CARenewing               | Normal  | CARenewing               | Before CA renewal starts   |
| CARenewed                | Normal  | CARenewed                | After CA renewal completes |

## Future Improvements

1. **Non-Blocking Rollouts**: Track rollout status without blocking reconciliation
2. **Retry Logic**: Automatic retry for transient API errors
3. **Test Mode Optimization**: Faster reconciliation interval when testing
4. **Certificate Monitoring**: Dedicated certificate expiry monitoring goroutine
5. **Metrics**: Prometheus metrics for certificate status and renewal operations
