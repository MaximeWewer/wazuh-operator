# Backup & Restore

The Wazuh Operator provides comprehensive backup and restore capabilities for both OpenSearch indices and Wazuh Manager data.

## Overview

| Component         | Backup Method           | CRDs                                                                                          | Storage                             |
| ----------------- | ----------------------- | --------------------------------------------------------------------------------------------- | ----------------------------------- |
| **OpenSearch**    | Native Snapshot API     | OpenSearchSnapshotRepository, OpenSearchSnapshot, OpenSearchSnapshotPolicy, OpenSearchRestore | S3, MinIO, GCS, Azure, HDFS, NFS    |
| **Wazuh Manager** | File-based tar archives | WazuhBackup, WazuhRestore                                                                     | S3, MinIO, GCS, Azure, HDFS         |

## OpenSearch Backups

OpenSearch backups use the native [Snapshot API](https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/index/) to create consistent point-in-time copies of indices.

### Prerequisites

#### 1. Install repository plugins

The operator can automatically install OpenSearch repository plugins and configure the keystore. Add `repositoryPlugins` to your WazuhCluster spec:

```yaml
spec:
  indexer:
    repositoryPlugins:
      - name: repository-s3
        clientName: default
        credentialsSecret:
          name: s3-credentials
```

This creates two init containers on every indexer pod:

1. **install-repository-plugins** — Installs the plugin and persists it to the data PVC
2. **setup-keystore** — Creates the OpenSearch keystore with credentials from the referenced Secret

No `allow_insecure_settings` or manual init containers needed. See [Repository Plugins & Keystore](repository-plugins.md) for full details.

**Supported plugins:** `repository-s3`, `repository-gcs`, `repository-azure`, `repository-hdfs`

#### 2. Configure credentials

Create a Secret with your storage credentials:

**S3/MinIO:**

```bash
kubectl create secret generic s3-credentials \
  --namespace wazuh \
  --from-literal=access-key=YOURACCESSKEY \
  --from-literal=secret-key=YOURSECRETKEY
```

**GCS (service account):**

```bash
kubectl create secret generic gcs-credentials \
  --namespace wazuh \
  --from-file=credentials-file=service-account.json
```

**Azure:**

```bash
kubectl create secret generic azure-credentials \
  --namespace wazuh \
  --from-literal=account=mystorageaccount \
  --from-literal=key=base64storageaccountkey==
```

**GCS Workload Identity / HDFS:** No credentials Secret required.

#### 3. MinIO-specific configuration

When using MinIO instead of AWS S3, the following settings are required in the SnapshotRepository:

- `pathStyleAccess: true` — MinIO uses path-style URLs instead of virtual-hosted-style
- `endpoint: http://minio.namespace.svc.cluster.local:9000` — Your MinIO service endpoint
- `region: us-east-1` — Required for the OpenSearch repository-s3 plugin (the AWS SDK needs a region even for MinIO)

### Step 1: Create a Snapshot Repository

A repository defines where snapshots are stored. You must create a repository before taking snapshots.

**MinIO Example:**

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchSnapshotRepository
metadata:
  name: minio-backups
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  type: s3
  settings:
    bucket: wazuh-backups
    basePath: opensearch/snapshots
    endpoint: http://minio.minio.svc.cluster.local:9000
    pathStyleAccess: true
    compress: true
    credentialsSecret:
      name: minio-credentials
      accessKeyKey: access-key
      secretKeyKey: secret-key
  verify: true # Verify repository after creation
```

**AWS S3 Example (keystore-based — recommended):**

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchSnapshotRepository
metadata:
  name: aws-backups
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  type: s3
  settings:
    bucket: my-wazuh-backups
    basePath: production/opensearch
    region: eu-west-1
    compress: true
    serverSideEncryption: true
    storageClass: standard
    useKeystore: true
    client: default # Matches clientName in repositoryPlugins
  verify: true
```

**AWS S3 Example (inline credentials):**

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchSnapshotRepository
metadata:
  name: aws-backups-legacy
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  type: s3
  settings:
    bucket: my-wazuh-backups
    basePath: production/opensearch
    region: eu-west-1
    compress: true
    credentialsSecret:
      name: aws-credentials
      accessKeyKey: aws-access-key-id
      secretKeyKey: aws-secret-access-key
  verify: true
```

**GCS Example:**

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchSnapshotRepository
metadata:
  name: gcs-backups
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  type: gcs
  settings:
    bucket: my-wazuh-snapshots
    basePath: opensearch/snapshots
    compress: true
    useKeystore: true
    client: default
  verify: true
```

**HDFS Example:**

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchSnapshotRepository
metadata:
  name: hdfs-backups
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  type: hdfs
  settings:
    uri: "hdfs://namenode:8020"
    path: "/opensearch/snapshots"
    compress: true
  verify: true
```

### Step 2: Create Snapshots

#### Manual Snapshots (OpenSearchSnapshot)

Trigger snapshots on-demand before maintenance, upgrades, or as ad-hoc backups:

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchSnapshot
metadata:
  name: pre-upgrade
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  repository: minio-backups
  indices:
    - "wazuh-alerts-*"
    - "wazuh-archives-*"
    - "wazuh-monitoring-*"
  ignoreUnavailable: true
  includeGlobalState: false
  waitForCompletion: true
```

The snapshot name is auto-generated with a timestamp: `pre-upgrade-20250105-143022`

Check snapshot status:

```bash
kubectl get opensearchsnapshot pre-upgrade -o yaml
# status:
#   phase: Completed
#   snapshotName: pre-upgrade-20250105-143022
#   message: Snapshot completed successfully
```

#### Scheduled Snapshots (OpenSearchSnapshotPolicy)

For automated backups, use OpenSearchSnapshotPolicy with cron schedules:

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchSnapshotPolicy
metadata:
  name: daily-snapshots
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  repository:
    name: minio-backups
  description: "Daily automated snapshots"
  snapshotConfig:
    indices:
      - "wazuh-alerts-*"
      - "wazuh-archives-*"
  creation:
    schedule:
      expression: "0 2 * * *" # Daily at 2 AM
      timezone: "UTC"
    timeLimit: "1h"
  deletion:
    schedule:
      expression: "0 3 * * *" # Cleanup at 3 AM
    condition:
      maxAge: "30d" # Delete snapshots older than 30 days
      maxCount: 30 # Keep maximum 30 snapshots
      minCount: 7 # Always keep at least 7
```

### Step 3: Restore from Snapshots

Use OpenSearchRestore to restore indices from a snapshot:

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchRestore
metadata:
  name: restore-alerts
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  repository: minio-backups
  snapshot: pre-upgrade-20250105-143022
  indices:
    - "wazuh-alerts-*"
  ignoreUnavailable: true
  includeGlobalState: false
  # Rename indices to avoid conflicts with existing data
  renamePattern: "(.+)"
  renameReplacement: "restored-$1"
  # Optimize restore speed
  indexSettings:
    index.number_of_replicas: "0"
  waitForCompletion: true
```

**Important Notes:**

- You cannot restore to indices that already exist
- Use `renamePattern`/`renameReplacement` to prefix restored indices
- Or delete existing indices before restore
- After restore, increase replicas: `PUT /restored-wazuh-alerts-*/_settings {"index.number_of_replicas": 1}`

## Wazuh Manager Backups

Wazuh Manager backups create tar archives of critical data including agent keys, FIM databases, and configuration files.

### What Gets Backed Up

| Component       | Path                         | Description                        |
| --------------- | ---------------------------- | ---------------------------------- |
| `agentKeys`     | `/var/ossec/etc/client.keys` | Agent registration keys (critical) |
| `fimDatabase`   | `/var/ossec/queue/fim/`      | File Integrity Monitoring database |
| `agentDatabase` | `/var/ossec/queue/db/`       | Agent state databases              |
| `integrations`  | `/var/ossec/integrations/`   | Integration scripts                |
| `alertLogs`     | `/var/ossec/logs/alerts/`    | Alert log files                    |
| `customPaths`   | User-defined                 | Additional paths                   |

### Scheduled Backups (WazuhBackup)

Create a CronJob that backs up Wazuh Manager data on a schedule:

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhBackup
metadata:
  name: daily-backup
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster

  # Components to backup
  components:
    agentKeys: true # CRITICAL - required for agent reconnection
    fimDatabase: true # FIM baseline data
    agentDatabase: true # Agent state information
    integrations: false # Usually static
    alertLogs: false # Can be large - use OpenSearch snapshots instead

  # Cron schedule
  schedule: "0 2 * * *" # Daily at 2 AM UTC

  # Retention policy
  retention:
    maxBackups: 14 # Keep last 14 backups
    maxAge: "30d" # Delete backups older than 30 days

  # S3/MinIO storage
  storage:
    type: s3
    bucket: wazuh-backups
    prefix: "{{ .ClusterName }}/{{ .Namespace }}"
    endpoint: http://minio.minio.svc.cluster.local:9000
    forcePathStyle: true
    credentialsSecret:
      name: minio-backup-credentials
      accessKeyKey: access-key
      secretKeyKey: secret-key

  # Backup timeout
  backupTimeout: "30m"
```

### One-Shot Backups

For manual backups (without schedule), omit the `schedule` field:

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhBackup
metadata:
  name: pre-migration-backup
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  components:
    agentKeys: true
    fimDatabase: true
    agentDatabase: true
  # No schedule = one-shot Job
  storage:
    type: s3
    bucket: wazuh-backups
    prefix: migration
    endpoint: http://minio.minio.svc.cluster.local:9000
    forcePathStyle: true
    credentialsSecret:
      name: minio-backup-credentials
```

### GCS Backups

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhBackup
metadata:
  name: daily-backup-gcs
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  components:
    agentKeys: true
    fimDatabase: true
    agentDatabase: true
  schedule: "0 2 * * *"
  storage:
    type: gcs
    bucket: my-wazuh-backups
    prefix: "{{ .ClusterName }}/{{ .Namespace }}"
    gcs:
      project: my-gcp-project
    credentialsSecret:
      name: gcs-backup-credentials
      accessKeyKey: credentials-file
```

For GCS Workload Identity, omit `credentialsSecret`. The GCS SDK auto-discovers credentials from the pod's ServiceAccount.

### Azure Backups

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhBackup
metadata:
  name: daily-backup-azure
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  components:
    agentKeys: true
    fimDatabase: true
    agentDatabase: true
  schedule: "0 2 * * *"
  storage:
    type: azure
    bucket: wazuh-backups
    azure:
      container: wazuh-backups
      accountName: mystorageaccount
    credentialsSecret:
      name: azure-backup-credentials
      accessKeyKey: account
      secretKeyKey: key
```

### HDFS Backups

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhBackup
metadata:
  name: daily-backup-hdfs
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  components:
    agentKeys: true
    fimDatabase: true
    agentDatabase: true
  schedule: "0 2 * * *"
  storage:
    type: hdfs
    hdfs:
      uri: "http://namenode:9870/webhdfs/v1"
      path: /backups/wazuh
```

### Restore Wazuh Manager Data (WazuhRestore)

Restore from an S3 backup archive:

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhRestore
metadata:
  name: restore-from-backup
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster

  # Source: S3/MinIO location
  source:
    s3:
      bucket: wazuh-backups
      key: "wazuh-cluster/wazuh/daily-backup-20250105-020000.tar.gz"
      endpoint: http://minio.minio.svc.cluster.local:9000
      forcePathStyle: true
      credentialsSecret:
        name: minio-backup-credentials

  # Components to restore
  components:
    agentKeys: true
    fimDatabase: true
    agentDatabase: true

  # Safety options
  preRestoreBackup: true # Create backup before restore
  stopManager: true # Stop manager during restore
  restartAfterRestore: true # Restart after completion

  restoreTimeout: "30m"
```

Or reference an existing WazuhBackup resource:

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhRestore
metadata:
  name: restore-from-wazuhbackup
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  source:
    wazuhBackupRef:
      name: daily-backup
      # Optional: specify a specific backup timestamp
      # backupTimestamp: "20250105-020000"
  preRestoreBackup: true
  stopManager: true
  restartAfterRestore: true
```

### Restore from GCS

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhRestore
metadata:
  name: restore-from-gcs
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  source:
    gcs:
      bucket: my-wazuh-backups
      key: "wazuh-cluster/wazuh/daily-backup-gcs-20260105-020000.tar.gz"
      project: my-gcp-project
      credentialsSecret:
        name: gcs-backup-credentials
        accessKeyKey: credentials-file
  preRestoreBackup: true
  stopManager: true
  restartAfterRestore: true
```

### Restore from Azure

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhRestore
metadata:
  name: restore-from-azure
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  source:
    azure:
      container: wazuh-backups
      key: "wazuh-cluster/wazuh/daily-backup-azure-20260105-020000.tar.gz"
      accountName: mystorageaccount
      credentialsSecret:
        name: azure-backup-credentials
        accessKeyKey: account
        secretKeyKey: key
  preRestoreBackup: true
  stopManager: true
  restartAfterRestore: true
```

### Restore from HDFS

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhRestore
metadata:
  name: restore-from-hdfs
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-cluster
  source:
    hdfs:
      uri: "http://namenode:9870/webhdfs/v1"
      path: /backups/wazuh
      key: "daily-backup-hdfs-20260105-020000.tar.gz"
  preRestoreBackup: true
  stopManager: true
  restartAfterRestore: true
```

## Credentials Setup

Create secrets for storage access:

```bash
# S3/MinIO credentials
kubectl create secret generic s3-credentials \
  --namespace wazuh \
  --from-literal=access-key=YOURACCESSKEY \
  --from-literal=secret-key=YOURSECRETKEY

# GCS credentials (service account JSON)
kubectl create secret generic gcs-credentials \
  --namespace wazuh \
  --from-file=credentials-file=service-account.json

# Azure credentials
kubectl create secret generic azure-credentials \
  --namespace wazuh \
  --from-literal=account=mystorageaccount \
  --from-literal=key=base64storageaccountkey==
```

**Production Recommendations:**

- **AWS:** Use IRSA (IAM Roles for Service Accounts) instead of static credentials
- **GCS:** Use Workload Identity — omit `credentialsSecret` and the GCS SDK auto-discovers credentials
- **Azure:** Use Azure AD Workload Identity where available

## Monitoring Backup Status

### OpenSearch Snapshots

```bash
# Check repository status
kubectl get opensearchsnapshotrepository -n wazuh
# NAME            PHASE   MESSAGE
# minio-backups   Ready   Repository verified

# Check snapshot status
kubectl get opensearchsnapshot -n wazuh
# NAME          PHASE       SNAPSHOT-NAME                 MESSAGE
# pre-upgrade   Completed   pre-upgrade-20250105-143022   Snapshot completed

# Check policy status
kubectl get opensearchsnapshotpolicy -n wazuh
# NAME              PHASE   LAST-EXECUTION
# daily-snapshots   Ready   2025-01-05T02:00:00Z
```

### Wazuh Backups

```bash
# Check backup status
kubectl get wazuhbackup -n wazuh
# NAME           PHASE       LAST-BACKUP              MESSAGE
# daily-backup   Completed   2025-01-05T02:00:15Z     Backup completed successfully

# Check restore status
kubectl get wazuhrestore -n wazuh
# NAME                  PHASE       DURATION   MESSAGE
# restore-from-backup   Completed   2m15s      Restore completed successfully

# View backup Job logs
kubectl logs -n wazuh job/daily-backup-20250105-020000
```

## Best Practices

### Backup Strategy

1. **OpenSearch Indices:**

   - Use scheduled policies for daily automated snapshots
   - Trigger manual snapshots before upgrades
   - Keep 30 days of snapshots with 7 minimum retention

2. **Wazuh Manager:**

   - Always backup `agentKeys` - critical for agent reconnection
   - Use scheduled backups for ongoing protection
   - Create one-shot backups before migrations

3. **Storage:**
   - Use separate buckets or prefixes per environment
   - Enable server-side encryption for sensitive data
   - Consider lifecycle policies for cost optimization (S3, GCS, Azure)
   - Use `repositoryPlugins` + `useKeystore: true` for secure credential management
   - GCS Workload Identity and Azure AD Workload Identity avoid static credentials entirely

### Restore Testing

1. Test restores regularly to verify backup integrity
2. Use `renamePattern` to restore to test indices without affecting production
3. Document and practice the restore procedure

### Disaster Recovery

1. Store snapshots in a different region/zone than production
2. Keep a copy of credentials in a secure location
3. Maintain documentation of all backup configurations

## Troubleshooting

### Repository Not Ready

```bash
kubectl describe opensearchsnapshotrepository minio-backups -n wazuh
```

Common issues:

- Plugin not installed (check init container logs)
- Incorrect credentials
- Network connectivity to S3/MinIO
- Bucket doesn't exist or wrong permissions

### Snapshot Failed

```bash
# Check OpenSearch snapshot status
kubectl exec -n wazuh wazuh-cluster-indexer-0 -- \
  curl -k https://localhost:9200/_snapshot/minio-backups/_all
```

### Backup Job Failed

```bash
# Check Job status
kubectl describe job -n wazuh daily-backup-xxxxx

# Check pod logs
kubectl logs -n wazuh -l job-name=daily-backup-xxxxx
```

### Restore Issues

- **Index already exists:** Use `renamePattern` or delete existing indices first
- **Shard allocation failed:** Check cluster health and disk space
- **Permission denied:** Verify ServiceAccount RBAC permissions

## Related Documentation

- [Repository Plugins & Keystore](repository-plugins.md) - Automatic plugin installation and secure credentials
- [Advanced Indexer Topology](advanced-indexer-topology.md) - NodePools and dedicated roles
- [Drain Strategy](drain-strategy.md) - Safe scale-down operations
- [Volume Expansion](volume-expansion.md) - Storage management
