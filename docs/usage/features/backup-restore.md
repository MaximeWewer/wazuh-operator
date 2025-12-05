# Backup & Restore

The Wazuh Operator provides comprehensive backup and restore capabilities for both OpenSearch indices and Wazuh Manager data.

## Overview

| Component         | Backup Method           | CRDs                                                                                          | Storage               |
| ----------------- | ----------------------- | --------------------------------------------------------------------------------------------- | --------------------- |
| **OpenSearch**    | Native Snapshot API     | OpenSearchSnapshotRepository, OpenSearchSnapshot, OpenSearchSnapshotPolicy, OpenSearchRestore | S3, MinIO, Azure, NFS |
| **Wazuh Manager** | File-based tar archives | WazuhBackup, WazuhRestore                                                                     | S3, MinIO             |

## OpenSearch Backups

OpenSearch backups use the native [Snapshot API](https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/index/) to create consistent point-in-time copies of indices.

### Prerequisites

The `repository-s3` plugin must be installed for S3/MinIO backends. Add an init container to install it:

```yaml
spec:
  indexer:
    initContainers:
      - name: install-repository-s3
        image: opensearchproject/opensearch:2.x
        command:
          - sh
          - -c
          - |
            /usr/share/opensearch/bin/opensearch-plugin install --batch repository-s3
            cp -r /usr/share/opensearch/plugins/repository-s3 /plugins/
        volumeMounts:
          - name: plugins
            mountPath: /plugins
```

### Step 1: Create a Snapshot Repository

A repository defines where snapshots are stored. You must create a repository before taking snapshots.

**MinIO Example:**

```yaml
apiVersion: resources.wazuh.com/v1alpha1
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
      accessKeyKey: accessKeyId
      secretKeyKey: secretAccessKey
  verify: true # Verify repository after creation
```

**AWS S3 Example:**

```yaml
apiVersion: resources.wazuh.com/v1alpha1
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
    credentialsSecret:
      name: aws-credentials
      accessKeyKey: aws-access-key-id
      secretKeyKey: aws-secret-access-key
  verify: true
```

### Step 2: Create Snapshots

#### Manual Snapshots (OpenSearchSnapshot)

Trigger snapshots on-demand before maintenance, upgrades, or as ad-hoc backups:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
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
apiVersion: resources.wazuh.com/v1alpha1
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
apiVersion: resources.wazuh.com/v1alpha1
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
apiVersion: resources.wazuh.com/v1alpha1
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
      accessKeyKey: accessKeyId
      secretKeyKey: secretAccessKey

  # Backup timeout
  backupTimeout: "30m"
```

### One-Shot Backups

For manual backups (without schedule), omit the `schedule` field:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
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

### Restore Wazuh Manager Data (WazuhRestore)

Restore from an S3 backup archive:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
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
apiVersion: resources.wazuh.com/v1alpha1
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

## Credentials Setup

Create secrets for S3/MinIO access:

```bash
# MinIO credentials
kubectl create secret generic minio-backup-credentials \
  --namespace wazuh \
  --from-literal=accessKeyId=YOURACCESSKEY \
  --from-literal=secretAccessKey=YOURSECRETKEY

# AWS credentials
kubectl create secret generic aws-credentials \
  --namespace wazuh \
  --from-literal=aws-access-key-id=AKIAIOSFODNN7EXAMPLE \
  --from-literal=aws-secret-access-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Production Recommendation:** For AWS, use IRSA (IAM Roles for Service Accounts) instead of static credentials.

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
   - Consider S3 lifecycle policies for cost optimization

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

- [Advanced Indexer Topology](advanced-indexer-topology.md) - NodePools and dedicated roles
- [Drain Strategy](drain-strategy.md) - Safe scale-down operations
- [Volume Expansion](volume-expansion.md) - Storage management
