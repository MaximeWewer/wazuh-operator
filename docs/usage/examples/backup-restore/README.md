# Backup & Restore Examples

Two backup paths are covered:

- **OpenSearch indexer data** — `OpenSearchSnapshotRepository`, `OpenSearchSnapshot`,
  `OpenSearchSnapshotPolicy`, `OpenSearchRestore`.
- **Wazuh Manager configuration/state** — `WazuhBackup`, `WazuhRestore`
  (requires repository plugins on the cluster).

## OpenSearch (indexer)

| File | Kind | Description |
| ---- | ---- | ----------- |
| [opensearchsnapshotrepository-s3.yaml](opensearchsnapshotrepository-s3.yaml) | OpenSearchSnapshotRepository | AWS S3 repository |
| [opensearchsnapshotrepository-gcs.yaml](opensearchsnapshotrepository-gcs.yaml) | OpenSearchSnapshotRepository | Google Cloud Storage repository |
| [opensearchsnapshotrepository-minio.yaml](opensearchsnapshotrepository-minio.yaml) | OpenSearchSnapshotRepository | MinIO (S3-compatible) repository |
| [opensearchsnapshot-manual.yaml](opensearchsnapshot-manual.yaml) | OpenSearchSnapshot | One-off manual snapshot |
| [opensearchsnapshotpolicy-daily.yaml](opensearchsnapshotpolicy-daily.yaml) | OpenSearchSnapshotPolicy | Scheduled daily snapshots |
| [opensearchrestore-basic.yaml](opensearchrestore-basic.yaml) | OpenSearchRestore | Restore indices from a snapshot |

## Wazuh Manager

| File | Kind | Description |
| ---- | ---- | ----------- |
| [wazuhcluster-with-plugins.yaml](wazuhcluster-with-plugins.yaml) | WazuhCluster | Cluster with repository plugins enabled (prerequisite) |
| [wazuhbackup-oneshot.yaml](wazuhbackup-oneshot.yaml) | WazuhBackup | One-shot backup |
| [wazuhbackup-scheduled.yaml](wazuhbackup-scheduled.yaml) | WazuhBackup | Scheduled backup |
| [wazuhbackup-gcs.yaml](wazuhbackup-gcs.yaml) | WazuhBackup | Backup to Google Cloud Storage |
| [wazuhbackup-azure.yaml](wazuhbackup-azure.yaml) | WazuhBackup | Backup to Azure Blob Storage |
| [wazuhrestore-basic.yaml](wazuhrestore-basic.yaml) | WazuhRestore | Restore from an S3 backup |

## Related Documentation

- [Backup and Restore](../../features/backup-restore.md)
- [Repository Plugins](../../features/repository-plugins.md)
