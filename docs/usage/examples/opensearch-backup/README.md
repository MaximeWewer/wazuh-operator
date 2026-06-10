# OpenSearch Backup Examples

Snapshot and restore the **OpenSearch indexer** data via repositories,
snapshots, scheduled policies and restores. For **Wazuh Manager** backups, see
[../wazuh-backup/](../wazuh-backup/).

| File | Kind | Description |
| ---- | ---- | ----------- |
| [opensearchsnapshotrepository-s3.yaml](opensearchsnapshotrepository-s3.yaml) | OpenSearchSnapshotRepository | AWS S3 repository |
| [opensearchsnapshotrepository-gcs.yaml](opensearchsnapshotrepository-gcs.yaml) | OpenSearchSnapshotRepository | Google Cloud Storage repository |
| [opensearchsnapshotrepository-minio.yaml](opensearchsnapshotrepository-minio.yaml) | OpenSearchSnapshotRepository | MinIO (S3-compatible) repository |
| [opensearchsnapshot-manual.yaml](opensearchsnapshot-manual.yaml) | OpenSearchSnapshot | One-off manual snapshot |
| [opensearchsnapshotpolicy-daily.yaml](opensearchsnapshotpolicy-daily.yaml) | OpenSearchSnapshotPolicy | Scheduled daily snapshots |
| [opensearchrestore-basic.yaml](opensearchrestore-basic.yaml) | OpenSearchRestore | Restore indices from a snapshot |

## Usage

```bash
# Register a repository, then snapshot the indexer
kubectl apply -f opensearchsnapshotrepository-s3.yaml
kubectl apply -f opensearchsnapshot-manual.yaml
```

## Related Documentation

- [Backup and Restore](../../features/backup-restore.md)
