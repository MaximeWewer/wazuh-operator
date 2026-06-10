# Wazuh Manager Backup Examples

Backup and restore the **Wazuh Manager** configuration/state (`WazuhBackup`,
`WazuhRestore`). For OpenSearch **indexer data** snapshots, see
[../opensearch-backup/](../opensearch-backup/).

These CRDs require repository plugins on the cluster — start with
`wazuhcluster-with-plugins.yaml`.

| File | Kind | Description |
| ---- | ---- | ----------- |
| [wazuhcluster-with-plugins.yaml](wazuhcluster-with-plugins.yaml) | WazuhCluster | Cluster with repository plugins enabled (prerequisite) |
| [wazuhbackup-oneshot.yaml](wazuhbackup-oneshot.yaml) | WazuhBackup | One-shot backup |
| [wazuhbackup-scheduled.yaml](wazuhbackup-scheduled.yaml) | WazuhBackup | Scheduled backup (cron) |
| [wazuhbackup-gcs.yaml](wazuhbackup-gcs.yaml) | WazuhBackup | Backup to Google Cloud Storage |
| [wazuhbackup-azure.yaml](wazuhbackup-azure.yaml) | WazuhBackup | Backup to Azure Blob Storage |
| [wazuhrestore-basic.yaml](wazuhrestore-basic.yaml) | WazuhRestore | Restore from an S3 backup |

## Related Documentation

- [Backup and Restore](../../features/backup-restore.md)
- [Repository Plugins](../../features/repository-plugins.md)
