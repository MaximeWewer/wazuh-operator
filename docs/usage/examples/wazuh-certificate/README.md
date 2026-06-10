# Wazuh Certificate Examples

`WazuhCertificate` manages a TLS certificate as a standalone resource — an
alternative to the inline `spec.tls` block on `WazuhCluster`. Useful when you
want per-certificate lifecycle (auto-renewal, custom SANs) managed separately.

This CRD uses a single `spec.clusterRef` (name + namespace).

| File | Type | Description |
| ---- | ---- | ----------- |
| [wazuhcertificate-indexer.yaml](wazuhcertificate-indexer.yaml) | `indexer` | Indexer node cert with auto-SANs and daily renewal check |
| [wazuhcertificate-admin.yaml](wazuhcertificate-admin.yaml) | `admin` | Admin cert (securityadmin / cluster admin) |

Valid `spec.type` values: `ca`, `node`, `admin`, `filebeat`, `indexer`, `dashboard`.

## Related Documentation

- [TLS Configuration](../../features/tls.md)
