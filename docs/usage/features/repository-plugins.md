# Repository Plugins & Keystore

The Wazuh Operator can automatically install OpenSearch repository plugins (S3, GCS, Azure, HDFS) and configure the OpenSearch keystore with secure credentials. This eliminates the need for `allow_insecure_settings` and manual plugin management.

## How It Works

When `spec.indexer.repositoryPlugins` is configured in your WazuhCluster, the operator adds two init containers to every indexer pod:

1. **install-repository-plugins** - Installs the specified plugins from the OpenSearch plugin registry and persists them to the data PVC
2. **setup-keystore** - Creates a fresh OpenSearch keystore on every pod restart, populated from the referenced Kubernetes Secrets

This approach ensures:

- Plugins survive pod restarts (persisted to PVC)
- Credentials are always up-to-date (keystore rebuilt from Secrets on every restart)
- No plaintext credentials in OpenSearch settings
- Coexistence with the Prometheus monitoring plugin

## Supported Plugins

| Plugin | Description | Keystore Keys |
|--------|-------------|---------------|
| `repository-s3` | Amazon S3 / MinIO | `access_key`, `secret_key` |
| `repository-gcs` | Google Cloud Storage | `credentials_file` (JSON) |
| `repository-azure` | Azure Blob Storage | `account`, `key` |
| `repository-hdfs` | Hadoop HDFS | None (no keystore needed) |

## Configuration

### Basic Example (S3/MinIO)

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.9.2"
  indexer:
    replicas: 3
    repositoryPlugins:
      - name: repository-s3
        clientName: default
        credentialsSecret:
          name: s3-credentials
          # Default keys: access-key, secret-key
```

Create the credentials Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: s3-credentials
type: Opaque
stringData:
  access-key: "AKIAIOSFODNN7EXAMPLE"
  secret-key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

### GCS with Service Account

```yaml
repositoryPlugins:
  - name: repository-gcs
    clientName: default
    credentialsSecret:
      name: gcs-credentials
```

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: gcs-credentials
type: Opaque
data:
  credentials-file: <base64-encoded-service-account-json>
```

### GCS with Workload Identity

For GCS Workload Identity, omit `credentialsSecret`. The GCS SDK auto-discovers credentials from the pod's ServiceAccount:

```yaml
repositoryPlugins:
  - name: repository-gcs
    clientName: default
    # No credentialsSecret - uses Workload Identity
```

### Azure Blob Storage

```yaml
repositoryPlugins:
  - name: repository-azure
    clientName: default
    credentialsSecret:
      name: azure-credentials
```

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: azure-credentials
type: Opaque
stringData:
  account: "mystorageaccount"
  key: "base64storageaccountkey=="
```

### Multiple Backends

You can install multiple plugins simultaneously:

```yaml
repositoryPlugins:
  - name: repository-s3
    clientName: minio
    credentialsSecret:
      name: minio-credentials
  - name: repository-gcs
    clientName: prod-gcs
    credentialsSecret:
      name: gcs-credentials
```

### Custom Key Names

Override the default Secret key names:

```yaml
repositoryPlugins:
  - name: repository-s3
    credentialsSecret:
      name: my-secret
      keys:
        access-key: "aws_access_key_id"
        secret-key: "aws_secret_access_key"
```

## Using with Snapshot Repositories

Once plugins are installed, create an `OpenSearchSnapshotRepository` with `useKeystore: true`:

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchSnapshotRepository
metadata:
  name: my-s3-repo
spec:
  clusterRefs:
    - name: wazuh
      namespace: wazuh
  type: s3
  settings:
    bucket: my-snapshots
    basePath: wazuh
    useKeystore: true
    client: default  # Matches clientName in repositoryPlugins
```

The operator will:

1. Create the repository in OpenSearch referencing the keystore client
2. Call `/_nodes/reload_secure_settings` to ensure credentials are loaded
3. Verify the repository is accessible

## Credential Rotation

Since the keystore is rebuilt from Secrets on every pod restart, updating a Secret's data will take effect on the next pod restart. To force an immediate reload:

1. Update the Kubernetes Secret
2. Perform a rolling restart of the indexer StatefulSet

The operator does NOT automatically restart pods when Secrets change (this is by design to avoid disruption).
