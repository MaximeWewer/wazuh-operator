# Data Models

## Overview

The Wazuh Operator defines 27 Custom Resource Definitions (CRDs) organized into 6 logical categories. All CRDs use API group `resources.wazuh.com` with version `v1` (storage version). Version `v1` is still served for backward compatibility.

## CRD Categories

### 1. Wazuh Core CRDs (4)

These CRDs define the main Wazuh cluster components.

#### WazuhCluster

- **Purpose**: Main orchestrating CRD for deploying a complete Wazuh cluster
- **Modes**:
  - Inline mode: Define manager, indexer, dashboard specs directly
  - Reference mode: Reference separate component CRDs via `managerRef`, `indexerRef`, `dashboardRef`
- **Key Fields**:
  - `version`: Wazuh version (format: `X.Y.Z`)
  - `manager`: Inline manager configuration
  - `indexer`: Inline indexer configuration
  - `dashboard`: Inline dashboard configuration
  - `tls`: TLS/certificate configuration
  - `monitoring`: Prometheus monitoring integration
  - `drain`: Safe scale-down strategy configuration
- **Short Name**: `wc`

#### WazuhManager

- **Purpose**: Defines Wazuh Manager cluster (master + workers)
- **Key Fields**:
  - `master`: Master node specification
  - `workers`: Worker nodes specification (replicas, resources, storage)
  - `clusterKeySecretRef`: Internal cluster communication key
  - `apiCredentials`: Wazuh API credentials
  - `logRotation`: Automated log cleanup configuration
- **Short Name**: `wmgr`

#### WazuhIndexer (based on OpenSearch)

- **Purpose**: Defines OpenSearch indexer cluster for storing Wazuh alerts/archives
- **Key Fields**:
  - `replicas`: Number of indexer nodes
  - `nodePools`: Advanced topology with dedicated node roles (data, master, ingest, etc.)
  - `storageSize`: PVC size per node
  - `opensearchConfig`: Custom OpenSearch configuration
- **Short Name**: `widx`

#### WazuhDashboard (based on OpenSearch Dashboards)

- **Purpose**: Defines Web UI dashboard for Wazuh visualization
- **Key Fields**:
  - `replicas`: Number of dashboard instances
  - `indexerRef`: Reference to associated WazuhIndexer
  - `ingress`: Ingress configuration for external access
- **Short Name**: `wdash`

### 2. Wazuh Configuration CRDs (4)

These CRDs manage Wazuh-specific configuration and operational concerns.

#### WazuhRule

- **Purpose**: Manage Wazuh detection rules declaratively
- **Key Fields**:
  - `clusterRef`: Target WazuhCluster
  - `group`: Rule group name (e.g., "ssh", "web")
  - `targetNodes`: Deploy to "all", "master", or "workers"
  - `priority`: Rule precedence (higher = applied later)
  - `rules`: XML rule definitions
- **Short Name**: `wrule`

#### WazuhDecoder

- **Purpose**: Manage Wazuh log decoders declaratively
- **Key Fields**:
  - `clusterRef`: Target WazuhCluster
  - `decoderName`: Decoder identifier
  - `targetNodes`: Deploy to "all", "master", or "workers"
  - `decoders`: XML decoder definitions
- **Short Name**: `wdec`

#### WazuhCertificate

- **Purpose**: TLS certificate management with auto-generation and hot reload
- **Key Fields**:
  - `clusterRef`: Target WazuhCluster
  - `type`: Certificate type (ca, node, admin, filebeat, indexer, dashboard)
  - `distinguishedName`: X.509 DN configuration
  - `validity`: Certificate validity as duration string (e.g., "365d", "24h", "30m")
  - `autoRenewal`: Auto-renewal configuration with threshold
  - `hotReload`: Enable cert reload without pod restart (Wazuh 4.9+)
  - `secretName`: Secret name to store the certificate
  - `keyConfig`: Key algorithm and size configuration
- **Short Name**: `wzcert`

#### WazuhFilebeat

- **Purpose**: Declarative Filebeat configuration for log forwarding
- **Key Fields**:
  - `clusterRef`: Target WazuhCluster
  - `output`: Output configuration (OpenSearch, Logstash, etc.)
  - `indexTemplates`: Index template definitions
  - `ingestPipelines`: Ingest pipeline definitions
- **Short Name**: `wfb`

### 3. Wazuh Backup/Restore CRDs (2)

These CRDs handle Wazuh Manager data protection.

#### WazuhBackup

- **Purpose**: Schedule or trigger Wazuh Manager backups to S3/MinIO
- **Key Fields**:
  - `clusterRef`: Target WazuhCluster
  - `schedule`: Cron expression (for scheduled backups)
  - `components`: What to backup (agentKeys, fimDatabase, agentDatabase, integrations, alertLogs)
  - `storage`: S3/MinIO configuration (bucket, endpoint, credentials)
  - `retention`: Backup retention policy
- **Short Name**: `wbak`

#### WazuhRestore

- **Purpose**: Restore Wazuh Manager data from S3/MinIO backup
- **Key Fields**:
  - `clusterRef`: Target WazuhCluster
  - `backupName`: Name/path of backup to restore
  - `components`: What to restore
  - `preRestoreBackup`: Create safety backup before restore
- **Short Name**: `wrest`

### 4. OpenSearch Security CRDs (5)

These CRDs manage OpenSearch security configuration (users, roles, permissions).

#### OpenSearchUser

- **Purpose**: Define OpenSearch users
- **Key Fields**:
  - `clusterRef`: Target WazuhCluster/WazuhIndexer
  - `username`: User name
  - `passwordSecretRef`: Reference to Secret containing password
  - `backendRoles`: Backend role assignments
  - `attributes`: Custom user attributes
- **Short Name**: `osuser`

#### OpenSearchRole

- **Purpose**: Define OpenSearch roles with index/cluster permissions
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `clusterPermissions`: Cluster-level permissions
  - `indexPermissions`: Per-index permissions with patterns and actions
  - `tenantPermissions`: Multi-tenancy permissions
- **Short Name**: `osrole`

#### OpenSearchRoleMapping

- **Purpose**: Map backend roles to OpenSearch roles
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `backendRoles`: Backend role names
  - `hosts`: Host-based mapping
  - `users`: User-based mapping
- **Short Name**: `osrmap`

#### OpenSearchActionGroup

- **Purpose**: Define reusable action groups
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `allowedActions`: List of allowed actions
- **Short Name**: `osag`

#### OpenSearchTenant

- **Purpose**: Multi-tenancy tenant definitions
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `description`: Tenant description
- **Short Name**: `ostenant`

### 5. OpenSearch Index Management CRDs (5)

These CRDs manage OpenSearch indices, templates, and lifecycle policies.

#### OpenSearchIndex

- **Purpose**: Create and manage OpenSearch indices
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `settings`: Index settings (shards, replicas, refresh interval, etc.)
  - `mappings`: Field mappings
  - `aliases`: Index aliases
- **Short Name**: `osidx`

#### OpenSearchIndexTemplate

- **Purpose**: Define index templates for automatic index configuration
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `indexPatterns`: Patterns matching target indices
  - `priority`: Template precedence
  - `template`: Settings, mappings, aliases to apply
  - `composedOf`: Component templates to include
- **Short Name**: `osidxt`

#### OpenSearchComponentTemplate

- **Purpose**: Reusable template components
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `template`: Settings/mappings fragment
- **Short Name**: `osctpl`

#### OpenSearchISMPolicy (Index State Management)

- **Purpose**: Automate index lifecycle (rollover, deletion, snapshots)
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `policy`: ISM policy definition (states, transitions, actions)
- **Short Name**: `osism`

#### OpenSearchSnapshotPolicy

- **Purpose**: Automated snapshot scheduling
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `schedule`: Cron expression for snapshots
  - `repository`: Target snapshot repository
  - `indices`: Index patterns to snapshot
  - `retention`: Snapshot retention rules
- **Short Name**: `ossnap`

### 6. OpenSearch Backup/Restore CRDs (3)

These CRDs handle OpenSearch snapshot-based backup and restore.

#### OpenSearchSnapshotRepository

- **Purpose**: Configure snapshot repositories (S3, MinIO, Azure, FS)
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `type`: Repository type (s3, azure, fs)
  - `settings`: Type-specific settings (bucket, endpoint, credentials, etc.)
- **Short Name**: `osrepo`

#### OpenSearchSnapshot

- **Purpose**: Trigger manual snapshots
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `repository`: Target repository name
  - `indices`: Indices to snapshot (supports patterns)
  - `ignoreUnavailable`: Skip missing indices
- **Short Name**: `ossnapshot`

#### OpenSearchRestore

- **Purpose**: Restore indices from snapshots
- **Key Fields**:
  - `clusterRef`: Target cluster
  - `repository`: Source repository
  - `snapshot`: Snapshot name
  - `indices`: Indices to restore
  - `renamePattern`/`renameReplacement`: Rename restored indices
- **Short Name**: `osrest`

## Common Type Patterns

### Reference Types

- `WazuhClusterReference`: Cross-CRD reference to WazuhCluster
- `ComponentRef`: Reference to WazuhManager/WazuhIndexer/WazuhDashboard
- `SecretKeyRef`: Reference to Secret key for sensitive data
- `ConfigMapReference`: Reference to ConfigMap data

### Shared Specifications

- `ImageSpec`: Container image configuration (repository, tag, pullPolicy)
- `ResourceRequirements`: CPU/memory requests and limits
- `PersistentVolumeClaimSpec`: Storage configuration
- `TLSConfig`: TLS/certificate settings
- `MonitoringConfig`: Prometheus ServiceMonitor/PodMonitor configuration
- `DrainConfiguration`: Safe scale-down settings (timeout, grace period, drain strategy)

### Status Patterns

All CRDs follow a consistent status pattern:

```go
type Status struct {
    Conditions []metav1.Condition  // Standard K8s conditions
    Phase      string               // Overall phase (Pending/Running/Ready/Failed)
    // Resource-specific status fields
}
```

**Standard Conditions**:

- `Ready`: Resource is fully operational
- `Progressing`: Changes are being applied
- `Degraded`: Resource is running but degraded
- `Failed`: Irrecoverable error

## CRD Validation

All CRDs use Kubebuilder validation markers:

- `+kubebuilder:validation:Required`: Field is mandatory
- `+kubebuilder:validation:Pattern`: Regex pattern matching
- `+kubebuilder:validation:Minimum`: Numeric minimum
- `+kubebuilder:validation:Enum`: Restricted value set
- `+kubebuilder:default`: Default value if not specified

## Relationships

```
WazuhCluster (1) ─┬─> (1) WazuhManager ──> (1..N) Manager Pods
                  ├─> (1) WazuhIndexer ──> (1..N) Indexer Pods (StatefulSet)
                  └─> (1) WazuhDashboard ─> (1..N) Dashboard Pods

WazuhCluster (1) ───> (0..N) WazuhRule ────> Manager ConfigMaps
WazuhCluster (1) ───> (0..N) WazuhDecoder ─> Manager ConfigMaps
WazuhCluster (1) ───> (0..1) WazuhCertificate ─> TLS Secrets

WazuhIndexer (1) ───> (0..N) OpenSearchUser ──┐
WazuhIndexer (1) ───> (0..N) OpenSearchRole ──┤─> OpenSearch Security API
WazuhIndexer (1) ───> (0..N) OpenSearchRoleMapping ┘

WazuhIndexer (1) ───> (0..N) OpenSearchIndex ──┐
WazuhIndexer (1) ───> (0..N) OpenSearchIndexTemplate ─┤─> OpenSearch Index API
WazuhIndexer (1) ───> (0..N) OpenSearchISMPolicy ─────┘

WazuhIndexer (1) ───> (0..N) OpenSearchSnapshotRepository ──┐
WazuhIndexer (1) ───> (0..N) OpenSearchSnapshot ────────────┤─> OpenSearch Snapshot API
WazuhIndexer (1) ───> (0..N) OpenSearchRestore ─────────────┘

WazuhManager (1) ───> (0..N) WazuhBackup ──> S3/MinIO (tar archives)
WazuhManager (1) ───> (0..N) WazuhRestore ─> S3/MinIO (tar archives)
```

## API Group and Versioning

- **API Group**: `resources.wazuh.com`
- **Storage Version**: `v1` (stable storage version)
- **Served Versions**: `v1` (primary), `v1` (backward compatibility)

## Storage Locations

- **CRD Manifests**: `config/crd/` (generated by controller-gen)
- **Sample Resources**: `config/samples/` (example CRs for each CRD)
- **Type Definitions**: `api/v1/*_types.go` (primary), `api/v1/*_types.go` (compatibility)
- **Generated Code**: `api/v1/zz_generated.deepcopy.go`, `api/v1/zz_generated.deepcopy.go`
