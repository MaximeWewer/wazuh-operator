# Wazuh Operator CRD Reference

This document provides a complete reference for all Custom Resource Definitions (CRDs) supported by the Wazuh Operator.

## Table of Contents

- [WazuhCluster](#wazuhcluster)
- [OpenSearch Security CRDs](#opensearch-security-crds)
  - [OpenSearchUser](#opensearchuser)
  - [OpenSearchRole](#opensearchrole)
  - [OpenSearchRoleMapping](#opensearchrolemapping)
  - [OpenSearchTenant](#opensearchtenant)
  - [OpenSearchActionGroup](#opensearchactiongroup)
  - [OpenSearchAuthConfig](#opensearchauthconfig)
- [OpenSearch Index Management CRDs](#opensearch-index-management-crds)
  - [OpenSearchIndex](#opensearchindex)
  - [OpenSearchIndexTemplate](#opensearchindextemplate)
  - [OpenSearchComponentTemplate](#opensearchcomponenttemplate)
  - [OpenSearchISMPolicy](#opensearchismpolicy)
  - [OpenSearchSnapshotPolicy](#opensearchsnapshotpolicy)
- [OpenSearch Backup CRDs](#opensearch-backup-crds)
  - [OpenSearchSnapshotRepository](#opensearchsnapshotrepository)
  - [OpenSearchSnapshot](#opensearchsnapshot)
  - [OpenSearchRestore](#opensearchrestore)
- [Wazuh Configuration CRDs](#wazuh-configuration-crds)
  - [WazuhRule](#wazuhrule)
  - [WazuhDecoder](#wazuhdecoder)
  - [WazuhFilebeat](#wazuhfilebeat)
- [Wazuh Backup CRDs](#wazuh-backup-crds)
  - [WazuhBackup](#wazuhbackup)
  - [WazuhRestore](#wazuhrestore)

---

## WazuhCluster

The main CRD for deploying a complete Wazuh stack (Manager, Indexer, Dashboard).

**API Group:** `resources.wazuh.com/v1alpha1`
**Kind:** `WazuhCluster`
**Short Name:** `wc`

### Spec Fields

| Field              | Type                                      | Required | Default | Description                   |
| ------------------ | ----------------------------------------- | -------- | ------- | ----------------------------- |
| `version`          | string                                    | **Yes**  | -       | Wazuh version (format: X.Y.Z) |
| `storageClassName` | string                                    | No       | -       | Storage class for all PVCs    |
| `imagePullSecrets` | []LocalObjectReference                    | No       | -       | Image pull secrets            |
| `tls`              | [TLSConfig](#tlsconfig)                   | No       | -       | TLS configuration             |
| `monitoring`       | [MonitoringConfig](#monitoringconfig)     | No       | -       | Prometheus monitoring         |
| `drain`            | [DrainConfiguration](#drainconfiguration) | No       | -       | Drain strategy configuration  |
| `manager`          | [ManagerSpec](#managerspec)               | No       | -       | Manager configuration         |
| `indexer`          | [IndexerSpec](#indexerspec)               | No       | -       | Indexer configuration         |
| `dashboard`        | [DashboardSpec](#dashboardspec)           | No       | -       | Dashboard configuration       |

### TLSConfig

| Field        | Type                                    | Required | Default | Description                         |
| ------------ | --------------------------------------- | -------- | ------- | ----------------------------------- |
| `enabled`    | bool                                    | No       | `true`  | Enable TLS                          |
| `certConfig` | [CertificateConfig](#certificateconfig) | No       | -       | Auto-generated certificate settings |
| `hotReload`  | [HotReloadConfig](#hotreloadconfig)     | No       | -       | Hot reload settings                 |

> **Note**: Cert-manager integration and custom certificates are planned features but not yet implemented.

### CertificateConfig

| Field                    | Type   | Required | Default      | Description             |
| ------------------------ | ------ | -------- | ------------ | ----------------------- |
| `country`                | string | No       | `US`         | X.509 Country           |
| `state`                  | string | No       | `California` | X.509 State             |
| `locality`               | string | No       | `California` | X.509 Locality          |
| `organization`           | string | No       | `Wazuh`      | X.509 Organization      |
| `organizationalUnit`     | string | No       | `Wazuh`      | X.509 OU                |
| `commonName`             | string | No       | `admin`      | X.509 CN                |
| `validityDays`           | int    | No       | `365`        | Certs validity (days)   |
| `renewalThresholdDays`   | int    | No       | `30`         | Certs renewal threshold |
| `caValidityDays`         | int    | No       | `730`        | CA validity (days)      |
| `caRenewalThresholdDays` | int    | No       | `60`         | CA renewal threshold    |

### HotReloadConfig

| Field            | Type | Required | Default | Description       |
| ---------------- | ---- | -------- | ------- | ----------------- |
| `enabled`        | bool | No       | `true`  | Enable hot reload |
| `forceAPIReload` | bool | No       | `false` | Force API reload  |

### MonitoringConfig

| Field             | Type                                            | Required | Default | Description             |
| ----------------- | ----------------------------------------------- | -------- | ------- | ----------------------- |
| `enabled`         | bool                                            | No       | `false` | Enable monitoring       |
| `wazuhExporter`   | [WazuhExporterConfig](#wazuhexporterconfig)     | No       | -       | Wazuh exporter sidecar  |
| `indexerExporter` | [IndexerExporterConfig](#indexerexporterconfig) | No       | -       | OpenSearch plugin       |
| `serviceMonitor`  | [ServiceMonitorConfig](#servicemonitorconfig)   | No       | -       | ServiceMonitor settings |

### DrainConfiguration

Configuration for safe scale-down operations. See [Drain Strategy](features/drain-strategy.md) for detailed documentation.

| Field     | Type                                      | Required | Default | Description                           |
| --------- | ----------------------------------------- | -------- | ------- | ------------------------------------- |
| `dryRun`  | bool                                      | No       | `false` | Preview mode without making changes   |
| `indexer` | [IndexerDrainConfig](#indexerdrainconfig) | No       | -       | Indexer drain settings                |
| `manager` | [ManagerDrainConfig](#managerdrainconfig) | No       | -       | Manager drain settings                |
| `retry`   | [DrainRetryConfig](#drainretryconfig)     | No       | -       | Retry configuration for failed drains |

### IndexerDrainConfig

| Field                   | Type     | Required | Default | Description                          |
| ----------------------- | -------- | -------- | ------- | ------------------------------------ |
| `timeout`               | Duration | No       | `30m`   | Maximum time for shard relocation    |
| `healthCheckInterval`   | Duration | No       | `10s`   | Interval between shard status checks |
| `minGreenHealthTimeout` | Duration | No       | `5m`    | Wait time for cluster green health   |

### ManagerDrainConfig

| Field                | Type     | Required | Default | Description                         |
| -------------------- | -------- | -------- | ------- | ----------------------------------- |
| `timeout`            | Duration | No       | `15m`   | Maximum time for queue drain        |
| `queueCheckInterval` | Duration | No       | `5s`    | Interval between queue depth checks |
| `gracePeriod`        | Duration | No       | `30s`   | Wait time after queue is empty      |

### DrainRetryConfig

| Field               | Type     | Required | Default | Description                      |
| ------------------- | -------- | -------- | ------- | -------------------------------- |
| `maxAttempts`       | int32    | No       | `3`     | Maximum retry attempts           |
| `initialDelay`      | Duration | No       | `5m`    | Initial delay before first retry |
| `backoffMultiplier` | float64  | No       | `2.0`   | Exponential backoff factor       |
| `maxDelay`          | Duration | No       | `30m`   | Maximum delay between retries    |

### WazuhExporterConfig

| Field          | Type                 | Required | Default                              | Description         |
| -------------- | -------------------- | -------- | ------------------------------------ | ------------------- |
| `enabled`      | bool                 | No       | `false`                              | Enable exporter     |
| `image`        | string               | No       | `kennyopennix/wazuh-exporter:latest` | Exporter image      |
| `port`         | int32                | No       | `9090`                               | Metrics port        |
| `apiProtocol`  | string               | No       | `https`                              | API protocol        |
| `apiVerifySSL` | bool                 | No       | `false`                              | Verify SSL          |
| `logLevel`     | string               | No       | `INFO`                               | Log level           |
| `resources`    | ResourceRequirements | No       | -                                    | Container resources |

### IndexerExporterConfig

| Field     | Type   | Required | Default | Description     |
| --------- | ------ | -------- | ------- | --------------- |
| `enabled` | bool   | No       | `false` | Enable exporter |
| `version` | string | No       | Auto    | Plugin version  |

### ServiceMonitorConfig

| Field           | Type              | Required | Default | Description           |
| --------------- | ----------------- | -------- | ------- | --------------------- |
| `enabled`       | bool              | No       | `false` | Create ServiceMonitor |
| `labels`        | map[string]string | No       | -       | ServiceMonitor labels |
| `interval`      | string            | No       | `30s`   | Scrape interval       |
| `scrapeTimeout` | string            | No       | `10s`   | Scrape timeout        |

### ManagerSpec

| Field                         | Type                                          | Required | Default | Description                      |
| ----------------------------- | --------------------------------------------- | -------- | ------- | -------------------------------- |
| `image`                       | [ImageSpec](#imagespec)                       | No       | -       | Image override                   |
| `clusterKeySecretRef`         | SecretKeySelector                             | No       | -       | Cluster key secret               |
| `apiCredentials`              | [CredentialsSecretRef](#credentialssecretref) | No       | -       | API credentials                  |
| `authdPasswordSecretRef`      | SecretKeySelector                             | No       | -       | Authd password                   |
| `filebeatSSLVerificationMode` | string                                        | No       | `full`  | SSL mode (full/none/certificate) |
| `config`                      | [WazuhConfigSpec](#wazuhconfigspec)           | No       | -       | OSSEC configuration              |
| `logRotation`                 | [LogRotationSpec](#logrotationspec)           | No       | -       | Log rotation CronJob             |
| `master`                      | [MasterSpec](#masterspec)                     | **Yes**  | -       | Master node config               |
| `workers`                     | [WorkerSpec](#workerspec)                     | **Yes**  | -       | Worker nodes config              |

### LogRotationSpec

| Field             | Type     | Required | Default                  | Description                                                               |
| ----------------- | -------- | -------- | ------------------------ | ------------------------------------------------------------------------- |
| `enabled`         | bool     | No       | `false`                  | Enable log rotation CronJob                                               |
| `schedule`        | string   | No       | `0 0 * * 1`              | Cron schedule (default: weekly on Monday at midnight)                     |
| `retentionDays`   | int32    | No       | `7`                      | Days to retain log files                                                  |
| `maxFileSizeMB`   | int32    | No       | `0`                      | Max file size in MB (0 = disabled)                                        |
| `combinationMode` | string   | No       | `or`                     | How age/size filters combine: `or` (delete if old OR large), `and` (both) |
| `paths`           | []string | No       | alerts/, archives/       | Log paths to clean                                                        |
| `image`           | string   | No       | `bitnami/kubectl:latest` | kubectl image for CronJob                                                 |

### WazuhConfigSpec

| Field                  | Type                                  | Required | Default | Description                 |
| ---------------------- | ------------------------------------- | -------- | ------- | --------------------------- |
| `global`               | [OSSECGlobalSpec](#ossecglobalspec)   | No       | -       | Global section              |
| `alerts`               | [OSSECAlertsSpec](#ossecalertsspec)   | No       | -       | Alerts section              |
| `logging`              | [OSSECLoggingSpec](#ossecloggingspec) | No       | -       | Logging section             |
| `remote`               | [OSSECRemoteSpec](#ossecremotespec)   | No       | -       | Remote section              |
| `auth`                 | [OSSECAuthSpec](#ossecauthspec)       | No       | -       | Auth section                |
| `masterConfig`         | string                                | No       | -       | Raw XML for master          |
| `workerConfig`         | string                                | No       | -       | Raw XML for workers         |
| `localInternalOptions` | string                                | No       | -       | local_internal_options.conf |

### OSSECGlobalSpec

| Field                          | Type   | Required | Default | Description             |
| ------------------------------ | ------ | -------- | ------- | ----------------------- |
| `jsonoutOutput`                | bool   | No       | `true`  | JSON output             |
| `alertsLog`                    | bool   | No       | `true`  | Enable alerts.log       |
| `logAll`                       | bool   | No       | `false` | Log all events          |
| `logAllJson`                   | bool   | No       | `false` | Log all in JSON         |
| `emailNotification`            | bool   | No       | `false` | Email notifications     |
| `smtpServer`                   | string | No       | -       | SMTP server             |
| `emailFrom`                    | string | No       | -       | From address            |
| `emailTo`                      | string | No       | -       | To address              |
| `emailMaxPerHour`              | int    | No       | `12`    | Max emails/hour         |
| `agentsDisconnectionTime`      | string | No       | `10m`   | Disconnection time      |
| `agentsDisconnectionAlertTime` | string | No       | `0`     | Alert time (0=disabled) |

### OSSECAlertsSpec

| Field             | Type | Required | Default | Description            |
| ----------------- | ---- | -------- | ------- | ---------------------- |
| `logAlertLevel`   | int  | No       | `3`     | Min log level (0-16)   |
| `emailAlertLevel` | int  | No       | `12`    | Min email level (0-16) |

### OSSECLoggingSpec

| Field       | Type   | Required | Default | Description                               |
| ----------- | ------ | -------- | ------- | ----------------------------------------- |
| `logFormat` | string | No       | `plain` | Log format: `plain`, `json`, `plain,json` |

### OSSECRemoteSpec

| Field        | Type   | Required | Default  | Description        |
| ------------ | ------ | -------- | -------- | ------------------ |
| `connection` | string | No       | `secure` | Connection type    |
| `port`       | int    | No       | `1514`   | Port               |
| `protocol`   | string | No       | `tcp`    | Protocol (tcp/udp) |
| `queueSize`  | int    | No       | `131072` | Queue size         |

### OSSECAuthSpec

| Field                 | Type         | Required | Default | Description      |
| --------------------- | ------------ | -------- | ------- | ---------------- |
| `disabled`            | bool         | No       | `false` | Disable authd    |
| `port`                | int          | No       | `1515`  | Port             |
| `useSourceIP`         | bool         | No       | `false` | Use source IP    |
| `purge`               | bool         | No       | `true`  | Purge old keys   |
| `usePassword`         | bool         | No       | `false` | Require password |
| `passwordSecretRef`   | SecretKeyRef | No       | -       | Password secret  |
| `enabledOnMasterOnly` | bool         | No       | `true`  | Master only      |

### MasterSpec

| Field                      | Type                        | Required | Default | Description             |
| -------------------------- | --------------------------- | -------- | ------- | ----------------------- |
| `storageSize`              | string                      | No       | `50Gi`  | Storage size            |
| `resources`                | ResourceRequirements        | No       | -       | Resources               |
| `service`                  | [ServiceSpec](#servicespec) | No       | -       | Service config          |
| `nodeSelector`             | map[string]string           | No       | -       | Node selector           |
| `tolerations`              | []Toleration                | No       | -       | Tolerations             |
| `affinity`                 | Affinity                    | No       | -       | Affinity rules          |
| `extraConfig`              | string                      | No       | -       | Extra ossec.conf XML    |
| `extraVolumes`             | []Volume                    | No       | -       | Extra volumes           |
| `extraVolumeMounts`        | []VolumeMount               | No       | -       | Extra mounts            |
| `podAnnotations`           | map[string]string           | No       | -       | Pod annotations         |
| `annotations`              | map[string]string           | No       | -       | StatefulSet annotations |
| `ingress`                  | [IngressSpec](#ingressspec) | No       | -       | Ingress config          |
| `env`                      | []EnvVar                    | No       | -       | Environment variables   |
| `envFrom`                  | []EnvFromSource             | No       | -       | Env from sources        |
| `securityContext`          | PodSecurityContext          | No       | -       | Pod security            |
| `containerSecurityContext` | SecurityContext             | No       | -       | Container security      |

### WorkerSpec

Includes all fields from MasterSpec, plus:

| Field                 | Type                                | Required | Default | Description       |
| --------------------- | ----------------------------------- | -------- | ------- | ----------------- |
| `replicas`            | int32                               | No       | `2`     | Number of workers |
| `podDisruptionBudget` | [PDBSpec](#pdbspec)                 | No       | -       | PDB config        |
| `overrides`           | [][WorkerOverride](#workeroverride) | No       | -       | Per-pod overrides |

### WorkerOverride

| Field         | Type   | Required | Default | Description                  |
| ------------- | ------ | -------- | ------- | ---------------------------- |
| `index`       | int32  | **Yes**  | -       | Worker index (0-based)       |
| `extraConfig` | string | No       | -       | Extra config for this worker |
| `description` | string | No       | -       | Description                  |

### IndexerSpec

| Field                      | Type                                          | Required | Default            | Description                                                        |
| -------------------------- | --------------------------------------------- | -------- | ------------------ | ------------------------------------------------------------------ |
| `replicas`                 | int32                                         | No       | `3`                | Number of replicas (simple mode)                                   |
| `nodePools`                | [][IndexerNodePoolSpec](#indexernodepoolspec) | No       | -                  | NodePools for advanced topology (mutually exclusive with replicas) |
| `storageSize`              | string                                        | No       | `50Gi`             | Storage size                                                       |
| `clusterName`              | string                                        | No       | `wazuh`            | Cluster name                                                       |
| `javaOpts`                 | string                                        | No       | `-Xms1g -Xmx1g...` | Java options                                                       |
| `image`                    | [ImageSpec](#imagespec)                       | No       | -                  | Image override                                                     |
| `resources`                | ResourceRequirements                          | No       | -                  | Resources                                                          |
| `credentials`              | [CredentialsSecretRef](#credentialssecretref) | No       | -                  | Admin credentials                                                  |
| `service`                  | [ServiceSpec](#servicespec)                   | No       | -                  | Service config                                                     |
| `nodeSelector`             | map[string]string                             | No       | -                  | Node selector                                                      |
| `tolerations`              | []Toleration                                  | No       | -                  | Tolerations                                                        |
| `affinity`                 | Affinity                                      | No       | -                  | Affinity rules                                                     |
| `podDisruptionBudget`      | [PDBSpec](#pdbspec)                           | No       | -                  | PDB config                                                         |
| `annotations`              | map[string]string                             | No       | -                  | StatefulSet annotations                                            |
| `podAnnotations`           | map[string]string                             | No       | -                  | Pod annotations                                                    |
| `ingress`                  | [IngressSpec](#ingressspec)                   | No       | -                  | Ingress config                                                     |
| `updateStrategy`           | string                                        | No       | `RollingUpdate`    | Update strategy                                                    |
| `initContainers`           | []Container                                   | No       | -                  | Init containers                                                    |
| `env`                      | []EnvVar                                      | No       | -                  | Environment variables                                              |
| `envFrom`                  | []EnvFromSource                               | No       | -                  | Env from sources                                                   |
| `securityContext`          | PodSecurityContext                            | No       | -                  | Pod security                                                       |
| `containerSecurityContext` | SecurityContext                               | No       | -                  | Container security                                                 |

> **Note**: `replicas` and `nodePools` are mutually exclusive. Use `replicas` for simple mode (all nodes have all roles) or `nodePools` for advanced mode (dedicated node roles). See [Advanced Indexer Topology](features/advanced-indexer-topology.md) for details.

### IndexerNodePoolSpec

Configuration for a nodePool in advanced indexer topology mode. Each nodePool becomes a separate StatefulSet with its own configuration.

| Field            | Type                 | Required | Default | Description                                    |
| ---------------- | -------------------- | -------- | ------- | ---------------------------------------------- |
| `name`           | string               | **Yes**  | -       | Unique name for the nodePool (DNS-compatible)  |
| `replicas`       | int32                | **Yes**  | -       | Number of replicas in this pool                |
| `roles`          | []IndexerNodeRole    | **Yes**  | -       | OpenSearch node roles                          |
| `attributes`     | map[string]string    | No       | -       | Node attributes for shard allocation awareness |
| `storageSize`    | string               | No       | `50Gi`  | Storage size for this pool                     |
| `storageClass`   | \*string             | No       | -       | StorageClass for this pool                     |
| `javaOpts`       | string               | No       | -       | Java options for this pool                     |
| `resources`      | ResourceRequirements | No       | -       | Resource requests/limits                       |
| `nodeSelector`   | map[string]string    | No       | -       | Kubernetes node selector                       |
| `tolerations`    | []Toleration         | No       | -       | Kubernetes tolerations                         |
| `affinity`       | \*Affinity           | No       | -       | Kubernetes affinity rules                      |
| `annotations`    | map[string]string    | No       | -       | StatefulSet annotations                        |
| `podAnnotations` | map[string]string    | No       | -       | Pod annotations                                |

### IndexerNodeRole

Valid values for OpenSearch node roles:

| Role                    | Description                                           |
| ----------------------- | ----------------------------------------------------- |
| `cluster_manager`       | Manages cluster state and metadata (minimum 3 needed) |
| `data`                  | Stores data and executes search/indexing              |
| `ingest`                | Pre-processes documents before indexing               |
| `search`                | Dedicated search nodes                                |
| `ml`                    | Machine learning workloads                            |
| `remote_cluster_client` | Cross-cluster search support                          |
| `coordinating_only`     | Routes requests, aggregates results (no data)         |

### DashboardSpec

| Field                      | Type                        | Required | Default | Description            |
| -------------------------- | --------------------------- | -------- | ------- | ---------------------- |
| `replicas`                 | int32                       | No       | `2`     | Number of replicas     |
| `enableSSL`                | bool                        | No       | `false` | Enable SSL             |
| `image`                    | [ImageSpec](#imagespec)     | No       | -       | Image override         |
| `resources`                | ResourceRequirements        | No       | -       | Resources              |
| `wazuhPlugin`              | object                      | No       | -       | Wazuh plugin config    |
| `service`                  | [ServiceSpec](#servicespec) | No       | -       | Service config         |
| `nodeSelector`             | map[string]string           | No       | -       | Node selector          |
| `tolerations`              | []Toleration                | No       | -       | Tolerations            |
| `affinity`                 | Affinity                    | No       | -       | Affinity rules         |
| `podDisruptionBudget`      | [PDBSpec](#pdbspec)         | No       | -       | PDB config             |
| `annotations`              | map[string]string           | No       | -       | Deployment annotations |
| `podAnnotations`           | map[string]string           | No       | -       | Pod annotations        |
| `ingress`                  | [IngressSpec](#ingressspec) | No       | -       | Ingress config         |
| `env`                      | []EnvVar                    | No       | -       | Environment variables  |
| `envFrom`                  | []EnvFromSource             | No       | -       | Env from sources       |
| `securityContext`          | PodSecurityContext          | No       | -       | Pod security           |
| `containerSecurityContext` | SecurityContext             | No       | -       | Container security     |

### Common Types

#### ImageSpec

| Field        | Type   | Required | Default        | Description      |
| ------------ | ------ | -------- | -------------- | ---------------- |
| `repository` | string | No       | -              | Image repository |
| `tag`        | string | No       | -              | Image tag        |
| `pullPolicy` | string | No       | `IfNotPresent` | Pull policy      |

#### ServiceSpec

| Field            | Type              | Required | Default     | Description  |
| ---------------- | ----------------- | -------- | ----------- | ------------ |
| `type`           | string            | No       | `ClusterIP` | Service type |
| `annotations`    | map[string]string | No       | -           | Annotations  |
| `loadBalancerIP` | string            | No       | -           | LB IP        |
| `nodePort`       | int32             | No       | -           | Node port    |
| `ports`          | []ServicePortSpec | No       | -           | Custom ports |

#### IngressSpec

| Field              | Type              | Required | Default | Description    |
| ------------------ | ----------------- | -------- | ------- | -------------- |
| `enabled`          | bool              | No       | `false` | Enable ingress |
| `ingressClassName` | string            | No       | -       | Ingress class  |
| `annotations`      | map[string]string | No       | -       | Annotations    |
| `hosts`            | []IngressHost     | No       | -       | Host rules     |
| `tls`              | []IngressTLS      | No       | -       | TLS config     |

#### PDBSpec

| Field            | Type  | Required | Default | Description     |
| ---------------- | ----- | -------- | ------- | --------------- |
| `enabled`        | bool  | No       | `false` | Enable PDB      |
| `maxUnavailable` | int32 | No       | -       | Max unavailable |
| `minAvailable`   | int32 | No       | -       | Min available   |

#### CredentialsSecretRef

| Field         | Type   | Required | Default    | Description  |
| ------------- | ------ | -------- | ---------- | ------------ |
| `secretName`  | string | No       | -          | Secret name  |
| `usernameKey` | string | No       | `username` | Username key |
| `passwordKey` | string | No       | `password` | Password key |

---

## OpenSearch Security CRDs

### OpenSearchUser

Manages OpenSearch internal users.

**Short Name:** `osuser`

| Field             | Type                  | Required | Default | Description           |
| ----------------- | --------------------- | -------- | ------- | --------------------- |
| `clusterRef`      | WazuhClusterReference | **Yes**  | -       | Cluster reference     |
| `defaultAdmin`    | bool                  | No       | `false` | Mark as default admin |
| `passwordSecret`  | CredentialsSecretRef  | No       | -       | Password secret       |
| `hash`            | string                | No       | -       | Pre-computed hash     |
| `backendRoles`    | []string              | No       | -       | Backend roles         |
| `openSearchRoles` | []string              | No       | -       | OpenSearch roles      |
| `attributes`      | map[string]string     | No       | -       | Custom attributes     |
| `description`     | string                | No       | -       | Description           |

### OpenSearchRole

Manages OpenSearch security roles.

**Short Name:** `osrole`

| Field                | Type                  | Required | Default | Description         |
| -------------------- | --------------------- | -------- | ------- | ------------------- |
| `clusterRef`         | WazuhClusterReference | **Yes**  | -       | Cluster reference   |
| `clusterPermissions` | []string              | No       | -       | Cluster permissions |
| `indexPermissions`   | []IndexPermission     | No       | -       | Index permissions   |
| `tenantPermissions`  | []TenantPermission    | No       | -       | Tenant permissions  |
| `description`        | string                | No       | -       | Description         |

#### IndexPermission

| Field            | Type     | Required | Default | Description             |
| ---------------- | -------- | -------- | ------- | ----------------------- |
| `indexPatterns`  | []string | **Yes**  | -       | Index patterns          |
| `allowedActions` | []string | **Yes**  | -       | Allowed actions         |
| `dls`            | string   | No       | -       | Document-level security |
| `fls`            | []string | No       | -       | Field-level security    |
| `maskedFields`   | []string | No       | -       | Masked fields           |

### OpenSearchRoleMapping

Maps users/roles to OpenSearch roles.

**Short Name:** `osrmap`

| Field             | Type                  | Required | Default | Description       |
| ----------------- | --------------------- | -------- | ------- | ----------------- |
| `clusterRef`      | WazuhClusterReference | **Yes**  | -       | Cluster reference |
| `users`           | []string              | No       | -       | Internal users    |
| `backendRoles`    | []string              | No       | -       | Backend roles     |
| `hosts`           | []string              | No       | -       | Host patterns     |
| `andBackendRoles` | []string              | No       | -       | AND backend roles |
| `description`     | string                | No       | -       | Description       |

### OpenSearchTenant

Manages multi-tenancy for dashboards.

**Short Name:** `ostenant`

| Field         | Type                  | Required | Default | Description       |
| ------------- | --------------------- | -------- | ------- | ----------------- |
| `clusterRef`  | WazuhClusterReference | **Yes**  | -       | Cluster reference |
| `description` | string                | No       | -       | Description       |

### OpenSearchActionGroup

Creates custom action groups.

**Short Name:** `osag`

| Field            | Type                  | Required | Default | Description              |
| ---------------- | --------------------- | -------- | ------- | ------------------------ |
| `clusterRef`     | WazuhClusterReference | **Yes**  | -       | Cluster reference        |
| `allowedActions` | []string              | **Yes**  | -       | Actions/groups           |
| `type`           | string                | No       | -       | Type (cluster/index/all) |
| `description`    | string                | No       | -       | Description              |

### OpenSearchAuthConfig

Manages authentication configuration (Basic, OIDC, SAML, LDAP).

**Short Names:** `osauthconfig`, `osauth`

| Field        | Type                  | Required | Default | Description       |
| ------------ | --------------------- | -------- | ------- | ----------------- |
| `clusterRef` | WazuhClusterReference | **Yes**  | -       | Cluster reference |
| `basicAuth`  | BasicAuthSpec         | No       | -       | Basic auth config |
| `oidc`       | OIDCAuthSpec          | No       | -       | OIDC config       |
| `saml`       | SAMLAuthSpec          | No       | -       | SAML config       |
| `ldap`       | LDAPAuthSpec          | No       | -       | LDAP config       |

See sample files for detailed authentication configurations.

---

## OpenSearch Index Management CRDs

### OpenSearchIndex

Manages OpenSearch indices.

**Short Name:** `osidx`

| Field        | Type                   | Required | Default | Description       |
| ------------ | ---------------------- | -------- | ------- | ----------------- |
| `clusterRef` | WazuhClusterReference  | **Yes**  | -       | Cluster reference |
| `settings`   | IndexSettings          | No       | -       | Index settings    |
| `mappings`   | IndexMappings          | No       | -       | Field mappings    |
| `aliases`    | []OpenSearchIndexAlias | No       | -       | Index aliases     |

### OpenSearchIndexTemplate

Manages index templates.

**Short Name:** `osidxt`

| Field           | Type                  | Required | Default | Description         |
| --------------- | --------------------- | -------- | ------- | ------------------- |
| `clusterRef`    | WazuhClusterReference | **Yes**  | -       | Cluster reference   |
| `indexPatterns` | []string              | **Yes**  | -       | Index patterns      |
| `template`      | IndexTemplate         | No       | -       | Template definition |
| `composedOf`    | []string              | No       | -       | Component templates |
| `priority`      | int32                 | No       | -       | Priority            |
| `version`       | int64                 | No       | -       | Version             |
| `dataStream`    | DataStreamConfig      | No       | -       | Data stream config  |

### OpenSearchComponentTemplate

Manages reusable template components.

**Short Name:** `osctpl`

| Field        | Type                  | Required | Default | Description         |
| ------------ | --------------------- | -------- | ------- | ------------------- |
| `clusterRef` | WazuhClusterReference | **Yes**  | -       | Cluster reference   |
| `template`   | ComponentTemplate     | **Yes**  | -       | Template definition |
| `version`    | int64                 | No       | -       | Version             |

### OpenSearchISMPolicy

Manages Index State Management policies.

**Short Name:** `osism`

| Field          | Type                  | Required | Default | Description       |
| -------------- | --------------------- | -------- | ------- | ----------------- |
| `clusterRef`   | WazuhClusterReference | **Yes**  | -       | Cluster reference |
| `description`  | string                | No       | -       | Description       |
| `defaultState` | string                | **Yes**  | -       | Default state     |
| `states`       | []ISMState            | **Yes**  | -       | Policy states     |
| `ismTemplate`  | []ISMTemplateConfig   | No       | -       | Auto-assignment   |

### OpenSearchSnapshotPolicy

Manages snapshot/backup policies.

**Short Name:** `ossnap`

| Field            | Type                  | Required | Default | Description       |
| ---------------- | --------------------- | -------- | ------- | ----------------- |
| `clusterRef`     | WazuhClusterReference | **Yes**  | -       | Cluster reference |
| `description`    | string                | No       | -       | Description       |
| `repository`     | SnapshotRepository    | **Yes**  | -       | Repository config |
| `snapshotConfig` | SnapshotConfig        | No       | -       | What to snapshot  |
| `creation`       | SnapshotCreation      | **Yes**  | -       | Creation schedule |
| `deletion`       | SnapshotDeletion      | No       | -       | Retention policy  |
| `notification`   | SnapshotNotification  | No       | -       | Notifications     |

---

## OpenSearch Backup CRDs

### OpenSearchSnapshotRepository

Manages OpenSearch snapshot repositories for storing backups.

**Short Name:** `osrepo`

| Field        | Type                       | Required | Default | Description                          |
| ------------ | -------------------------- | -------- | ------- | ------------------------------------ |
| `clusterRef` | WazuhClusterReference      | **Yes**  | -       | Cluster reference                    |
| `type`       | string                     | **Yes**  | -       | Repository type: `s3`, `azure`, `fs` |
| `settings`   | SnapshotRepositorySettings | **Yes**  | -       | Repository settings                  |
| `verify`     | bool                       | No       | `true`  | Verify repository after creation     |

#### SnapshotRepositorySettings (S3)

| Field                  | Type                       | Required | Default | Description                      |
| ---------------------- | -------------------------- | -------- | ------- | -------------------------------- |
| `bucket`               | string                     | **Yes**  | -       | S3 bucket name                   |
| `basePath`             | string                     | No       | -       | Path prefix within bucket        |
| `region`               | string                     | No       | -       | AWS region                       |
| `endpoint`             | string                     | No       | -       | Custom endpoint (for MinIO)      |
| `pathStyleAccess`      | bool                       | No       | `false` | Use path-style access (MinIO)    |
| `compress`             | bool                       | No       | `true`  | Compress snapshot files          |
| `serverSideEncryption` | bool                       | No       | `false` | Enable S3 server-side encryption |
| `storageClass`         | string                     | No       | -       | S3 storage class                 |
| `credentialsSecret`    | CredentialsSecretReference | **Yes**  | -       | Secret containing S3 credentials |

### OpenSearchSnapshot

Triggers manual snapshots on-demand.

**Short Name:** `ossnapshot`

| Field                | Type                  | Required | Default | Description                  |
| -------------------- | --------------------- | -------- | ------- | ---------------------------- |
| `clusterRef`         | WazuhClusterReference | **Yes**  | -       | Cluster reference            |
| `repository`         | string                | **Yes**  | -       | Repository name              |
| `indices`            | []string              | No       | all     | Index patterns to snapshot   |
| `ignoreUnavailable`  | bool                  | No       | `true`  | Skip missing indices         |
| `includeGlobalState` | bool                  | No       | `false` | Include cluster state        |
| `partial`            | bool                  | No       | `false` | Allow partial snapshots      |
| `waitForCompletion`  | bool                  | No       | `true`  | Wait for snapshot completion |

**Status Fields:**

| Field          | Type   | Description                                        |
| -------------- | ------ | -------------------------------------------------- |
| `snapshotName` | string | Generated snapshot name (e.g., `name-timestamp`)   |
| `state`        | string | Snapshot state: `IN_PROGRESS`, `SUCCESS`, `FAILED` |

### OpenSearchRestore

Restores indices from a snapshot.

**Short Name:** `osrest`

| Field                | Type                  | Required | Default | Description                        |
| -------------------- | --------------------- | -------- | ------- | ---------------------------------- |
| `clusterRef`         | WazuhClusterReference | **Yes**  | -       | Cluster reference                  |
| `repository`         | string                | **Yes**  | -       | Repository name                    |
| `snapshot`           | string                | **Yes**  | -       | Snapshot name to restore           |
| `indices`            | []string              | No       | all     | Index patterns to restore          |
| `ignoreUnavailable`  | bool                  | No       | `true`  | Skip missing indices               |
| `includeGlobalState` | bool                  | No       | `false` | Include cluster state              |
| `renamePattern`      | string                | No       | -       | Regex pattern for renaming indices |
| `renameReplacement`  | string                | No       | -       | Replacement string for rename      |
| `indexSettings`      | map[string]string     | No       | -       | Override settings during restore   |
| `waitForCompletion`  | bool                  | No       | `true`  | Wait for restore completion        |

**Example: Rename during restore:**

```yaml
renamePattern: "(.+)"
renameReplacement: "restored-$1"
# wazuh-alerts-2025.01 → restored-wazuh-alerts-2025.01
```

---

## Wazuh Configuration CRDs

### WazuhRule

Manages custom Wazuh detection rules.

**Short Name:** `wrule`

| Field         | Type                  | Required | Default | Description                 |
| ------------- | --------------------- | -------- | ------- | --------------------------- |
| `clusterRef`  | WazuhClusterReference | **Yes**  | -       | Cluster reference           |
| `ruleName`    | string                | **Yes**  | -       | Rule name                   |
| `rules`       | string                | **Yes**  | -       | Rule XML content            |
| `description` | string                | No       | -       | Description                 |
| `targetNodes` | string                | No       | `all`   | Target (master/workers/all) |
| `ruleID`      | int32                 | No       | -       | Starting rule ID            |
| `level`       | int32                 | No       | -       | Rule level (0-15)           |
| `groups`      | []string              | No       | -       | Rule groups                 |
| `overwrite`   | bool                  | No       | `false` | Overwrite existing          |
| `priority`    | int32                 | No       | `500`   | Application priority        |
| `ifSID`       | []int32               | No       | -       | Parent rule IDs             |
| `ifGroup`     | []string              | No       | -       | Parent rule groups          |

### WazuhDecoder

Manages custom log decoders.

**Short Name:** `wdecoder`

| Field           | Type                  | Required | Default | Description                 |
| --------------- | --------------------- | -------- | ------- | --------------------------- |
| `clusterRef`    | WazuhClusterReference | **Yes**  | -       | Cluster reference           |
| `decoderName`   | string                | **Yes**  | -       | Decoder name                |
| `decoders`      | string                | **Yes**  | -       | Decoder XML content         |
| `description`   | string                | No       | -       | Description                 |
| `targetNodes`   | string                | No       | `all`   | Target (master/workers/all) |
| `priority`      | int32                 | No       | `500`   | Application priority        |
| `overwrite`     | bool                  | No       | `false` | Overwrite existing          |
| `parentDecoder` | string                | No       | -       | Parent decoder name         |

---

### WazuhFilebeat

Manages Filebeat configuration for shipping Wazuh alerts and archives to OpenSearch.

**Short Name:** `wfb`

| Field        | Type                   | Required | Default | Description                     |
| ------------ | ---------------------- | -------- | ------- | ------------------------------- |
| `clusterRef` | WazuhClusterReference  | **Yes**  | -       | Cluster reference               |
| `alerts`     | FilebeatAlertsConfig   | No       | -       | Alerts module configuration     |
| `archives`   | FilebeatArchivesConfig | No       | -       | Archives module configuration   |
| `template`   | FilebeatTemplateConfig | No       | -       | Index template configuration    |
| `pipeline`   | FilebeatPipelineConfig | No       | -       | Ingest pipeline configuration   |
| `logging`    | FilebeatLoggingConfig  | No       | -       | Filebeat logging settings       |
| `ssl`        | FilebeatSSLConfig      | No       | -       | SSL/TLS settings                |
| `output`     | FilebeatOutputConfig   | No       | -       | OpenSearch output configuration |

#### FilebeatAlertsConfig

| Field     | Type | Default | Description                    |
| --------- | ---- | ------- | ------------------------------ |
| `enabled` | bool | `true`  | Enable/disable alerts shipping |

#### FilebeatArchivesConfig

| Field     | Type | Default | Description                      |
| --------- | ---- | ------- | -------------------------------- |
| `enabled` | bool | `false` | Enable/disable archives shipping |

#### FilebeatTemplateConfig

| Field                | Type                 | Default | Description                               |
| -------------------- | -------------------- | ------- | ----------------------------------------- |
| `shards`             | int32                | `3`     | Number of primary shards (1-100)          |
| `replicas`           | int32                | `0`     | Number of replica shards (0-10)           |
| `refreshInterval`    | string               | `5s`    | Index refresh interval                    |
| `fieldLimit`         | int32                | `10000` | Maximum fields per document (1000-100000) |
| `customTemplateRef`  | ConfigMapKeySelector | -       | Custom template from ConfigMap            |
| `additionalMappings` | object               | -       | Custom field mappings (raw JSON)          |

#### FilebeatPipelineConfig

| Field                    | Type                 | Default            | Description                        |
| ------------------------ | -------------------- | ------------------ | ---------------------------------- |
| `geoipEnabled`           | bool                 | `true`             | Enable GeoIP enrichment processors |
| `indexPrefix`            | string               | `wazuh-alerts-4.x` | Index name prefix                  |
| `additionalRemoveFields` | []string             | -                  | Additional fields to remove        |
| `timestampFormat`        | string               | `ISO8601`          | Timestamp parsing format           |
| `customPipelineRef`      | ConfigMapKeySelector | -                  | Custom pipeline from ConfigMap     |

#### FilebeatLoggingConfig

| Field       | Type   | Default | Description                                    |
| ----------- | ------ | ------- | ---------------------------------------------- |
| `level`     | string | `info`  | Log level: `debug`, `info`, `warning`, `error` |
| `toFiles`   | bool   | `true`  | Enable logging to files                        |
| `keepFiles` | int32  | `7`     | Number of log files to retain (1-100)          |

#### FilebeatSSLConfig

| Field                 | Type         | Default | Description                      |
| --------------------- | ------------ | ------- | -------------------------------- |
| `verificationMode`    | string       | `full`  | `full`, `certificate`, or `none` |
| `caCertSecretRef`     | SecretKeyRef | -       | CA certificate secret reference  |
| `clientCertSecretRef` | SecretKeyRef | -       | Client certificate secret        |
| `clientKeySecretRef`  | SecretKeyRef | -       | Client key secret                |

#### FilebeatOutputConfig

| Field                  | Type                 | Default | Description                  |
| ---------------------- | -------------------- | ------- | ---------------------------- |
| `hosts`                | []string             | -       | OpenSearch host list         |
| `credentialsSecretRef` | CredentialsSecretRef | -       | Credentials secret reference |
| `protocol`             | string               | `https` | `http` or `https`            |
| `port`                 | int32                | `9200`  | OpenSearch port (1-65535)    |

See [Filebeat Configuration Guide](./features/filebeat-configuration.md) for detailed usage and examples.

---

## Wazuh Backup CRDs

### WazuhBackup

Manages scheduled or one-shot backups of Wazuh Manager data to S3/MinIO.

**Short Name:** `wbak`

| Field           | Type                  | Required | Default | Description                              |
| --------------- | --------------------- | -------- | ------- | ---------------------------------------- |
| `clusterRef`    | WazuhClusterReference | **Yes**  | -       | Cluster reference                        |
| `components`    | BackupComponents      | **Yes**  | -       | Components to backup                     |
| `schedule`      | string                | No       | -       | Cron schedule (omit for one-shot backup) |
| `retention`     | RetentionPolicy       | No       | -       | Backup retention policy                  |
| `storage`       | BackupStorage         | **Yes**  | -       | S3/MinIO storage configuration           |
| `suspend`       | bool                  | No       | `false` | Suspend scheduled backups                |
| `backupTimeout` | string                | No       | `30m`   | Maximum backup duration                  |
| `image`         | ImageSpec             | No       | -       | Custom backup image                      |
| `resources`     | ResourceRequirements  | No       | -       | Container resources                      |

#### BackupComponents

| Field           | Type     | Default | Description                         |
| --------------- | -------- | ------- | ----------------------------------- |
| `agentKeys`     | bool     | `true`  | Agent registration keys (critical)  |
| `fimDatabase`   | bool     | `true`  | File Integrity Monitoring database  |
| `agentDatabase` | bool     | `true`  | Agent state databases               |
| `integrations`  | bool     | `false` | Integration scripts                 |
| `alertLogs`     | bool     | `false` | Alert log files (can be large)      |
| `customPaths`   | []string | -       | Additional paths within /var/ossec/ |

#### RetentionPolicy

| Field        | Type   | Description                             |
| ------------ | ------ | --------------------------------------- |
| `maxBackups` | int32  | Maximum number of backups to keep       |
| `maxAge`     | string | Delete backups older than (e.g., "30d") |

#### BackupStorage

| Field               | Type                       | Required | Default | Description                      |
| ------------------- | -------------------------- | -------- | ------- | -------------------------------- |
| `type`              | string                     | **Yes**  | -       | Storage type: `s3`               |
| `bucket`            | string                     | **Yes**  | -       | S3/MinIO bucket name             |
| `prefix`            | string                     | No       | -       | Path prefix (supports templates) |
| `region`            | string                     | No       | -       | AWS region                       |
| `endpoint`          | string                     | No       | -       | Custom endpoint (for MinIO)      |
| `forcePathStyle`    | bool                       | No       | `false` | Use path-style access (MinIO)    |
| `credentialsSecret` | CredentialsSecretReference | **Yes**  | -       | Secret containing credentials    |

**Status Fields:**

| Field           | Type   | Description                         |
| --------------- | ------ | ----------------------------------- |
| `lastBackup`    | \*Time | Timestamp of last successful backup |
| `lastBackupKey` | string | S3 key of last backup archive       |
| `backupCount`   | int32  | Total number of backups             |
| `jobName`       | string | Name of current/last Job            |

### WazuhRestore

Restores Wazuh Manager data from an S3/MinIO backup archive.

**Short Name:** `wrest`

| Field                 | Type                  | Required | Default | Description                   |
| --------------------- | --------------------- | -------- | ------- | ----------------------------- |
| `clusterRef`          | WazuhClusterReference | **Yes**  | -       | Cluster reference             |
| `source`              | RestoreSource         | **Yes**  | -       | Source configuration          |
| `components`          | RestoreComponents     | No       | all     | Components to restore         |
| `preRestoreBackup`    | bool                  | No       | `true`  | Create backup before restore  |
| `stopManager`         | bool                  | No       | `true`  | Stop manager during restore   |
| `restartAfterRestore` | bool                  | No       | `true`  | Restart manager after restore |
| `restoreTimeout`      | string                | No       | `30m`   | Maximum restore duration      |
| `resources`           | ResourceRequirements  | No       | -       | Container resources           |

#### RestoreSource

Either `s3` or `wazuhBackupRef` must be specified:

| Field            | Type            | Description                         |
| ---------------- | --------------- | ----------------------------------- |
| `s3`             | S3RestoreSource | Restore from S3/MinIO directly      |
| `wazuhBackupRef` | WazuhBackupRef  | Reference to a WazuhBackup resource |

#### S3RestoreSource

| Field               | Type                       | Required | Description                   |
| ------------------- | -------------------------- | -------- | ----------------------------- |
| `bucket`            | string                     | **Yes**  | S3/MinIO bucket name          |
| `key`               | string                     | **Yes**  | Full path to backup archive   |
| `region`            | string                     | No       | AWS region                    |
| `endpoint`          | string                     | No       | Custom endpoint (for MinIO)   |
| `forcePathStyle`    | bool                       | No       | Use path-style access (MinIO) |
| `credentialsSecret` | CredentialsSecretReference | **Yes**  | Secret containing credentials |

#### WazuhBackupRef

| Field             | Type   | Required | Description                  |
| ----------------- | ------ | -------- | ---------------------------- |
| `name`            | string | **Yes**  | Name of WazuhBackup resource |
| `backupTimestamp` | string | No       | Specific backup timestamp    |

**Status Fields:**

| Field          | Type              | Description                     |
| -------------- | ----------------- | ------------------------------- |
| `startTime`    | \*Time            | When restore started            |
| `endTime`      | \*Time            | When restore completed          |
| `duration`     | string            | Total restore duration          |
| `sourceBackup` | RestoreSourceInfo | Information about source backup |
| `jobName`      | string            | Name of restore Job             |

See [Backup & Restore Guide](./features/backup-restore.md) for detailed usage and examples.

---

## Common Status Fields

All CRDs include these status fields:

| Field                | Type        | Description                          |
| -------------------- | ----------- | ------------------------------------ |
| `phase`              | string      | Current phase (Pending/Ready/Failed) |
| `message`            | string      | Additional information               |
| `conditions`         | []Condition | Standard conditions                  |
| `lastSyncTime`       | Time        | Last sync timestamp                  |
| `observedGeneration` | int64       | Last observed generation             |
| `lastAppliedHash`    | string      | Spec hash for drift detection        |
| `driftDetected`      | bool        | Manual modification detected         |
| `lastDriftTime`      | Time        | When drift was detected              |
| `conflictsWith`      | string      | Conflicting CRD name                 |
| `ownershipClaimed`   | bool        | CRD owns the resource                |

### WazuhCluster Additional Status Fields

The WazuhCluster CRD includes additional status fields for volume expansion tracking:

| Field             | Type                                            | Description                        |
| ----------------- | ----------------------------------------------- | ---------------------------------- |
| `volumeExpansion` | [VolumeExpansionStatus](#volumeexpansionstatus) | Storage expansion progress tracker |

#### VolumeExpansionStatus

Tracks storage expansion progress for all cluster components:

| Field                     | Type                                                  | Description                      |
| ------------------------- | ----------------------------------------------------- | -------------------------------- |
| `indexerExpansion`        | [ComponentExpansionStatus](#componentexpansionstatus) | Indexer PVC expansion status     |
| `managerMasterExpansion`  | [ComponentExpansionStatus](#componentexpansionstatus) | Manager master expansion status  |
| `managerWorkersExpansion` | [ComponentExpansionStatus](#componentexpansionstatus) | Manager workers expansion status |

#### ComponentExpansionStatus

Tracks expansion status for a specific component:

| Field                | Type     | Description                                             |
| -------------------- | -------- | ------------------------------------------------------- |
| `phase`              | string   | Expansion phase: Pending, InProgress, Completed, Failed |
| `requestedSize`      | string   | Target storage size (e.g., "100Gi")                     |
| `currentSize`        | string   | Current storage size                                    |
| `message`            | string   | Human-readable status message                           |
| `lastTransitionTime` | Time     | When the phase last changed                             |
| `pvcsExpanded`       | []string | List of PVCs that have completed expansion              |
| `pvcsPending`        | []string | List of PVCs still pending expansion                    |

**Example status:**

```yaml
status:
  volumeExpansion:
    indexerExpansion:
      phase: InProgress
      requestedSize: "100Gi"
      currentSize: "50Gi"
      message: "Expanding PVCs: 2 completed, 1 pending"
      pvcsExpanded:
        - data-wazuh-indexer-0
        - data-wazuh-indexer-1
      pvcsPending:
        - data-wazuh-indexer-2
      lastTransitionTime: "2025-01-15T10:30:00Z"
    managerMasterExpansion:
      phase: Completed
      requestedSize: "40Gi"
      currentSize: "40Gi"
      message: "All 1 PVC(s) expanded successfully to 40Gi"
      pvcsExpanded:
        - data-wazuh-manager-master-0
      lastTransitionTime: "2025-01-15T10:28:00Z"
```

See [Volume Expansion Guide](./features/volume-expansion.md) for detailed usage instructions.

---

## Sample Files

See `config/samples/` for example manifests:

### WazuhCluster Examples

- `wazuh_v1alpha1_wazuhcluster_minimal.yaml` - Minimal development setup
- `wazuh_v1alpha1_wazuhcluster_production.yaml` - Production configuration
- `wazuh_v1alpha1_wazuhcluster_complete.yaml` - All options documented
- `wazuh_v1alpha1_wazuhcluster_monitoring.yaml` - Prometheus monitoring
- `wazuh_v1alpha1_wazuhcluster_tls.yaml` - TLS configurations
- `wazuh_v1alpha1_wazuhcluster_cloud_workers.yaml` - Cloud log collection

### Wazuh Configuration

- `wazuh_v1alpha1_rule.yaml` - Custom rule example
- `wazuh_v1alpha1_decoder.yaml` - Custom decoder example

### OpenSearch Security & Index Management

- `opensearch_v1alpha1_*.yaml` - OpenSearch resource examples

### Backup & Restore

- `opensearch_v1alpha1_opensearchsnapshotrepository_s3.yaml` - AWS S3 repository
- `opensearch_v1alpha1_opensearchsnapshotrepository_minio.yaml` - MinIO repository
- `opensearch_v1alpha1_opensearchsnapshot_manual.yaml` - Manual snapshot trigger
- `opensearch_v1alpha1_opensearchrestore.yaml` - Restore from snapshot
- `wazuh_v1alpha1_wazuhbackup_scheduled.yaml` - Scheduled Wazuh backups
- `wazuh_v1alpha1_wazuhbackup_oneshot.yaml` - One-shot Wazuh backup
- `wazuh_v1alpha1_wazuhrestore.yaml` - Wazuh restore examples
