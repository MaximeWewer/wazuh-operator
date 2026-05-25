# Wazuh Operator CRD Reference

This document provides a complete reference for all Custom Resource Definitions (CRDs) supported by the Wazuh Operator.

## Cluster references

Resource CRDs reference the WazuhCluster they apply to via either
`spec.clusterRefs` (list, multi-cluster) or `spec.clusterRef` (single, one-shot
operations). Both forms require `name` **and** `namespace`; cross-namespace
references are supported.

| Form | CRDs |
|------|------|
| `clusterRefs: [{name, namespace}]` (MinItems=1) | WazuhAgentGroup, WazuhRule, WazuhDecoder, WazuhFilebeat, OpenSearchUser, OpenSearchRole, OpenSearchRoleMapping, OpenSearchTenant, OpenSearchActionGroup, OpenSearchAuthConfig, OpenSearchISMPolicy, OpenSearchIndexTemplate, OpenSearchComponentTemplate, OpenSearchIndex, OpenSearchSnapshotPolicy, OpenSearchSnapshotRepository, OpenSearchSnapshot, OpenSearchRestore |
| `clusterRef: {name, namespace}` | WazuhBackup, WazuhRestore, WazuhCertificate |

Multi-cluster CRDs report per-target-cluster reconciliation state via
`status.clusterStatuses[]` (each entry: `name`, `namespace`, `phase`,
`lastSyncTime`, `lastAppliedHash`, `message`). The top-level `status.phase`
is the aggregate (`Failed` if any failed, `Pending` if any pending,
`Ready` only when every target is ready).

For OpenSearchSnapshot and OpenSearchRestore the operator currently runs the
one-shot operation against the first entry only; submit a separate CR per
additional cluster when targeting more than one.

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
  - [WazuhAgentGroup](#wazuhagentgroup)
  - [WazuhDecoder](#wazuhdecoder)
  - [WazuhIntegration](#wazuhintegration)
  - [WazuhCertificate](#wazuhcertificate)
  - [WazuhFilebeat](#wazuhfilebeat)
- [Wazuh Backup CRDs](#wazuh-backup-crds)
  - [WazuhBackup](#wazuhbackup)
  - [WazuhRestore](#wazuhrestore)

---

## WazuhCluster

The main CRD for deploying a complete Wazuh stack (Manager, Indexer, Dashboard).

**API Group:** `resources.wazuh.com/v1`
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

> **Note**: Custom certificates (BYO certs) are supported. See [TLS Configuration](features/tls.md#custom-certificates) for details.

### CertificateConfig

| Field                | Type   | Required | Default      | Description                                             |
| -------------------- | ------ | -------- | ------------ | ------------------------------------------------------- |
| `country`            | string | No       | `FR`         | X.509 Country                                           |
| `state`              | string | No       | `Alsace`     | X.509 State                                             |
| `locality`           | string | No       | `Strasbourg` | X.509 Locality                                          |
| `organization`       | string | No       | `Wazuh`      | X.509 Organization                                      |
| `organizationalUnit` | string | No       | `Wazuh`      | X.509 OU                                                |
| `commonName`         | string | No       | `admin`      | X.509 CN                                                |
| `validity`           | string | No       | `365d`       | Node cert validity (e.g., "365d", "24h", "30m")         |
| `renewalThreshold`   | string | No       | `30d`        | Node cert renewal threshold (e.g., "30d", "12h", "30m") |
| `caValidity`         | string | No       | `3650d`      | CA validity (e.g., "3650d" = 10 years)                  |
| `caRenewalThreshold` | string | No       | `60d`        | CA renewal threshold (e.g., "60d", "24h")               |

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
| `enabled`      | bool                 | No       | `false`                                              | Enable exporter                                  |
| `image`        | string               | No       | `ghcr.io/maximewewer/wazuh-prometheus-exporter:latest` | Exporter image                                 |
| `port`         | int32                | No       | `9555`                                               | Metrics port                                     |
| `apiProtocol`  | string               | No       | `https`                                              | API protocol (builds the Wazuh API URL)          |
| `apiVerifySSL` | bool                 | No       | `true`                                               | Verify Wazuh API TLS cert (false skips verify)   |
| `apiCASecretRef` | SecretKeyRef       | No       | cluster common CA                                    | CA bundle to verify the API cert (when apiVerifySSL=true); defaults to the manager certs `ca.crt` |
| `logLevel`     | string               | No       | `info`                                               | Log level (trace/debug/info/warn/error)          |
| `cacheTTL`     | string               | No       | -                                                    | Metrics cache TTL (>= scrape interval), e.g. 30s |
| `startupGrace` | string               | No       | `60s`                                                | Quiet-startup window (warn vs error) for a slow Wazuh API; 0–10m |
| `resources`    | ResourceRequirements | No       | -                                                    | Container resources                              |

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
| `global`               | [OSSECGlobalSpec](#ossecglobalspec)       | No       | -       | Global section              |
| `alerts`               | [OSSECAlertsSpec](#ossecalertsspec)       | No       | -       | Alerts section              |
| `logging`              | [OSSECLoggingSpec](#ossecloggingspec)     | No       | -       | Logging section             |
| `remote`               | [OSSECRemoteSpec](#ossecremotespec)       | No       | -       | Remote section              |
| `auth`                 | [OSSECAuthSpec](#ossecauthspec)           | No       | -       | Auth section                |
| `ruleset`              | [OSSECRulesetSpec](#ossecrulesetspec)     | No       | -       | Ruleset section             |

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
| `disabled`            | bool                                          | No       | `false` | Disable authd    |
| `port`                | int                                           | No       | `1515`  | Port             |
| `useSourceIP`         | bool                                          | No       | `false` | Use source IP    |
| `purge`               | bool                                          | No       | `true`  | Purge old keys   |
| `usePassword`         | bool                                          | No       | `false` | Require password |
| `passwordSecretRef`   | SecretKeyRef                                  | No       | -       | Password secret  |
| `enabledOnMasterOnly` | bool                                          | No       | `true`  | Master only      |
| `force`               | [OSSECAuthForceSpec](#ossecauthforcespec)      | No       | -       | Agent replacement policy |

### OSSECAuthForceSpec

Controls agent replacement when duplicate names or IP addresses are detected. All configured conditions must be satisfied to perform the replacement. If omitted, the `<force>` block is not generated (Wazuh defaults apply).

| Field                     | Type   | Required | Default | Description                                                                 |
| ------------------------- | ------ | -------- | ------- | --------------------------------------------------------------------------- |
| `enabled`                 | bool   | No       | `true`  | Toggle forced insertion on duplicate name/IP                                |
| `disconnectedTime`        | string | No       | `1h`    | Min time agent must be disconnected before replacement (e.g. `0`, `30m`, `1h`, `1d`) |
| `disconnectedTimeEnabled` | bool   | No       | `true`  | Toggle the disconnected time condition                                      |
| `afterRegistrationTime`   | string | No       | `1h`    | Min time since registration before replacement (e.g. `0`, `30m`, `1h`)     |
| `keyMismatch`             | bool   | No       | `true`  | Replace when agent key differs from registered key                          |

### OSSECRulesetSpec

Configures the `<ruleset>` section of `ossec.conf`, which tells Wazuh where to load rules, decoders, and CDB lists from. Default directories include both built-in (`ruleset/`) and custom (`etc/`) paths.

| Field             | Type     | Required | Default                              | Description                                        |
| ----------------- | -------- | -------- | ------------------------------------ | -------------------------------------------------- |
| `ruleDirs`        | []string | No       | `["ruleset/rules", "etc/rules"]`     | Directories to load rules from                     |
| `decoderDirs`     | []string | No       | `["ruleset/decoders", "etc/decoders"]` | Directories to load decoders from                |
| `ruleExcludes`    | []string | No       | `[]`                                 | Rule files to exclude from loading                 |
| `decoderExcludes` | []string | No       | `[]`                                 | Decoder files to exclude from loading              |
| `lists`           | []string | No       | `[]`                                 | CDB list files to load (without `.cdb` extension)  |

### MasterSpec

| Field                      | Type                              | Required | Default | Description             |
| -------------------------- | --------------------------------- | -------- | ------- | ----------------------- |
| `storageSize`              | string                            | No       | `50Gi`  | Storage size            |
| `resources`                | ResourceRequirements              | No       | -       | Resources               |
| `service`                  | [ServiceSpec](#servicespec)       | No       | -       | Service config          |
| `nodeSelector`             | map[string]string                 | No       | -       | Node selector           |
| `tolerations`              | []Toleration                      | No       | -       | Tolerations             |
| `affinity`                 | Affinity                          | No       | -       | Affinity rules          |
| `extraConfig`              | string                            | No       | -       | Extra ossec.conf XML    |
| `localInternalOptions`     | string                            | No       | -       | local_internal_options.conf |
| `extraVolumes`             | []Volume                          | No       | -       | Extra volumes           |
| `extraVolumeMounts`        | []VolumeMount                     | No       | -       | Extra mounts            |
| `extraInitContainers`      | []Container                       | No       | -       | Extra init containers   |
| `extraContainers`          | []Container                       | No       | -       | Extra sidecar containers|
| `podAnnotations`           | map[string]string                 | No       | -       | Pod annotations         |
| `annotations`              | map[string]string                 | No       | -       | StatefulSet annotations |
| `ingress`                  | [IngressSpec](#ingressspec)       | No       | -       | Ingress config          |
| `gatewayAPI`               | [GatewayAPISpec](#gatewayapispec) | No       | -       | Gateway API config      |
| `env`                      | []EnvVar                          | No       | -       | Environment variables   |
| `envFrom`                  | []EnvFromSource                   | No       | -       | Env from sources        |
| `securityContext`          | PodSecurityContext                | No       | -       | Pod security            |
| `containerSecurityContext` | SecurityContext                   | No       | -       | Container security      |
| `serviceAccount`           | [ServiceAccountConfig](#serviceaccountconfig) | No       | -       | ServiceAccount config   |

### WorkerSpec

Includes all fields from [MasterSpec](#masterspec) (including `extraVolumes`, `extraVolumeMounts`, `extraInitContainers`, `extraContainers`, `serviceAccount`), plus:

| Field                 | Type                                | Required | Default | Description               |
| --------------------- | ----------------------------------- | -------- | ------- | ------------------------- |
| `replicas`            | int32                               | No       | `2`     | Number of workers         |
| `podDisruptionBudget` | [PDBSpec](#pdbspec)                 | No       | -       | PDB config                |
| `overrides`           | [][WorkerOverride](#workeroverride) | No       | -       | Per-pod overrides         |
| `hpa`                 | [HPASpec](#hpaspec)                 | No       | -       | Horizontal Pod Autoscaler |

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
| `gatewayAPI`               | [GatewayAPISpec](#gatewayapispec)             | No       | -                  | Gateway API config                                                 |
| `updateStrategy`           | string                                        | No       | `RollingUpdate`    | Update strategy (`RollingUpdate` or `OnDelete`)                    |
| `extraVolumes`             | []Volume                                      | No       | -                  | Extra volumes                                                      |
| `extraVolumeMounts`        | []VolumeMount                                 | No       | -                  | Extra volume mounts                                                |
| `extraInitContainers`      | []Container                                   | No       | -                  | Extra init containers                                              |
| `extraContainers`          | []Container                                   | No       | -                  | Extra sidecar containers                                           |
| `env`                      | []EnvVar                                      | No       | -                  | Environment variables                                              |
| `envFrom`                  | []EnvFromSource                               | No       | -                  | Env from sources                                                   |
| `securityContext`          | PodSecurityContext                            | No       | -                  | Pod security                                                       |
| `containerSecurityContext` | SecurityContext                               | No       | -                  | Container security                                                 |
| `antiAffinity`             | [AntiAffinitySpec](#antiaffinityspec)         | No       | -                  | Pod anti-affinity for HA                                           |
| `hpa`                      | [HPASpec](#hpaspec)                           | No       | -                  | Horizontal Pod Autoscaler (use with caution for StatefulSet)       |
| `repositoryPlugins`        | [][RepositoryPluginConfig](#repositorypluginconfig) | No | -                  | Auto-install OpenSearch repository plugins + keystore              |
| `serviceAccount`           | [ServiceAccountConfig](#serviceaccountconfig)       | No       | -                  | ServiceAccount for cloud identity integrations                     |

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
| `annotations`         | map[string]string    | No       | -       | StatefulSet annotations                        |
| `podAnnotations`      | map[string]string    | No       | -       | Pod annotations                                |
| `extraVolumes`        | []Volume             | No       | -       | Extra volumes                                  |
| `extraVolumeMounts`   | []VolumeMount        | No       | -       | Extra volume mounts                            |
| `extraInitContainers` | []Container          | No       | -       | Extra init containers                          |
| `extraContainers`     | []Container          | No       | -       | Extra sidecar containers                       |
| `serviceAccount`      | [ServiceAccountConfig](#serviceaccountconfig) | No       | -       | SA config (inherits from indexer if nil)     |

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

| Field                      | Type                              | Required | Default | Description               |
| -------------------------- | --------------------------------- | -------- | ------- | ------------------------- |
| `replicas`                 | int32                             | No       | `2`     | Number of replicas        |
| `enableSSL`                | bool                              | No       | `true`  | Enable SSL for dashboard  |
| `image`                    | [ImageSpec](#imagespec)           | No       | -       | Image override            |
| `resources`                | ResourceRequirements              | No       | -       | Resources                 |
| `wazuhPlugin`              | object                            | No       | -       | Wazuh plugin config       |
| `service`                  | [ServiceSpec](#servicespec)       | No       | -       | Service config            |
| `nodeSelector`             | map[string]string                 | No       | -       | Node selector             |
| `tolerations`              | []Toleration                      | No       | -       | Tolerations               |
| `affinity`                 | Affinity                          | No       | -       | Affinity rules            |
| `podDisruptionBudget`      | [PDBSpec](#pdbspec)               | No       | -       | PDB config                |
| `annotations`              | map[string]string                 | No       | -       | Deployment annotations    |
| `podAnnotations`           | map[string]string                 | No       | -       | Pod annotations           |
| `ingress`                  | [IngressSpec](#ingressspec)       | No       | -       | Ingress config            |
| `gatewayAPI`               | [GatewayAPISpec](#gatewayapispec) | No       | -       | Gateway API config        |
| `env`                      | []EnvVar                          | No       | -       | Environment variables     |
| `envFrom`                  | []EnvFromSource                   | No       | -       | Env from sources          |
| `extraVolumes`             | []Volume                          | No       | -       | Extra volumes             |
| `extraVolumeMounts`        | []VolumeMount                     | No       | -       | Extra volume mounts       |
| `extraInitContainers`      | []Container                       | No       | -       | Extra init containers     |
| `extraContainers`          | []Container                       | No       | -       | Extra sidecar containers  |
| `securityContext`          | PodSecurityContext                | No       | -       | Pod security              |
| `containerSecurityContext` | SecurityContext                   | No       | -       | Container security        |
| `hpa`                      | [HPASpec](#hpaspec)               | No       | -       | Horizontal Pod Autoscaler |
| `serviceAccount`           | [ServiceAccountConfig](#serviceaccountconfig) | No       | -       | ServiceAccount config   |

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

#### ServiceAccountConfig

Configuration for component ServiceAccounts. Supports cloud identity integrations (GKE Workload Identity, AWS IRSA, Azure Workload Identity).

| Field         | Type              | Required | Default | Description                                                                                 |
| ------------- | ----------------- | -------- | ------- | ------------------------------------------------------------------------------------------- |
| `create`      | bool              | No       | `false` | If true, the operator creates and manages the ServiceAccount                                |
| `name`        | string            | No       | -       | SA name. Auto-generated as `{cluster}-{component}` if empty and `create=true`               |
| `annotations` | map[string]string | No       | -       | SA annotations (e.g., `iam.gke.io/gcp-service-account`, `eks.amazonaws.com/role-arn`)       |
| `labels`      | map[string]string | No       | -       | SA labels (e.g., `azure.workload.identity/use: "true"`)                                     |

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

| Field               | Type                                    | Required | Default    | Description                         |
| ------------------- | --------------------------------------- | -------- | ---------- | ----------------------------------- |
| `secretName`        | string                                  | No       | -          | Native K8s Secret name              |
| `externalSecretRef` | [ExternalSecretRef](#externalsecretref) | No       | -          | External Secrets Operator reference |
| `usernameKey`       | string                                  | No       | `username` | Username key in secret              |
| `passwordKey`       | string                                  | No       | `password` | Password key in secret              |

> **Note:** Use either `secretName` for native K8s Secrets or `externalSecretRef` for External Secrets Operator (ESO) integration.

#### ExternalSecretRef

Support for External Secrets Operator (ESO) to integrate with Vault, AWS Secrets Manager, Azure Key Vault, etc.

| Field             | Type                                          | Required | Default | Description                              |
| ----------------- | --------------------------------------------- | -------- | ------- | ---------------------------------------- |
| `name`            | string                                        | **Yes**  | -       | ExternalSecret name (creates K8s Secret) |
| `namespace`       | string                                        | No       | -       | Namespace (defaults to parent resource)  |
| `secretStoreRef`  | [SecretStoreReference](#secretstorereference) | No       | -       | SecretStore or ClusterSecretStore ref    |
| `remoteRef`       | [RemoteSecretRef](#remotesecretref)           | No       | -       | Remote secret location in provider       |
| `refreshInterval` | string                                        | No       | `1h`    | Sync interval (e.g., "1h", "30m")        |

#### SecretStoreReference

| Field  | Type   | Required | Default       | Description                                 |
| ------ | ------ | -------- | ------------- | ------------------------------------------- |
| `name` | string | **Yes**  | -             | SecretStore or ClusterSecretStore name      |
| `kind` | string | No       | `SecretStore` | Kind: `SecretStore` or `ClusterSecretStore` |

#### RemoteSecretRef

| Field      | Type   | Required | Default | Description                               |
| ---------- | ------ | -------- | ------- | ----------------------------------------- |
| `key`      | string | **Yes**  | -       | Key/path in external provider             |
| `property` | string | No       | -       | Specific property within the secret       |
| `version`  | string | No       | -       | Version of the secret (provider-specific) |

#### HPASpec

Configuration for Horizontal Pod Autoscaler (supported on Dashboard, Workers, Indexer).

| Field                               | Type                        | Required | Default | Description                       |
| ----------------------------------- | --------------------------- | -------- | ------- | --------------------------------- |
| `enabled`                           | bool                        | No       | `false` | Enable HPA                        |
| `minReplicas`                       | \*int32                     | No       | `1`     | Minimum replicas                  |
| `maxReplicas`                       | int32                       | No       | `10`    | Maximum replicas                  |
| `targetCPUUtilizationPercentage`    | \*int32                     | No       | `80`    | Target CPU utilization (1-100)    |
| `targetMemoryUtilizationPercentage` | \*int32                     | No       | -       | Target memory utilization (1-100) |
| `behavior`                          | [HPABehavior](#hpabehavior) | No       | -       | Scaling behavior configuration    |

#### HPABehavior

| Field       | Type                                | Required | Default | Description              |
| ----------- | ----------------------------------- | -------- | ------- | ------------------------ |
| `scaleDown` | [HPAScalingRules](#hpascalingrules) | No       | -       | Scale down configuration |
| `scaleUp`   | [HPAScalingRules](#hpascalingrules) | No       | -       | Scale up configuration   |

#### HPAScalingRules

| Field                        | Type    | Required | Default | Description                                |
| ---------------------------- | ------- | -------- | ------- | ------------------------------------------ |
| `stabilizationWindowSeconds` | \*int32 | No       | -       | Stabilization window (0-3600)              |
| `selectPolicy`               | string  | No       | -       | Policy selection: `Max`, `Min`, `Disabled` |

#### AntiAffinitySpec

| Field         | Type   | Required | Default                  | Description                                   |
| ------------- | ------ | -------- | ------------------------ | --------------------------------------------- |
| `enabled`     | bool   | No       | `false`                  | Enable anti-affinity                          |
| `type`        | string | No       | `required`               | Anti-affinity type: `required` or `preferred` |
| `topologyKey` | string | No       | `kubernetes.io/hostname` | Topology key for spreading                    |
| `weight`      | int32  | No       | `100`                    | Weight for preferred anti-affinity (1-100)    |

#### RepositoryPluginConfig

Automatically installs OpenSearch repository plugins and configures the keystore. See [Repository Plugins & Keystore](features/repository-plugins.md).

| Field               | Type                                                        | Required | Default     | Description                                                             |
| ------------------- | ----------------------------------------------------------- | -------- | ----------- | ----------------------------------------------------------------------- |
| `name`              | string                                                      | **Yes**  | -           | Plugin name: `repository-s3`, `repository-gcs`, `repository-azure`, `repository-hdfs` |
| `clientName`        | string                                                      | No       | `default`   | Named client for keystore entries                                       |
| `credentialsSecret` | [RepositoryPluginCredentials](#repositoryplugincredentials) | No       | -           | Secret containing plugin credentials                                    |

#### RepositoryPluginCredentials

| Field  | Type              | Required | Default | Description                                                                                     |
| ------ | ----------------- | -------- | ------- | ----------------------------------------------------------------------------------------------- |
| `name` | string            | **Yes**  | -       | Secret name                                                                                     |
| `keys` | map[string]string | No       | -       | Custom key mappings. Defaults: S3=`access-key`/`secret-key`, GCS=`credentials-file`, Azure=`account`/`key` |

#### GatewayAPISpec

Configuration for exposing services via Gateway API (HTTPRoute, TCPRoute, UDPRoute) instead of legacy Ingress.

| Field        | Type                                    | Required | Default | Description                 |
| ------------ | --------------------------------------- | -------- | ------- | --------------------------- |
| `enabled`    | bool                                    | No       | `false` | Enable Gateway API          |
| `gatewayRef` | [GatewayReference](#gatewayreference)   | No       | -       | Reference to parent Gateway |
| `hostnames`  | []string                                | No       | -       | Hostnames for HTTPRoute     |
| `http`       | [GatewayHTTPConfig](#gatewayhttpconfig) | No       | -       | HTTP route configuration    |
| `tcp`        | [GatewayTCPConfig](#gatewaytcpconfig)   | No       | -       | TCP route configuration     |
| `udp`        | [GatewayUDPConfig](#gatewayudpconfig)   | No       | -       | UDP route configuration     |

#### GatewayReference

| Field         | Type   | Required | Default | Description                     |
| ------------- | ------ | -------- | ------- | ------------------------------- |
| `name`        | string | **Yes**  | -       | Name of the Gateway             |
| `namespace`   | string | No       | -       | Namespace of the Gateway        |
| `sectionName` | string | No       | -       | Section name within the Gateway |

#### GatewayHTTPConfig

| Field         | Type              | Required | Default | Description                |
| ------------- | ----------------- | -------- | ------- | -------------------------- |
| `annotations` | map[string]string | No       | -       | HTTPRoute annotations      |
| `pathPrefix`  | string            | No       | `/`     | Path prefix for HTTP route |

#### GatewayTCPConfig

| Field               | Type              | Required | Default | Description                            |
| ------------------- | ----------------- | -------- | ------- | -------------------------------------- |
| `enabled`           | bool              | No       | `false` | Enable TCP routes                      |
| `enrollmentEnabled` | bool              | No       | `false` | TCP route for enrollment (port 1515)   |
| `eventsEnabled`     | bool              | No       | `false` | TCP route for agent events (port 1514) |
| `clusterEnabled`    | bool              | No       | `false` | TCP route for cluster comm (port 1516) |
| `annotations`       | map[string]string | No       | -       | TCPRoute annotations                   |

#### GatewayUDPConfig

| Field         | Type              | Required | Default | Description                 |
| ------------- | ----------------- | -------- | ------- | --------------------------- |
| `enabled`     | bool              | No       | `false` | Enable UDP route for syslog |
| `syslogPort`  | int32             | No       | `514`   | UDP port for syslog         |
| `annotations` | map[string]string | No       | -       | UDPRoute annotations        |

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

Manages authentication configuration (Basic, OIDC, SAML, LDAP, JWT).
Multiple methods can be enabled at once (e.g. `jwt` + `basicAuth`); each becomes
a separate `authc` domain ordered by its `order` field. Per the
security-dashboards-plugin requirement, when more than one method is enabled
`basicAuth.enabled` must be `true`.

**Short Names:** `osauthconfig`, `osauth`

| Field        | Type                  | Required | Default | Description       |
| ------------ | --------------------- | -------- | ------- | ----------------- |
| `clusterRefs`| []WazuhClusterRef     | **Yes**  | -       | Cluster references|
| `basicAuth`  | BasicAuthSpec         | No       | -       | Basic auth config |
| `oidc`       | OIDCAuthSpec          | No       | -       | OIDC config       |
| `saml`       | SAMLAuthSpec          | No       | -       | SAML config       |
| `ldap`       | LDAPAuthSpec          | No       | -       | LDAP config       |
| `jwt`        | JWTAuthSpec           | No       | -       | JWT config        |

#### JWTAuthSpec

JSON Web Token (bearer token) authentication. Exactly one verification source
is required: `signingKeyRef` **or** `jwksUrl`. Suitable for proxy-injected
tokens such as Teleport application access.

| Field                       | Type         | Required | Default         | Description                                                              |
| --------------------------- | ------------ | -------- | --------------- | ------------------------------------------------------------------------ |
| `enabled`                   | bool         | No       | `false`         | Enable JWT auth domain                                                   |
| `order`                     | int          | No       | `4`             | Evaluation order among auth domains                                      |
| `challenge`                 | bool         | No       | `false`         | Issue auth challenge (keep `false` for JWT)                              |
| `httpEnabled`               | bool         | No       | `true`          | Enable on HTTP layer                                                     |
| `transportEnabled`          | bool         | No       | `false`         | Enable on transport layer                                                |
| `signingKeyRef`             | SecretKeyRef | No\*     | -               | Secret with the signing key (see "Signing key format" below)             |
| `jwksUrl`                   | string       | No\*     | -               | JWKS endpoint to fetch public keys (e.g. Teleport proxy)                 |
| `jwtHeader`                 | string       | No       | `Authorization` | HTTP header carrying the token                                          |
| `jwtUrlParameter`           | string       | No       | -               | Read token from a URL query parameter instead of a header               |
| `subjectKey`                | string       | No       | (`sub`)         | JWT claim used as the username                                           |
| `rolesKey`                  | string       | No       | -               | JWT claim containing backend roles                                       |
| `requiredAudience`          | string       | No       | -               | Reject tokens whose `aud` claim does not match                          |
| `requiredIssuer`            | string       | No       | -               | Reject tokens whose `iss` claim does not match                          |
| `clockSkewToleranceSeconds` | int          | No       | -               | Leeway for `exp`/`nbf` validation                                        |

\* `signingKeyRef` and `jwksUrl` are mutually exclusive; one of the two is required.

**Version-aware routing (automatic).** The OpenSearch `jwt` authenticator only
accepts a `jwks_uri` from **OpenSearch 3.3+**. On older versions, JWKS validation
must go through the `openid` authenticator (where `jwks_uri` replaces
`openid_connect_url`). The operator picks the right form automatically from the
target cluster's version (`spec.version` → OpenSearch version):

| `signingKeyRef`/`jwksUrl` | OpenSearch < 3.3            | OpenSearch ≥ 3.3        |
| ------------------------- | -------------------------- | ----------------------- |
| `jwksUrl`                 | `type: openid` + jwks_uri  | `type: jwt` + jwks_uri  |
| `signingKeyRef`           | `type: jwt` + signing_key  | `type: jwt` + signing_key |

> All current Wazuh releases ship OpenSearch ≤ 2.19, so `jwksUrl` is emitted as an
> `openid` domain today. The native `jwt` + `jwks_uri` form activates automatically
> once a Wazuh version that ships OpenSearch 3.3+ is mapped in
> `pkg/versions.WazuhToOpenSearchVersion`.

**Signing key format (`signingKeyRef`).** The value is base64-decoded by the
security plugin (strict decoder — no embedded newlines):

- **HMAC**: the base64-encoded shared secret.
- **RSA/ECDSA**: the base64 of the DER public key on a **single line** (i.e. the PEM
  body with headers and line breaks stripped). A wrapped multi-line PEM fails with
  `Illegal base64 character`.

Produce it from a PEM or a Teleport JWKS:

```bash
# from a PEM public key
openssl rsa -pubin -in teleport-jwt.pem -outform DER | base64 -w0 > signing_key.b64
kubectl create secret generic teleport-jwt-key -n wazuh --from-file=signing_key=signing_key.b64
```

**Example — JWT (Teleport JWKS) + local basic auth:**

```yaml
apiVersion: resources.wazuh.com/v1
kind: OpenSearchAuthConfig
metadata:
  name: teleport-jwt
  namespace: wazuh
spec:
  clusterRefs:
    - name: production
      namespace: wazuh
  # Local users stay available; required when multiple methods are enabled.
  basicAuth:
    enabled: true
    order: 1
    challenge: true
  jwt:
    enabled: true
    order: 0
    # Routed to the openid authenticator on OpenSearch < 3.3, native jwt on >= 3.3.
    jwksUrl: "https://teleport.example.com/.well-known/jwks.json"
    jwtHeader: "Authorization"
    subjectKey: "sub"
    rolesKey: "roles"
    clockSkewToleranceSeconds: 30
```

Static-key variant (works on every version, `type: jwt`):

```yaml
  jwt:
    enabled: true
    order: 0
    signingKeyRef:
      name: teleport-jwt-key
      key: signing_key   # single-line base64 (see "Signing key format")
    jwtHeader: "Authorization"
    subjectKey: "sub"
    rolesKey: "roles"
```

Map the `roles` claim to OpenSearch roles with an `OpenSearchRoleMapping` (backend roles).

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

| Field        | Type                       | Required | Default | Description                                       |
| ------------ | -------------------------- | -------- | ------- | ------------------------------------------------- |
| `clusterRef` | WazuhClusterReference      | **Yes**  | -       | Cluster reference                                 |
| `type`       | string                     | **Yes**  | -       | Repository type: `s3`, `azure`, `fs`, `gcs`, `hdfs` |
| `settings`   | SnapshotRepositorySettings | **Yes**  | -       | Repository settings                               |
| `verify`     | bool                       | No       | `true`  | Verify repository after creation                  |

#### SnapshotRepositorySettings

| Field                  | Type                       | Required | Default     | Description                                                  |
| ---------------------- | -------------------------- | -------- | ----------- | ------------------------------------------------------------ |
| `bucket`               | string                     | No       | -           | Bucket name (S3, GCS, Azure)                                 |
| `basePath`             | string                     | No       | -           | Path prefix within bucket                                    |
| `region`               | string                     | No       | -           | AWS region (S3)                                              |
| `endpoint`             | string                     | No       | -           | Custom endpoint (MinIO)                                      |
| `pathStyleAccess`      | bool                       | No       | `false`     | Use path-style access (MinIO)                                |
| `compress`             | bool                       | No       | `true`      | Compress snapshot files                                      |
| `serverSideEncryption` | bool                       | No       | `false`     | Enable S3 server-side encryption                             |
| `storageClass`         | string                     | No       | -           | S3 storage class                                             |
| `credentialsSecret`    | CredentialsSecretReference | No       | -           | Secret containing credentials (legacy inline mode)           |
| `client`               | string                     | No       | `default`   | Named client for keystore-based credentials                  |
| `useKeystore`          | bool                       | No       | `false`     | Use keystore credentials instead of inline                   |
| `applicationName`      | string                     | No       | -           | GCS application name                                         |
| `endpointSuffix`       | string                     | No       | -           | Azure endpoint suffix for sovereign clouds                   |
| `uri`                  | string                     | No       | -           | HDFS namenode URI (e.g., `hdfs://namenode:8020`)             |
| `path`                 | string                     | No       | -           | HDFS directory path                                          |
| `securityPrincipal`    | string                     | No       | -           | HDFS Kerberos principal                                      |
| `hadoopConf`           | map[string]string          | No       | -           | Extra HDFS Hadoop configuration (prefixed with `conf.`)      |
| `container`            | string                     | No       | -           | Azure container name                                         |
| `readonly`             | bool                       | No       | `false`     | Read-only repository                                         |

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

**Short Name:** `osrestore`

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

### WazuhAgentGroup

Manages Wazuh agent groups declaratively. Agent groups define shared configuration that is pushed to agents belonging to that group.

**Short Name:** `wagentgroup`

| Field         | Type                  | Required | Default           | Description                                                  |
| ------------- | --------------------- | -------- | ----------------- | ------------------------------------------------------------ |
| `clusterRef`  | WazuhClusterReference | **Yes**  | -                 | Cluster reference                                            |
| `groupName`   | string                | No       | `metadata.name`   | Agent group name (pattern: `^[a-zA-Z0-9._-]+$`)             |
| `description` | string                | No       | -                 | Group description                                            |
| `agentConf`   | string                | No       | -                 | XML agent configuration content (`<agent_config>` block)     |
| `files`       | map[string]string     | No       | -                 | Extra files to place in `/var/ossec/etc/shared/<groupName>/` (mounted via ConfigMap) |

#### Status Fields

| Field                | Type        | Description                                 |
| -------------------- | ----------- | ------------------------------------------- |
| `phase`              | string      | Current phase (Pending/Ready/Failed)        |
| `conditions`         | []Condition | Standard conditions                         |
| `lastSyncTime`       | Time        | Last sync timestamp                         |
| `observedGeneration` | int64       | Last observed generation                    |
| `lastAppliedHash`    | string      | Spec hash for drift detection               |
| `message`            | string      | Additional information                      |
| `agentCount`         | int32       | Number of agents in this group              |

#### Example

```yaml
# docs/usage/examples/wazuh-cluster/wazuhagentgroup-basic.yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhAgentGroup
metadata:
  name: linux-servers
spec:
  clusterRefs:
    - name: wazuh-cluster
      namespace: wazuh
  groupName: linux
  description: "Linux servers group"
  agentConf: |
    <agent_config>
      <syscheck>
        <frequency>600</frequency>
        <directories>/etc,/usr/bin,/usr/sbin</directories>
      </syscheck>
    </agent_config>
  files:
    ar.conf: |
      restart-wazuh0 - ar.conf - 0
      host-deny0 - ar.conf - 600
    rootcheck.txt: |
      # Custom rootcheck policy
```

> **Note:** The `files` field lets you place arbitrary files in the group's shared directory (`/var/ossec/etc/shared/<groupName>/`). The Wazuh API only supports writing `agent.conf`, so additional files like `ar.conf` or custom rootcheck policies are mounted via a ConfigMap with SubPath mounts. Changing `files` triggers a rolling restart of the manager pods.

---

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

### WazuhIntegration

Provisions a Wazuh [custom integration](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html): it installs an executable script in `/var/ossec/integrations/` **and** injects the matching `<integration>` block into `ossec.conf` so `wazuh-integratord` forwards alerts to the script.

**Short Name:** `wintegration`

| Field              | Type                | Required | Default | Description                                                                                          |
| ------------------ | ------------------- | -------- | ------- | ---------------------------------------------------------------------------------------------------- |
| `clusterRefs`      | []WazuhClusterRef   | **Yes**  | -       | Target clusters (cross-namespace)                                                                    |
| `name`             | string              | **Yes**  | -       | Logical name **without** the `custom-` prefix (pattern `^[a-zA-Z0-9_-]+$`); the operator adds it     |
| `script`           | string              | **Yes**  | -       | Integration script content; first line must be a shebang                                             |
| `scriptExtension`  | string              | No       | -       | Optional file extension (no dot), e.g. `py`/`sh` → file becomes `custom-<name>.<ext>`                |
| `hookURL`          | string              | No       | -       | Endpoint passed to the script (`argv[3]`), rendered as `<hook_url>`                                   |
| `hookURLSecretRef` | SecretKeySelector   | No       | -       | Read the hook URL from a Secret in the target cluster namespace (overrides `hookURL`)                |
| `apiKeySecretRef`  | SecretKeySelector   | No       | -       | Read the API key from a Secret in the target cluster namespace; rendered as `<api_key>` (`argv[2]`)  |
| `level`            | int32               | No       | -       | Minimum alert level filter (`<level>`, 0-16)                                                         |
| `ruleID`           | []int32             | No       | -       | Rule ID filter (`<rule_id>`, comma-joined)                                                            |
| `group`            | string              | No       | -       | Rule group filter (`<group>`)                                                                         |
| `eventLocation`    | string              | No       | -       | Alert source filter (`<location>`)                                                                   |
| `alertFormat`      | string              | No       | `json`  | Alert payload format (`json`/`full_log`)                                                              |
| `options`          | string              | No       | -       | Raw JSON forwarded inside `<options>`                                                                 |
| `targetNodes`      | string              | No       | `all`   | Target manager nodes (master/workers/all)                                                            |

The generated script filename and the `<integration>` `<name>` tag are both `custom-<name>[.<scriptExtension>]` (kept in sync because `wazuh-integratord` executes the file named exactly like `<name>`). The script is mounted read-only into `/var/ossec/integrations/` as `root:wazuh` with mode `0750` (the ownership Wazuh requires) — the executable bit comes from the ConfigMap DefaultMode and the wazuh group from the pod's fsGroup. Adding, changing, or removing an integration triggers a rolling restart of the targeted manager pods.

#### Example

```yaml
# docs/usage/examples/wazuh-cluster/wazuhintegration-basic.yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhIntegration
metadata:
  name: slack-high-severity
spec:
  clusterRefs:
    - name: wazuh-cluster
      namespace: wazuh
  name: slack            # operator forces the prefix -> custom-slack
  scriptExtension: py    # -> file & <name> become custom-slack.py
  targetNodes: master
  level: 10
  alertFormat: json
  hookURL: "https://hooks.slack.com/services"
  apiKeySecretRef:       # Secret must live in the target cluster's namespace
    name: slack-integration-credentials
    key: api-key
  script: |
    #!/usr/bin/env python3
    import sys, json
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(alert_file) as f:
        alert = json.load(f)
    # ... forward the alert to the external API ...
    sys.exit(0)
```

### WazuhCertificate

Manages TLS certificates for Wazuh cluster components.

**Short Name:** `wzcert`

| Field               | Type                    | Required | Default | Description                                                     |
| ------------------- | ----------------------- | -------- | ------- | --------------------------------------------------------------- |
| `clusterRef`        | WazuhClusterReference   | **Yes**  | -       | Cluster reference (object with `name` field)                    |
| `type`              | string                  | **Yes**  | -       | Certificate type: ca, node, admin, filebeat, indexer, dashboard |
| `distinguishedName` | DistinguishedNameConfig | No       | -       | X.509 DN configuration                                          |
| `validity`          | string                  | No       | `365d`  | Certificate validity duration (e.g., "365d", "24h", "30m")      |
| `autoRenewal`       | AutoRenewalConfig       | No       | -       | Auto-renewal configuration                                      |
| `sans`              | []string                | No       | -       | Subject Alternative Names                                       |
| `autoGenerateSANs`  | AutoGenerateSANsConfig  | No       | -       | Auto-generate SANs from cluster topology                        |
| `secretName`        | string                  | **Yes**  | -       | Secret name to store the certificate                            |
| `hotReload`         | bool                    | No       | `false` | Enable hot-reload for OpenSearch (2.13+)                        |
| `keyConfig`         | KeyConfig               | No       | -       | Key algorithm and size configuration                            |

#### DistinguishedNameConfig

| Field                | Type   | Required | Default  | Description        |
| -------------------- | ------ | -------- | -------- | ------------------ |
| `country`            | string | No       | `FR`     | X.509 Country      |
| `state`              | string | No       | `Alsace` | X.509 State        |
| `locality`           | string | No       | `S`      | X.509 Locality     |
| `organization`       | string | No       | `Wazuh`  | X.509 Organization |
| `organizationalUnit` | string | No       | `Wazuh`  | X.509 OU           |
| `commonName`         | string | No       | -        | X.509 CN           |

#### AutoRenewalConfig

| Field                        | Type    | Required | Default     | Description                         |
| ---------------------------- | ------- | -------- | ----------- | ----------------------------------- |
| `enabled`                    | bool    | No       | `true`      | Enable auto-renewal                 |
| `thresholdDays`              | int     | No       | `30`        | Days before expiry to renew (1-365) |
| `schedule`                   | string  | No       | `0 2 * * *` | Cron schedule for renewal checks    |
| `successfulJobsHistoryLimit` | \*int32 | No       | `3`         | Successful job history to keep      |
| `failedJobsHistoryLimit`     | \*int32 | No       | `1`         | Failed job history to keep          |

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

Manages scheduled or one-shot backups of Wazuh Manager data to S3, GCS, Azure, or HDFS.

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
| `serviceAccount` | [ServiceAccountConfig](#serviceaccountconfig) | No | - | ServiceAccount configuration for backup jobs |

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

| Field               | Type                                      | Required | Default | Description                                      |
| ------------------- | ----------------------------------------- | -------- | ------- | ------------------------------------------------ |
| `type`              | string                                    | **Yes**  | -       | Storage type: `s3`, `gcs`, `azure`, `hdfs`       |
| `bucket`            | string                                    | No       | -       | Bucket/container name (S3, GCS, Azure)           |
| `prefix`            | string                                    | No       | -       | Path prefix (supports templates)                 |
| `region`            | string                                    | No       | -       | AWS region (S3)                                  |
| `endpoint`          | string                                    | No       | -       | Custom endpoint (MinIO)                          |
| `forcePathStyle`    | bool                                      | No       | `false` | Use path-style access (MinIO)                    |
| `credentialsSecret` | CredentialsSecretReference                | No       | -       | Secret containing credentials (optional for GCS WI, HDFS) |
| `gcs`               | [GCSBackupConfig](#gcsbackupconfig)       | No       | -       | GCS-specific configuration                       |
| `azure`             | [AzureBackupConfig](#azurebackupconfig)   | No       | -       | Azure-specific configuration                     |
| `hdfs`              | [HDFSBackupConfig](#hdfsbackupconfig)     | No       | -       | HDFS-specific configuration                      |

#### GCSBackupConfig

| Field     | Type   | Required | Default | Description    |
| --------- | ------ | -------- | ------- | -------------- |
| `project` | string | No       | -       | GCP project ID |

#### AzureBackupConfig

| Field            | Type   | Required | Default | Description                          |
| ---------------- | ------ | -------- | ------- | ------------------------------------ |
| `container`      | string | No       | -       | Azure Blob Storage container name    |
| `accountName`    | string | No       | -       | Azure Storage account name           |
| `endpointSuffix` | string | No       | -       | Azure endpoint suffix (Gov/China)    |

#### HDFSBackupConfig

| Field  | Type   | Required | Default | Description                    |
| ------ | ------ | -------- | ------- | ------------------------------ |
| `uri`  | string | **Yes**  | -       | HDFS namenode WebHDFS URI      |
| `path` | string | **Yes**  | -       | HDFS directory path            |

**Status Fields:**

| Field           | Type   | Description                         |
| --------------- | ------ | ----------------------------------- |
| `lastBackup`    | \*Time | Timestamp of last successful backup |
| `lastBackupKey` | string | S3 key of last backup archive       |
| `backupCount`   | int32  | Total number of backups             |
| `jobName`       | string | Name of current/last Job            |

### WazuhRestore

Restores Wazuh Manager data from a backup archive (S3, GCS, Azure, or HDFS).

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
| `serviceAccount` | [ServiceAccountConfig](#serviceaccountconfig) | No | - | ServiceAccount configuration for restore jobs |

#### RestoreSource

Exactly one source must be specified:

| Field            | Type                                              | Description                         |
| ---------------- | ------------------------------------------------- | ----------------------------------- |
| `s3`             | [S3RestoreSource](#s3restoresource)               | Restore from S3/MinIO               |
| `gcs`            | [GCSRestoreSource](#gcsrestoresource)             | Restore from GCS                    |
| `azure`          | [AzureRestoreSource](#azurerestoresource)         | Restore from Azure Blob Storage     |
| `hdfs`           | [HDFSRestoreSource](#hdfsrestoresource)           | Restore from HDFS                   |
| `wazuhBackupRef` | [WazuhBackupRef](#wazuhbackupref)                 | Reference to a WazuhBackup resource |

#### S3RestoreSource

| Field               | Type                       | Required | Description                   |
| ------------------- | -------------------------- | -------- | ----------------------------- |
| `bucket`            | string                     | **Yes**  | S3/MinIO bucket name          |
| `key`               | string                     | **Yes**  | Full path to backup archive   |
| `region`            | string                     | No       | AWS region                    |
| `endpoint`          | string                     | No       | Custom endpoint (for MinIO)   |
| `forcePathStyle`    | bool                       | No       | Use path-style access (MinIO) |
| `credentialsSecret` | CredentialsSecretReference | **Yes**  | Secret containing credentials |

#### GCSRestoreSource

| Field               | Type                       | Required | Description                             |
| ------------------- | -------------------------- | -------- | --------------------------------------- |
| `bucket`            | string                     | **Yes**  | GCS bucket name                         |
| `key`               | string                     | **Yes**  | Object key to backup archive            |
| `project`           | string                     | No       | GCP project ID                          |
| `credentialsSecret` | CredentialsSecretReference | No       | Credentials (optional for Workload Identity) |

#### AzureRestoreSource

| Field               | Type                       | Required | Description                           |
| ------------------- | -------------------------- | -------- | ------------------------------------- |
| `container`         | string                     | **Yes**  | Azure Blob Storage container name     |
| `key`               | string                     | **Yes**  | Blob key to backup archive            |
| `accountName`       | string                     | No       | Azure Storage account name            |
| `endpointSuffix`    | string                     | No       | Azure endpoint suffix (Gov/China)     |
| `credentialsSecret` | CredentialsSecretReference | No       | Secret containing credentials         |

#### HDFSRestoreSource

| Field  | Type   | Required | Description                |
| ------ | ------ | -------- | -------------------------- |
| `uri`  | string | **Yes**  | HDFS namenode WebHDFS URI  |
| `path` | string | **Yes**  | HDFS directory path        |
| `key`  | string | **Yes**  | Archive filename           |

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

- `wazuh_v1_wazuhcluster_minimal.yaml` - Minimal development setup
- `wazuh_v1_wazuhcluster_production.yaml` - Production configuration
- `wazuh_v1_wazuhcluster_complete.yaml` - All options documented
- `wazuh_v1_wazuhcluster_monitoring.yaml` - Prometheus monitoring
- `wazuh_v1_wazuhcluster_tls.yaml` - TLS configurations
- `wazuh_v1_wazuhcluster_cloud_workers.yaml` - Cloud log collection

### Wazuh Configuration

- `wazuh_v1_rule.yaml` - Custom rule example
- `wazuh_v1_decoder.yaml` - Custom decoder example

### OpenSearch Security & Index Management

- `opensearch_v1_*.yaml` - OpenSearch resource examples

### Backup & Restore

- `opensearch_v1_opensearchsnapshotrepository_s3.yaml` - AWS S3 repository
- `opensearch_v1_opensearchsnapshotrepository_minio.yaml` - MinIO repository
- `opensearch_v1_opensearchsnapshotrepository_gcs.yaml` - GCS + HDFS repositories
- `opensearch_v1_opensearchsnapshot_manual.yaml` - Manual snapshot trigger
- `opensearch_v1_opensearchrestore.yaml` - Restore from snapshot
- `wazuh_v1_wazuhcluster_with_plugins.yaml` - WazuhCluster with repository plugins
- `wazuh_v1_wazuhbackup_scheduled.yaml` - Scheduled Wazuh backups (S3)
- `wazuh_v1_wazuhbackup_gcs.yaml` - GCS backup (with Workload Identity variant)
- `wazuh_v1_wazuhbackup_azure.yaml` - Azure Blob Storage backup
- `wazuh_v1_wazuhbackup_oneshot.yaml` - One-shot Wazuh backup
- `wazuh_v1_wazuhrestore.yaml` - Wazuh restore examples
