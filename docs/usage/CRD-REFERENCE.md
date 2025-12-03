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
- [Wazuh Configuration CRDs](#wazuh-configuration-crds)
  - [WazuhRule](#wazuhrule)
  - [WazuhDecoder](#wazuhdecoder)

---

## WazuhCluster

The main CRD for deploying a complete Wazuh stack (Manager, Indexer, Dashboard).

**API Group:** `resources.wazuh.com/v1alpha1`
**Kind:** `WazuhCluster`
**Short Name:** `wc`

### Spec Fields

| Field              | Type                                  | Required | Default | Description                   |
| ------------------ | ------------------------------------- | -------- | ------- | ----------------------------- |
| `version`          | string                                | **Yes**  | -       | Wazuh version (format: X.Y.Z) |
| `storageClassName` | string                                | No       | -       | Storage class for all PVCs    |
| `imagePullSecrets` | []LocalObjectReference                | No       | -       | Image pull secrets            |
| `tls`              | [TLSConfig](#tlsconfig)               | No       | -       | TLS configuration             |
| `monitoring`       | [MonitoringConfig](#monitoringconfig) | No       | -       | Prometheus monitoring         |
| `manager`          | [ManagerSpec](#managerspec)           | No       | -       | Manager configuration         |
| `indexer`          | [IndexerSpec](#indexerspec)           | No       | -       | Indexer configuration         |
| `dashboard`        | [DashboardSpec](#dashboardspec)       | No       | -       | Dashboard configuration       |

### TLSConfig

| Field        | Type                                    | Required | Default | Description                         |
| ------------ | --------------------------------------- | -------- | ------- | ----------------------------------- |
| `enabled`    | bool                                    | No       | `true`  | Enable TLS                          |
| `certConfig` | [CertificateConfig](#certificateconfig) | No       | -       | Auto-generated certificate settings |
| `hotReload`  | [HotReloadConfig](#hotreloadconfig)     | No       | -       | Hot reload settings                 |

> **Note**: Cert-manager integration and custom certificates are planned features but not yet implemented.

### CertificateConfig

| Field                    | Type   | Required | Default      | Description                 |
| ------------------------ | ------ | -------- | ------------ | --------------------------- |
| `country`                | string | No       | `US`         | X.509 Country               |
| `state`                  | string | No       | `California` | X.509 State                 |
| `locality`               | string | No       | `California` | X.509 Locality              |
| `organization`           | string | No       | `Wazuh`      | X.509 Organization          |
| `organizationalUnit`     | string | No       | `Wazuh`      | X.509 OU                    |
| `commonName`             | string | No       | `admin`      | X.509 CN                    |
| `validityDays`           | int    | No       | `365`        | Certs validity (days)       |
| `renewalThresholdDays`   | int    | No       | `30`         | Certs renewal threshold     |
| `caValidityDays`         | int    | No       | `730`        | CA validity (days)          |
| `caRenewalThresholdDays` | int    | No       | `60`         | CA renewal threshold        |

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

### WazuhExporterConfig

| Field          | Type                 | Required | Default                                     | Description         |
| -------------- | -------------------- | -------- | ------------------------------------------- | ------------------- |
| `enabled`      | bool                 | No       | `false`                                     | Enable exporter     |
| `image`        | string               | No       | `kennyopennix/wazuh-exporter:latest`        | Exporter image      |
| `port`         | int32                | No       | `9090`                                      | Metrics port        |
| `apiProtocol`  | string               | No       | `https`                                     | API protocol        |
| `apiVerifySSL` | bool                 | No       | `false`                                     | Verify SSL          |
| `logLevel`     | string               | No       | `INFO`                                      | Log level           |
| `resources`    | ResourceRequirements | No       | -                                           | Container resources |

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

| Field             | Type     | Required | Default               | Description                                                   |
| ----------------- | -------- | -------- | --------------------- | ------------------------------------------------------------- |
| `enabled`         | bool     | No       | `false`               | Enable log rotation CronJob                                   |
| `schedule`        | string   | No       | `0 0 * * 1`           | Cron schedule (default: weekly on Monday at midnight)         |
| `retentionDays`   | int32    | No       | `7`                   | Days to retain log files                                      |
| `maxFileSizeMB`   | int32    | No       | `0`                   | Max file size in MB (0 = disabled)                            |
| `combinationMode` | string   | No       | `or`                  | How age/size filters combine: `or` (delete if old OR large), `and` (both) |
| `paths`           | []string | No       | alerts/, archives/    | Log paths to clean                                            |
| `image`           | string   | No       | `bitnami/kubectl:latest` | kubectl image for CronJob                                  |

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

| Field       | Type   | Required | Default | Description                              |
| ----------- | ------ | -------- | ------- | ---------------------------------------- |
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

| Field                      | Type                                          | Required | Default            | Description             |
| -------------------------- | --------------------------------------------- | -------- | ------------------ | ----------------------- |
| `replicas`                 | int32                                         | No       | `3`                | Number of replicas      |
| `storageSize`              | string                                        | No       | `50Gi`             | Storage size            |
| `clusterName`              | string                                        | No       | `wazuh`            | Cluster name            |
| `javaOpts`                 | string                                        | No       | `-Xms1g -Xmx1g...` | Java options            |
| `image`                    | [ImageSpec](#imagespec)                       | No       | -                  | Image override          |
| `resources`                | ResourceRequirements                          | No       | -                  | Resources               |
| `credentials`              | [CredentialsSecretRef](#credentialssecretref) | No       | -                  | Admin credentials       |
| `service`                  | [ServiceSpec](#servicespec)                   | No       | -                  | Service config          |
| `nodeSelector`             | map[string]string                             | No       | -                  | Node selector           |
| `tolerations`              | []Toleration                                  | No       | -                  | Tolerations             |
| `affinity`                 | Affinity                                      | No       | -                  | Affinity rules          |
| `podDisruptionBudget`      | [PDBSpec](#pdbspec)                           | No       | -                  | PDB config              |
| `annotations`              | map[string]string                             | No       | -                  | StatefulSet annotations |
| `podAnnotations`           | map[string]string                             | No       | -                  | Pod annotations         |
| `ingress`                  | [IngressSpec](#ingressspec)                   | No       | -                  | Ingress config          |
| `updateStrategy`           | string                                        | No       | `RollingUpdate`    | Update strategy         |
| `initContainers`           | []Container                                   | No       | -                  | Init containers         |
| `env`                      | []EnvVar                                      | No       | -                  | Environment variables   |
| `envFrom`                  | []EnvFromSource                               | No       | -                  | Env from sources        |
| `securityContext`          | PodSecurityContext                            | No       | -                  | Pod security            |
| `containerSecurityContext` | SecurityContext                               | No       | -                  | Container security      |

### DashboardSpec

| Field                      | Type                                    | Required | Default | Description            |
| -------------------------- | --------------------------------------- | -------- | ------- | ---------------------- |
| `replicas`                 | int32                                   | No       | `2`     | Number of replicas     |
| `enableSSL`                | bool                                    | No       | `false` | Enable SSL             |
| `image`                    | [ImageSpec](#imagespec)                 | No       | -       | Image override         |
| `resources`                | ResourceRequirements                    | No       | -       | Resources              |
| `wazuhPlugin`              | object                                  | No       | -       | Wazuh plugin config    |
| `service`                  | [ServiceSpec](#servicespec)             | No       | -       | Service config         |
| `nodeSelector`             | map[string]string                       | No       | -       | Node selector          |
| `tolerations`              | []Toleration                            | No       | -       | Tolerations            |
| `affinity`                 | Affinity                                | No       | -       | Affinity rules         |
| `podDisruptionBudget`      | [PDBSpec](#pdbspec)                     | No       | -       | PDB config             |
| `annotations`              | map[string]string                       | No       | -       | Deployment annotations |
| `podAnnotations`           | map[string]string                       | No       | -       | Pod annotations        |
| `ingress`                  | [IngressSpec](#ingressspec)             | No       | -       | Ingress config         |
| `env`                      | []EnvVar                                | No       | -       | Environment variables  |
| `envFrom`                  | []EnvFromSource                         | No       | -       | Env from sources       |
| `securityContext`          | PodSecurityContext                      | No       | -       | Pod security           |
| `containerSecurityContext` | SecurityContext                         | No       | -       | Container security     |

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

| Field                     | Type                                                  | Description                     |
| ------------------------- | ----------------------------------------------------- | ------------------------------- |
| `indexerExpansion`        | [ComponentExpansionStatus](#componentexpansionstatus) | Indexer PVC expansion status    |
| `managerMasterExpansion`  | [ComponentExpansionStatus](#componentexpansionstatus) | Manager master expansion status |
| `managerWorkersExpansion` | [ComponentExpansionStatus](#componentexpansionstatus) | Manager workers expansion status |

#### ComponentExpansionStatus

Tracks expansion status for a specific component:

| Field                | Type     | Description                                          |
| -------------------- | -------- | ---------------------------------------------------- |
| `phase`              | string   | Expansion phase: Pending, InProgress, Completed, Failed |
| `requestedSize`      | string   | Target storage size (e.g., "100Gi")                  |
| `currentSize`        | string   | Current storage size                                 |
| `message`            | string   | Human-readable status message                        |
| `lastTransitionTime` | Time     | When the phase last changed                          |
| `pvcsExpanded`       | []string | List of PVCs that have completed expansion           |
| `pvcsPending`        | []string | List of PVCs still pending expansion                 |

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

- `wazuh_v1alpha1_wazuhcluster_minimal.yaml` - Minimal development setup
- `wazuh_v1alpha1_wazuhcluster_production.yaml` - Production configuration
- `wazuh_v1alpha1_wazuhcluster_complete.yaml` - All options documented
- `wazuh_v1alpha1_wazuhcluster_monitoring.yaml` - Prometheus monitoring
- `wazuh_v1alpha1_wazuhcluster_tls.yaml` - TLS configurations
- `wazuh_v1alpha1_wazuhcluster_cloud_workers.yaml` - Cloud log collection
- `opensearch_v1alpha1_*.yaml` - OpenSearch resource examples
- `wazuh_v1alpha1_rule.yaml` - Custom rule example
- `wazuh_v1alpha1_decoder.yaml` - Custom decoder example
