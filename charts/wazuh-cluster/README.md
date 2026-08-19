# wazuh-cluster

## Prerequisites

- Kubernetes 1.25+
- Helm 3
- Wazuh Operator installed (use the `wazuh-operator` chart)

## Documentation

| Resource                                                       | Description                     |
| -------------------------------------------------------------- | ------------------------------- |
| [User Documentation](../../docs/usage/README.md)               | Full usage guide                |
| [Quick Start Examples](../../docs/usage/examples/quick-start/) | Minimal deployment examples     |
| [Production Examples](../../docs/usage/examples/production/)   | Production-ready configurations |
| [Sizing Profiles](../../docs/usage/features/sizing.md)         | Cluster sizing guide            |
| [CRD Reference](../../docs/usage/CRD-REFERENCE.md)             | Complete API documentation      |

## Installation

### Quick Start

1. Install the Wazuh Operator first (if not already installed):

```bash
helm template wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-operator | kubectl apply --server-side -f -
```

2. Install the chart with a sizing profile:

```bash
helm template my-wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=M \
  --namespace wazuh | kubectl apply --server-side -f -
```

## Upgrading

```bash
helm template my-wazuh-cluster ./charts/wazuh-cluster \
  -f my-values.yaml \
  --namespace wazuh | kubectl apply --server-side -f -
```

## Uninstallation

```bash
kubectl delete -f <(helm template my-wazuh-cluster ./charts/wazuh-cluster --namespace wazuh)
```

> **Note:** This will delete all WazuhCluster resources and secrets. The operator will clean up all associated Kubernetes resources.

## Values

### Global Parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| createNamespace | bool | `true` | Create namespace if it doesn't exist |
| nameOverride | string | `""` | Override the name of the chart |
| namespace | string | `"wazuh"` | Namespace where the Wazuh cluster will be deployed |

### Sizing Profiles

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| sizing.profile | string | `"M"` | Sizing profile: XS (testing), S (dev), M (small prod), L (prod), XL (enterprise). Set to "" for custom config. |
| sizing.storageClassName | string | `""` | Custom storage class (applies to all profiles). Leave empty for cluster default. |

### Inline Secrets

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| secrets.indexerAdmin.password | string | `""` | Indexer admin password (leave empty for auto-generation by the operator) |
| secrets.indexerAdmin.username | string | `"admin"` | Indexer admin username |
| secrets.wazuhApi.password | string | `""` | Wazuh API password (leave empty for auto-generation by the operator) |
| secrets.wazuhApi.username | string | `"wazuh-api"` | Wazuh API username |
| secrets.wazuhAuthd.enabled | bool | `true` | Enable authd password secret creation |
| secrets.wazuhAuthd.password | string | `""` | Agent enrollment password (leave empty for auto-generation by the operator) |

### External Secrets Operator (ESO)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| externalSecrets.enabled | bool | `false` | Enable External Secrets integration (when true, inline secrets are ignored for configured components) |
| externalSecrets.indexerAdmin.name | string | `""` | ExternalSecret name (leave empty to use inline secrets) |
| externalSecrets.indexerAdmin.passwordKey | string | `"password"` | Key in synced secret containing password |
| externalSecrets.indexerAdmin.refreshInterval | string | `"1h"` | Sync interval (e.g., "1h", "30m") |
| externalSecrets.indexerAdmin.remoteRef.key | string | `""` | Key/path in external provider (e.g., "secret/data/wazuh/indexer") |
| externalSecrets.indexerAdmin.secretStoreRef.kind | string | `"SecretStore"` | SecretStore kind: SecretStore or ClusterSecretStore |
| externalSecrets.indexerAdmin.secretStoreRef.name | string | `""` | SecretStore name |
| externalSecrets.indexerAdmin.usernameKey | string | `"username"` | Key in synced secret containing username |
| externalSecrets.wazuhApi.name | string | `""` | ExternalSecret name (leave empty to use inline secrets) |
| externalSecrets.wazuhApi.passwordKey | string | `"password"` |  |
| externalSecrets.wazuhApi.refreshInterval | string | `"1h"` |  |
| externalSecrets.wazuhApi.remoteRef.key | string | `""` |  |
| externalSecrets.wazuhApi.secretStoreRef.kind | string | `"SecretStore"` |  |
| externalSecrets.wazuhApi.secretStoreRef.name | string | `""` |  |
| externalSecrets.wazuhApi.usernameKey | string | `"username"` |  |
| externalSecrets.wazuhAuthd.name | string | `""` | ExternalSecret name (leave empty to use inline secrets) |
| externalSecrets.wazuhAuthd.passwordKey | string | `"password"` | Key in synced secret containing password |
| externalSecrets.wazuhAuthd.refreshInterval | string | `"1h"` |  |
| externalSecrets.wazuhAuthd.remoteRef.key | string | `""` |  |
| externalSecrets.wazuhAuthd.secretStoreRef.kind | string | `"SecretStore"` |  |
| externalSecrets.wazuhAuthd.secretStoreRef.name | string | `""` |  |

### Cluster General

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster.enabled | bool | `true` | Enable WazuhCluster deployment |
| cluster.name | string | `"wazuh-cluster"` | Name of the WazuhCluster resource |
| cluster.spec.imagePullSecrets | list | `[]` | Image pull secrets for private container registries (applied to all components) |
| cluster.spec.version | string | `"4.9.0"` | Wazuh version to deploy |

### Indexer Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster.spec.indexer.affinity | object | `{}` | Indexer pod affinity rules |
| cluster.spec.indexer.annotations | object | `{}` | Indexer StatefulSet annotations |
| cluster.spec.indexer.antiAffinity.enabled | bool | `false` | Enable pod anti-affinity for indexer |
| cluster.spec.indexer.antiAffinity.topologyKey | string | `"kubernetes.io/hostname"` | Topology key for anti-affinity |
| cluster.spec.indexer.antiAffinity.type | string | `"preferred"` | Anti-affinity type: "preferred" or "required" |
| cluster.spec.indexer.antiAffinity.weight | int | `100` | Weight for preferred anti-affinity (1-100) |
| cluster.spec.indexer.clusterSettings | object | `{}` |  |
| cluster.spec.indexer.containerSecurityContext | object | `{}` | Indexer container security context |
| cluster.spec.indexer.env | list | `[]` | Indexer environment variables |
| cluster.spec.indexer.envFrom | list | `[]` | Indexer environment variables from ConfigMaps/Secrets |
| cluster.spec.indexer.extraContainers | list | `[]` | Indexer extra sidecar containers |
| cluster.spec.indexer.extraInitContainers | list | `[]` | Indexer extra init containers |
| cluster.spec.indexer.extraVolumeMounts | list | `[]` | Indexer extra volume mounts |
| cluster.spec.indexer.extraVolumes | list | `[]` | Indexer extra volumes |
| cluster.spec.indexer.gatewayAPI.enabled | bool | `false` | Enable Gateway API for indexer |
| cluster.spec.indexer.hpa.behavior | object | `{}` | HPA scaling behavior |
| cluster.spec.indexer.hpa.enabled | bool | `false` | Enable HPA for indexer |
| cluster.spec.indexer.hpa.maxReplicas | int | `9` | Maximum indexer replicas |
| cluster.spec.indexer.hpa.minReplicas | int | `3` | Minimum indexer replicas |
| cluster.spec.indexer.hpa.targetCPUUtilizationPercentage | int | `70` | Target CPU utilization percentage |
| cluster.spec.indexer.hpa.targetMemoryUtilizationPercentage | int | `80` | Target memory utilization percentage |
| cluster.spec.indexer.image | object | `{"pullPolicy":"","repository":"","tag":""}` | Override global storageClassName for indexer PVCs (e.g., "fast-ssd") storageClass: "" @extra cluster.spec.indexer.image Indexer image override |
| cluster.spec.indexer.image.pullPolicy | string | `""` | Indexer image pull policy |
| cluster.spec.indexer.image.repository | string | `""` | Indexer image repository (leave empty for operator default) |
| cluster.spec.indexer.image.tag | string | `""` | Indexer image tag (leave empty for operator default) |
| cluster.spec.indexer.ingress.annotations | object | `{}` | Ingress annotations |
| cluster.spec.indexer.ingress.enabled | bool | `false` | Enable Ingress for indexer |
| cluster.spec.indexer.ingress.hosts | list | `[]` | Ingress hosts |
| cluster.spec.indexer.ingress.ingressClassName | string | `""` | Ingress class name |
| cluster.spec.indexer.ingress.tls | list | `[]` | Ingress TLS configuration |
| cluster.spec.indexer.nodeSelector | object | `{}` | Indexer node selector |
| cluster.spec.indexer.podAnnotations | object | `{}` | Indexer pod annotations |
| cluster.spec.indexer.podDisruptionBudget.enabled | bool | `false` | Enable PDB for indexer |
| cluster.spec.indexer.podDisruptionBudget.maxUnavailable | int | `1` | Maximum unavailable indexer pods |
| cluster.spec.indexer.securityContext | object | `{}` | Indexer pod security context |
| cluster.spec.indexer.service.annotations | object | `{}` | Indexer service annotations |
| cluster.spec.indexer.service.type | string | `""` | Indexer service type |
| cluster.spec.indexer.serviceAccount.annotations | object | `{}` | ServiceAccount annotations (e.g., for GKE Workload Identity, AWS IRSA) |
| cluster.spec.indexer.serviceAccount.create | bool | `false` | Create a dedicated ServiceAccount for indexer pods |
| cluster.spec.indexer.serviceAccount.labels | object | `{}` | ServiceAccount labels (e.g., for Azure Workload Identity) |
| cluster.spec.indexer.serviceAccount.name | string | `""` | ServiceAccount name (auto-generated as "{cluster}-indexer" if empty) |
| cluster.spec.indexer.terminationGracePeriodSeconds | int | `120` | Termination grace period for indexer pods (seconds) |
| cluster.spec.indexer.tolerations | list | `[]` | Indexer tolerations |
| cluster.spec.indexer.topologySpreadConstraints | list | `[]` | Indexer topology spread constraints |
| cluster.spec.indexer.updateStrategy | string | `"RollingUpdate"` | Indexer update strategy (RollingUpdate or OnDelete) |

### Manager Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster.spec.manager.agentPurge.disconnectedDays | int | `30` | Delete agents disconnected for more than this many days |
| cluster.spec.manager.agentPurge.dryRun | bool | `true` | Dry-run: list matching agents without deleting them |
| cluster.spec.manager.agentPurge.enabled | bool | `false` | Enable agent purge (WARNING: purged agents must re-enroll) |
| cluster.spec.manager.agentPurge.image | string | `"curlimages/curl:latest"` | Image for agent purge job |
| cluster.spec.manager.agentPurge.schedule | string | `"0 3 * * *"` | Agent purge cron schedule |
| cluster.spec.manager.agentPurge.statuses | list | `["disconnected"]` | Agent statuses to target: disconnected, never_connected |
| cluster.spec.manager.antiAffinity.enabled | bool | `false` | Enable pod anti-affinity for manager |
| cluster.spec.manager.antiAffinity.topologyKey | string | `"kubernetes.io/hostname"` | Topology key for anti-affinity |
| cluster.spec.manager.antiAffinity.type | string | `"preferred"` | Anti-affinity type: "preferred" or "required" |
| cluster.spec.manager.antiAffinity.weight | int | `100` | Weight for preferred anti-affinity (1-100) |
| cluster.spec.manager.config.alerts.emailAlertLevel | int | `12` | Minimum level for email alerts |
| cluster.spec.manager.config.alerts.logAlertLevel | int | `3` | Minimum level for logging alerts |
| cluster.spec.manager.config.auth.ciphers | string | `"HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"` | TLS ciphers for authd |
| cluster.spec.manager.config.auth.disabled | bool | `false` | Disable authd |
| cluster.spec.manager.config.auth.enabledOnMasterOnly | bool | `true` | Only allow registration on master node |
| cluster.spec.manager.config.auth.port | int | `1515` | Authd listening port |
| cluster.spec.manager.config.auth.purge | bool | `true` | Purge agents on registration conflict |
| cluster.spec.manager.config.auth.usePassword | bool | `false` | Require password for registration |
| cluster.spec.manager.config.auth.useSourceIP | bool | `false` | Use source IP for agent registration |
| cluster.spec.manager.config.global.agentsDisconnectionAlertTime | string | `"0"` | Agent disconnection alert time (0 = disabled) |
| cluster.spec.manager.config.global.agentsDisconnectionTime | string | `"10m"` | Agent disconnection time threshold |
| cluster.spec.manager.config.global.alertsLog | bool | `true` | Enable alerts log |
| cluster.spec.manager.config.global.emailFrom | string | `"wazuh@example.wazuh.com"` | Email sender address |
| cluster.spec.manager.config.global.emailMaxPerHour | int | `12` | Maximum emails per hour |
| cluster.spec.manager.config.global.emailNotification | bool | `false` | Enable email notifications |
| cluster.spec.manager.config.global.emailTo | string | `"recipient@example.wazuh.com"` | Email recipient address |
| cluster.spec.manager.config.global.jsonoutOutput | bool | `true` | Enable JSON output |
| cluster.spec.manager.config.global.logAll | bool | `false` | Log all events |
| cluster.spec.manager.config.global.logAllJson | bool | `false` | Log all events in JSON format |
| cluster.spec.manager.config.global.smtpServer | string | `"smtp.example.wazuh.com"` | SMTP server address |
| cluster.spec.manager.config.logging.logFormat | string | `"plain"` | Log format: "plain" or "json" |
| cluster.spec.manager.config.remote.connection | string | `"secure"` | Connection type: "secure" or "syslog" |
| cluster.spec.manager.config.remote.port | int | `1514` | Remote listening port |
| cluster.spec.manager.config.remote.protocol | string | `"tcp"` | Protocol: "tcp" or "udp" |
| cluster.spec.manager.config.remote.queueSize | int | `131072` | Message queue size |
| cluster.spec.manager.config.ruleset.decoderDirs | list | `["ruleset/decoders","etc/decoders"]` | Directories to load decoders from |
| cluster.spec.manager.config.ruleset.decoderExcludes | list | `[]` | Decoder files to exclude from loading |
| cluster.spec.manager.config.ruleset.lists | list | `[]` | CDB list files to load (without extension) |
| cluster.spec.manager.config.ruleset.ruleDirs | list | `["ruleset/rules","etc/rules"]` | Directories to load rules from |
| cluster.spec.manager.config.ruleset.ruleExcludes | list | `[]` | Rule files to exclude from loading |
| cluster.spec.manager.filebeatSSLVerificationMode | string | `"full"` | Filebeat SSL verification mode: full, none, certificate |
| cluster.spec.manager.image.pullPolicy | string | `""` | Manager image pull policy |
| cluster.spec.manager.image.repository | string | `""` | Manager image repository (leave empty for operator default) |
| cluster.spec.manager.image.tag | string | `""` | Manager image tag (leave empty for operator default) |
| cluster.spec.manager.logRotation.combinationMode | string | `"or"` | Combination mode for retention criteria: "or" or "and" |
| cluster.spec.manager.logRotation.enabled | bool | `false` | Enable log rotation |
| cluster.spec.manager.logRotation.image | string | `"bitnami/kubectl:latest"` | Image for log rotation job |
| cluster.spec.manager.logRotation.maxFileSizeMB | int | `0` | Max file size in MB (0 = disabled) |
| cluster.spec.manager.logRotation.paths | list | `["/var/ossec/logs/alerts/","/var/ossec/logs/archives/"]` | Paths to rotate |
| cluster.spec.manager.logRotation.retentionDays | int | `7` | Retention period in days |
| cluster.spec.manager.logRotation.schedule | string | `"0 0 * * 1"` | Log rotation cron schedule |
| cluster.spec.manager.podDisruptionBudget.enabled | bool | `false` | Enable PDB for manager |
| cluster.spec.manager.podDisruptionBudget.maxUnavailable | int | `1` | Maximum unavailable manager pods |

### Manager Master Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster.spec.manager.master.affinity | object | `{}` | Master pod affinity rules |
| cluster.spec.manager.master.annotations | object | `{}` | Master StatefulSet annotations |
| cluster.spec.manager.master.containerSecurityContext | object | `{}` | Master container security context |
| cluster.spec.manager.master.env | list | `[]` | Master environment variables |
| cluster.spec.manager.master.envFrom | list | `[]` | Master environment variables from ConfigMaps/Secrets |
| cluster.spec.manager.master.extraConfig | string | `""` | Extra XML config to inject into ossec.conf (master only) |
| cluster.spec.manager.master.extraContainers | list | `[]` | Master extra sidecar containers |
| cluster.spec.manager.master.extraInitContainers | list | `[]` | Master extra init containers |
| cluster.spec.manager.master.extraVolumeMounts | list | `[]` | Master extra volume mounts |
| cluster.spec.manager.master.extraVolumes | list | `[]` | Master extra volumes |
| cluster.spec.manager.master.gatewayAPI.enabled | bool | `false` | Enable Gateway API for master |
| cluster.spec.manager.master.ingress.annotations | object | `{}` | Ingress annotations |
| cluster.spec.manager.master.ingress.enabled | bool | `false` | Enable Ingress for master |
| cluster.spec.manager.master.ingress.hosts | list | `[]` | Ingress hosts |
| cluster.spec.manager.master.ingress.ingressClassName | string | `""` | Ingress class name |
| cluster.spec.manager.master.ingress.tls | list | `[]` | Ingress TLS configuration |
| cluster.spec.manager.master.localInternalOptions | string | `""` | Local internal options (content for /var/ossec/etc/local_internal_options.conf) |
| cluster.spec.manager.master.nodeSelector | object | `{}` | Master node selector |
| cluster.spec.manager.master.podAnnotations | object | `{}` | Master pod annotations |
| cluster.spec.manager.master.securityContext | object | `{}` | Master pod security context |
| cluster.spec.manager.master.service.annotations | object | `{}` | Master service annotations |
| cluster.spec.manager.master.service.type | string | `""` | Master service type |
| cluster.spec.manager.master.serviceAccount.annotations | object | `{}` | ServiceAccount annotations |
| cluster.spec.manager.master.serviceAccount.create | bool | `false` | Create a dedicated ServiceAccount for master pods |
| cluster.spec.manager.master.serviceAccount.labels | object | `{}` | ServiceAccount labels |
| cluster.spec.manager.master.serviceAccount.name | string | `""` | ServiceAccount name (auto-generated as "{cluster}-master" if empty) |
| cluster.spec.manager.master.terminationGracePeriodSeconds | int | `90` | Master termination grace period (seconds) |
| cluster.spec.manager.master.tolerations | list | `[]` | Master tolerations |
| cluster.spec.manager.master.topologySpreadConstraints | list | `[]` | Master topology spread constraints |

### Manager Workers Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster.spec.manager.workers.affinity | object | `{}` | Workers pod affinity rules |
| cluster.spec.manager.workers.annotations | object | `{}` | Workers StatefulSet annotations |
| cluster.spec.manager.workers.containerSecurityContext | object | `{}` | Workers container security context |
| cluster.spec.manager.workers.env | list | `[]` | Workers environment variables |
| cluster.spec.manager.workers.envFrom | list | `[]` | Workers environment variables from ConfigMaps/Secrets |
| cluster.spec.manager.workers.extraConfig | string | `""` | Extra XML config to inject into ossec.conf (all workers) |
| cluster.spec.manager.workers.extraContainers | list | `[]` | Workers extra sidecar containers |
| cluster.spec.manager.workers.extraInitContainers | list | `[]` | Workers extra init containers |
| cluster.spec.manager.workers.extraVolumeMounts | list | `[]` | Workers extra volume mounts |
| cluster.spec.manager.workers.extraVolumes | list | `[]` | Workers extra volumes |
| cluster.spec.manager.workers.gatewayAPI.enabled | bool | `false` | Enable Gateway API for workers |
| cluster.spec.manager.workers.hpa.behavior | object | `{}` | HPA scaling behavior |
| cluster.spec.manager.workers.hpa.enabled | bool | `false` | Enable HPA for workers |
| cluster.spec.manager.workers.hpa.maxReplicas | int | `10` | Maximum worker replicas |
| cluster.spec.manager.workers.hpa.minReplicas | int | `2` | Minimum worker replicas |
| cluster.spec.manager.workers.hpa.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage |
| cluster.spec.manager.workers.hpa.targetMemoryUtilizationPercentage | int | `80` | Target memory utilization percentage |
| cluster.spec.manager.workers.ingress.annotations | object | `{}` | Ingress annotations |
| cluster.spec.manager.workers.ingress.enabled | bool | `false` | Enable Ingress for workers |
| cluster.spec.manager.workers.ingress.hosts | list | `[]` | Ingress hosts |
| cluster.spec.manager.workers.ingress.ingressClassName | string | `""` | Ingress class name |
| cluster.spec.manager.workers.ingress.tls | list | `[]` | Ingress TLS configuration |
| cluster.spec.manager.workers.localInternalOptions | string | `""` | Local internal options (content for /var/ossec/etc/local_internal_options.conf) |
| cluster.spec.manager.workers.nodeSelector | object | `{}` | Workers node selector |
| cluster.spec.manager.workers.podAnnotations | object | `{}` | Workers pod annotations |
| cluster.spec.manager.workers.podDisruptionBudget.enabled | bool | `false` | Enable PDB for workers |
| cluster.spec.manager.workers.podDisruptionBudget.maxUnavailable | int | `1` | Maximum unavailable worker pods |
| cluster.spec.manager.workers.securityContext | object | `{}` | Workers pod security context |
| cluster.spec.manager.workers.service.annotations | object | `{}` | Workers service annotations |
| cluster.spec.manager.workers.service.type | string | `""` | Workers service type |
| cluster.spec.manager.workers.serviceAccount.annotations | object | `{}` | ServiceAccount annotations |
| cluster.spec.manager.workers.serviceAccount.create | bool | `false` | Create a dedicated ServiceAccount for worker pods |
| cluster.spec.manager.workers.serviceAccount.labels | object | `{}` | ServiceAccount labels |
| cluster.spec.manager.workers.serviceAccount.name | string | `""` | ServiceAccount name (auto-generated as "{cluster}-worker" if empty) |
| cluster.spec.manager.workers.terminationGracePeriodSeconds | int | `90` | Workers termination grace period (seconds) |
| cluster.spec.manager.workers.tolerations | list | `[]` | Workers tolerations |
| cluster.spec.manager.workers.topologySpreadConstraints | list | `[]` | Workers topology spread constraints |

### Dashboard Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster.spec.dashboard.affinity | object | `{}` | Dashboard pod affinity rules |
| cluster.spec.dashboard.annotations | object | `{}` | Dashboard Deployment annotations |
| cluster.spec.dashboard.containerSecurityContext | object | `{}` | Dashboard container security context |
| cluster.spec.dashboard.enableSSL | bool | `true` | Enable HTTPS for dashboard (set to false for HTTP) |
| cluster.spec.dashboard.env | list | `[]` | Dashboard environment variables |
| cluster.spec.dashboard.envFrom | list | `[]` | Dashboard environment variables from ConfigMaps/Secrets |
| cluster.spec.dashboard.extraContainers | list | `[]` | Dashboard extra sidecar containers |
| cluster.spec.dashboard.extraInitContainers | list | `[]` | Dashboard extra init containers |
| cluster.spec.dashboard.extraVolumeMounts | list | `[]` | Dashboard extra volume mounts |
| cluster.spec.dashboard.extraVolumes | list | `[]` | Dashboard extra volumes |
| cluster.spec.dashboard.gatewayAPI.enabled | bool | `false` | Enable Gateway API for dashboard |
| cluster.spec.dashboard.hpa.enabled | bool | `false` | Enable HPA for dashboard |
| cluster.spec.dashboard.hpa.maxReplicas | int | `5` | Maximum dashboard replicas |
| cluster.spec.dashboard.hpa.minReplicas | int | `2` | Minimum dashboard replicas |
| cluster.spec.dashboard.hpa.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage |
| cluster.spec.dashboard.image.pullPolicy | string | `""` | Dashboard image pull policy |
| cluster.spec.dashboard.image.repository | string | `""` | Dashboard image repository (leave empty for operator default) |
| cluster.spec.dashboard.image.tag | string | `""` | Dashboard image tag (leave empty for operator default) |
| cluster.spec.dashboard.ingress.annotations | object | `{}` | Ingress annotations |
| cluster.spec.dashboard.ingress.enabled | bool | `false` | Enable Ingress for dashboard |
| cluster.spec.dashboard.ingress.hosts | list | `[]` | Ingress hosts |
| cluster.spec.dashboard.ingress.ingressClassName | string | `""` | Ingress class name |
| cluster.spec.dashboard.ingress.tls | list | `[]` | Ingress TLS configuration |
| cluster.spec.dashboard.nodeSelector | object | `{}` | Dashboard node selector |
| cluster.spec.dashboard.podAnnotations | object | `{}` | Dashboard pod annotations |
| cluster.spec.dashboard.podDisruptionBudget.enabled | bool | `false` | Enable PDB for dashboard |
| cluster.spec.dashboard.podDisruptionBudget.maxUnavailable | int | `1` | Maximum unavailable dashboard pods |
| cluster.spec.dashboard.securityContext | object | `{}` | Dashboard pod security context |
| cluster.spec.dashboard.service.annotations | object | `{}` | Dashboard service annotations |
| cluster.spec.dashboard.service.type | string | `""` | Dashboard service type |
| cluster.spec.dashboard.serviceAccount.annotations | object | `{}` | ServiceAccount annotations |
| cluster.spec.dashboard.serviceAccount.create | bool | `false` | Create a dedicated ServiceAccount for dashboard pods |
| cluster.spec.dashboard.serviceAccount.labels | object | `{}` | ServiceAccount labels |
| cluster.spec.dashboard.serviceAccount.name | string | `""` | ServiceAccount name (auto-generated as "{cluster}-dashboard" if empty) |
| cluster.spec.dashboard.terminationGracePeriodSeconds | int | `30` | Dashboard termination grace period (seconds) |
| cluster.spec.dashboard.tolerations | list | `[]` | Dashboard tolerations |
| cluster.spec.dashboard.topologySpreadConstraints | list | `[]` | Dashboard topology spread constraints |
| cluster.spec.dashboard.wazuhPlugin.alertsSamplePrefix | string | `"wazuh-alerts-4.x-"` | Alert sample prefix |
| cluster.spec.dashboard.wazuhPlugin.checks.api | bool | `true` | Check API connection |
| cluster.spec.dashboard.wazuhPlugin.checks.fields | bool | `true` | Check fields |
| cluster.spec.dashboard.wazuhPlugin.checks.maxBuckets | bool | `true` | Check max buckets |
| cluster.spec.dashboard.wazuhPlugin.checks.metaFields | bool | `true` | Check meta fields |
| cluster.spec.dashboard.wazuhPlugin.checks.pattern | bool | `true` | Check index pattern |
| cluster.spec.dashboard.wazuhPlugin.checks.setup | bool | `true` | Check setup |
| cluster.spec.dashboard.wazuhPlugin.checks.template | bool | `true` | Check template |
| cluster.spec.dashboard.wazuhPlugin.checks.timeFilter | bool | `true` | Check time filter |
| cluster.spec.dashboard.wazuhPlugin.cronPrefix | string | `"wazuh"` | Cron job prefix for Wazuh indices |
| cluster.spec.dashboard.wazuhPlugin.cronStatistics.indexCreation | string | `"w"` | Index creation frequency |
| cluster.spec.dashboard.wazuhPlugin.cronStatistics.indexName | string | `"statistics"` | Statistics index name |
| cluster.spec.dashboard.wazuhPlugin.cronStatistics.interval | string | `"0 */5 * * * *"` | Cron schedule expression |
| cluster.spec.dashboard.wazuhPlugin.cronStatistics.replicas | int | `0` | Number of replicas |
| cluster.spec.dashboard.wazuhPlugin.cronStatistics.shards | int | `1` | Number of primary shards |
| cluster.spec.dashboard.wazuhPlugin.cronStatistics.status | bool | `true` | Enable cron statistics |
| cluster.spec.dashboard.wazuhPlugin.enabled | bool | `false` | Enable custom Wazuh plugin configuration |
| cluster.spec.dashboard.wazuhPlugin.hideManagerAlerts | bool | `false` | Hide manager alerts from dashboard |
| cluster.spec.dashboard.wazuhPlugin.ipSelector | bool | `true` | Enable IP selector in the UI |
| cluster.spec.dashboard.wazuhPlugin.monitoring.creation | string | `"w"` | Index creation frequency: "h" (hourly), "d" (daily), "w" (weekly), "m" (monthly) |
| cluster.spec.dashboard.wazuhPlugin.monitoring.enabled | bool | `true` | Enable Wazuh monitoring |
| cluster.spec.dashboard.wazuhPlugin.monitoring.frequency | int | `900` | Monitoring check frequency (seconds) |
| cluster.spec.dashboard.wazuhPlugin.monitoring.pattern | string | `"wazuh-monitoring-*"` | Monitoring index pattern |
| cluster.spec.dashboard.wazuhPlugin.monitoring.replicas | int | `0` | Number of replicas |
| cluster.spec.dashboard.wazuhPlugin.monitoring.shards | int | `1` | Number of primary shards |
| cluster.spec.dashboard.wazuhPlugin.pattern | string | `"wazuh-alerts-*"` | Index pattern for Wazuh alerts |
| cluster.spec.dashboard.wazuhPlugin.timeout | int | `20000` | API timeout in milliseconds |
| cluster.spec.dashboard.wazuhPlugin.updatesDisabled | bool | `false` | Disable update checks |

### TLS Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster.spec.tls.caMaintenance.autoRestart | bool | `false` | Allow automatic restart when CA is renewed (if false, operator waits for manual intervention) |
| cluster.spec.tls.caMaintenance.maintenanceWindows | list | `[]` | Maintenance windows when CA renewal restart is allowed (cron format) |
| cluster.spec.tls.certConfig.adminRenewalThreshold | string | `"30d"` | Renew admin certificates when this much time remains before expiry |
| cluster.spec.tls.certConfig.adminValidity | string | `"365d"` | Admin certificate validity duration (used for OpenSearch security API) |
| cluster.spec.tls.certConfig.caRenewalThreshold | string | `"60d"` | Renew CA certificate when this much time remains before expiry |
| cluster.spec.tls.certConfig.caValidity | string | `"3650d"` | CA certificate validity duration (e.g., "3650d" for 10 years) |
| cluster.spec.tls.certConfig.country | string | `"US"` | Country code (2-letter ISO 3166-1 alpha-2) |
| cluster.spec.tls.certConfig.dashboardRenewalThreshold | string | `"30d"` | Renew dashboard certificates when this much time remains before expiry |
| cluster.spec.tls.certConfig.dashboardValidity | string | `"365d"` | Dashboard certificate validity duration (requires pod restart on renewal) |
| cluster.spec.tls.certConfig.ecdsaCurve | string | `"P256"` | ECDSA curve (only used when keyAlgorithm is "ECDSA"): P256, P384, P521 |
| cluster.spec.tls.certConfig.filebeatRenewalThreshold | string | `"30d"` | Renew filebeat certificates when this much time remains before expiry |
| cluster.spec.tls.certConfig.filebeatValidity | string | `"365d"` | Filebeat certificate validity duration (requires manager pod restart on renewal) |
| cluster.spec.tls.certConfig.indexerRenewalThreshold | string | `"30d"` | Renew indexer node certificates when this much time remains before expiry |
| cluster.spec.tls.certConfig.indexerValidity | string | `"365d"` | Indexer node certificate validity duration |
| cluster.spec.tls.certConfig.keyAlgorithm | string | `"RSA"` | Key algorithm: "RSA" (2048-bit) or "ECDSA" (P-256) |
| cluster.spec.tls.certConfig.locality | string | `"San Francisco"` | Locality (city) |
| cluster.spec.tls.certConfig.organization | string | `"Wazuh"` | Organization name |
| cluster.spec.tls.certConfig.organizationalUnit | string | `"Security"` | Organizational Unit |
| cluster.spec.tls.certConfig.state | string | `"California"` | State or Province |
| cluster.spec.tls.customCerts.adminSecretRef.key | string | `"tls.crt"` | Key in the secret |
| cluster.spec.tls.customCerts.adminSecretRef.name | string | `""` | Secret name containing admin certificates |
| cluster.spec.tls.customCerts.caSecretRef.key | string | `"ca.crt"` | Key in the secret |
| cluster.spec.tls.customCerts.caSecretRef.name | string | `""` | Secret name containing CA certificate |
| cluster.spec.tls.customCerts.enabled | bool | `false` | Enable custom certificates |
| cluster.spec.tls.customCerts.filebeatSecretRef.key | string | `"tls.crt"` | Key in the secret |
| cluster.spec.tls.customCerts.filebeatSecretRef.name | string | `""` | Secret name containing filebeat certificates |
| cluster.spec.tls.customCerts.nodeSecretRef.key | string | `"tls.crt"` | Key in the secret |
| cluster.spec.tls.customCerts.nodeSecretRef.name | string | `""` | Secret name containing node certificates |
| cluster.spec.tls.enabled | bool | `true` | Enable TLS for all components |
| cluster.spec.tls.hotReload.enabled | bool | `true` | Enable hot-reload of TLS certificates |
| cluster.spec.tls.hotReload.forceAPIReload | bool | `false` | Force API reload even for versions supporting automatic reload (OpenSearch >= 2.19) |

### Monitoring Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster.spec.monitoring.enabled | bool | `false` | Enable Prometheus monitoring exporters |
| cluster.spec.monitoring.indexerExporter.enabled | bool | `true` | Enable indexer exporter |
| cluster.spec.monitoring.indexerExporter.version | string | `""` | Indexer exporter version (defaults to OpenSearch version) |
| cluster.spec.monitoring.serviceMonitor.enabled | bool | `false` | Enable ServiceMonitor creation |
| cluster.spec.monitoring.serviceMonitor.interval | string | `"30s"` | Scrape interval |
| cluster.spec.monitoring.serviceMonitor.labels | object | `{}` | Additional labels for ServiceMonitor |
| cluster.spec.monitoring.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout |
| cluster.spec.monitoring.wazuhExporter.apiProtocol | string | `"https"` | API protocol for connecting to Wazuh API |
| cluster.spec.monitoring.wazuhExporter.apiVerifySSL | bool | `true` | Verify SSL when connecting to Wazuh API (false skips TLS verification) |
| cluster.spec.monitoring.wazuhExporter.cacheTTL | string | `""` | Metrics cache TTL (keep >= Prometheus scrape interval), e.g. "30s" |
| cluster.spec.monitoring.wazuhExporter.enabled | bool | `true` | Enable Wazuh exporter |
| cluster.spec.monitoring.wazuhExporter.image | string | `"ghcr.io/maximewewer/wazuh-prometheus-exporter:latest"` | Wazuh exporter image |
| cluster.spec.monitoring.wazuhExporter.logLevel | string | `"info"` | Exporter log level (trace, debug, info, warn, error) |
| cluster.spec.monitoring.wazuhExporter.port | int | `9555` | Wazuh exporter metrics port |
| cluster.spec.monitoring.wazuhExporter.startupGrace | string | `"60s"` | Quiet-startup window (WAZUH_STARTUP_GRACE): collection failures log as    warn instead of error until the first success, letting a slow Wazuh API    boot without noise. 0 (off) to 10m. |

### Drain Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster.spec.drain.dryRun | bool | `false` | Dry run mode (simulate drain without executing) |
| cluster.spec.drain.indexer.enabled | bool | `false` | Enable indexer drain on scale-down |
| cluster.spec.drain.indexer.healthCheckInterval | string | `"10s"` | Health check interval during drain |
| cluster.spec.drain.indexer.minGreenHealthTimeout | string | `"5m"` | Minimum time cluster must be green before completing drain |
| cluster.spec.drain.indexer.timeout | string | `"30m"` | Drain timeout |
| cluster.spec.drain.manager.enabled | bool | `false` | Enable manager drain on scale-down |
| cluster.spec.drain.manager.gracePeriod | string | `"30s"` | Grace period before drain |
| cluster.spec.drain.manager.queueCheckInterval | string | `"5s"` | Queue check interval during drain |
| cluster.spec.drain.manager.timeout | string | `"15m"` | Drain timeout |
| cluster.spec.drain.retry.backoffMultiplier | string | `"2.0"` | Backoff multiplier for retry delays |
| cluster.spec.drain.retry.initialDelay | string | `"5m"` | Initial delay between retries |
| cluster.spec.drain.retry.maxAttempts | int | `3` | Maximum retry attempts |
| cluster.spec.drain.retry.maxDelay | string | `"30m"` | Maximum delay between retries |

### OpenSearchSnapshotRepository

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchRepository.enabled | bool | `false` | Enable OpenSearchSnapshotRepository CRD creation |

### OpenSearchSnapshotPolicy

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchSnapshotPolicy.enabled | bool | `false` | Enable OpenSearchSnapshotPolicy CRD creation |

### WazuhBackup

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| wazuhBackup.enabled | bool | `false` | Enable WazuhBackup CRD creation |

### Backup Credentials

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| backupCredentials.enabled | bool | `false` | Enable backup credentials Secret creation |

### OpenSearchUser

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchUsers | list | `[]` | OpenSearch users to create |

### OpenSearchRole

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchRoles | list | `[]` | OpenSearch roles to create |

### OpenSearchRoleMapping

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchRoleMappings | list | `[]` | OpenSearch role mappings to create |

### OpenSearchTenant

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchTenants | list | `[]` | OpenSearch tenants to create |

### OpenSearchActionGroup

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchActionGroups | list | `[]` | OpenSearch action groups to create |

### OpenSearchAuthConfig

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchAuthConfig.enabled | bool | `false` | Enable OpenSearchAuthConfig CRD creation |

### OpenSearchIndex

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchIndices | list | `[]` | OpenSearch indices to create |

### OpenSearchIndexTemplate

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchIndexTemplates | list | `[]` | OpenSearch index templates to create |

### OpenSearchComponentTemplate

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchComponentTemplates | list | `[]` | OpenSearch component templates to create |

### OpenSearchISMPolicy

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchISMPolicies | list | `[]` | OpenSearch ISM policies to create |

### OpenSearchSnapshot

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchSnapshots | list | `[]` | OpenSearch snapshots to create |

### OpenSearchRestore

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| opensearchRestores | list | `[]` | OpenSearch restores to create |

### WazuhRule

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| wazuhRules | list | `[]` | Wazuh custom rules to create |

### WazuhDecoder

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| wazuhDecoders | list | `[]` | Wazuh custom decoders to create |

### WazuhAgentGroup

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| wazuhAgentGroups | list | `[]` | Wazuh agent groups to create |

### WazuhRestore

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| wazuhRestore.enabled | bool | `false` | Enable WazuhRestore CRD creation |

### Network Policy Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| networkPolicy.dashboard.additionalEgress | list | `[]` |  |
| networkPolicy.dashboard.ingressFrom | list | `[]` | Custom ingress rules (default: allow all on port 5601) |
| networkPolicy.enabled | bool | `false` | Enable NetworkPolicies for cluster components |
| networkPolicy.indexer.additionalEgress | list | `[]` | Additional egress rules for indexer (e.g., for S3 backups) |
| networkPolicy.indexer.additionalIngress | list | `[]` | Additional ingress rules for indexer |
| networkPolicy.manager.additionalEgress | list | `[]` |  |
| networkPolicy.manager.additionalIngress | list | `[]` |  |
| networkPolicy.manager.agentCIDRs | list | `[]` | Restrict agent connections to specific CIDRs (empty = all) |
| networkPolicy.manager.allowAgentConnections | bool | `true` | Allow agent connections from outside the cluster |
| networkPolicy.operatorNamespace | string | `"wazuh-operator"` | Operator namespace (for allowing operator access) |

### Resource Quota Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| resourceQuota.configmaps | string | `"50"` | Maximum ConfigMaps in namespace |
| resourceQuota.enabled | bool | `false` | Enable ResourceQuota and LimitRange |
| resourceQuota.limitRange.default.cpu | string | `"1"` |  |
| resourceQuota.limitRange.default.memory | string | `"2Gi"` |  |
| resourceQuota.limitRange.defaultRequest.cpu | string | `"100m"` |  |
| resourceQuota.limitRange.defaultRequest.memory | string | `"256Mi"` |  |
| resourceQuota.limitRange.max.cpu | string | `"16"` |  |
| resourceQuota.limitRange.max.memory | string | `"32Gi"` |  |
| resourceQuota.limitRange.pvcMax | string | `"500Gi"` | Maximum PVC size |
| resourceQuota.limitRange.pvcMin | string | `"1Gi"` | Minimum PVC size |
| resourceQuota.limits.cpu | string | `"40"` | Total CPU limits |
| resourceQuota.limits.memory | string | `"80Gi"` | Total memory limits |
| resourceQuota.persistentvolumeclaims | string | `"20"` | Maximum PVCs in namespace |
| resourceQuota.pods | string | `"25"` | Maximum pods (adjust based on sizing profile: XS=10, S=15, M=25, L=40, XL=60) |
| resourceQuota.requests.cpu | string | `"20"` | Total CPU requests limit |
| resourceQuota.requests.memory | string | `"40Gi"` | Total memory requests limit |
| resourceQuota.requests.storage | string | `"500Gi"` | Total storage requests limit |
| resourceQuota.secrets | string | `"50"` | Maximum Secrets in namespace |
| resourceQuota.services | string | `"20"` | Maximum Services in namespace |

## Examples

### Minimal Deployment

```yaml
sizing:
  profile: S

secrets:
  wazuhApi:
    password: "MySecurePassword123!"
  indexerAdmin:
    password: "MySecurePassword456!"
  wazuhAuthd:
    password: "MySecurePassword789!"
```

### Production with External Secrets (Vault)

```yaml
sizing:
  profile: L

# Disable inline secrets
secrets:
  wazuhApi:
    password: ""
  indexerAdmin:
    password: ""

# Use External Secrets Operator
externalSecrets:
  enabled: true
  indexerAdmin:
    name: wazuh-indexer-credentials
    secretStoreRef:
      name: vault-backend
      kind: SecretStore
    remoteRef:
      key: secret/data/wazuh/indexer
  wazuhApi:
    name: wazuh-api-credentials
    secretStoreRef:
      name: vault-backend
      kind: SecretStore
    remoteRef:
      key: secret/data/wazuh/api
```

### HPA and High Availability

```yaml
sizing:
  profile: L

cluster:
  spec:
    indexer:
      antiAffinity:
        enabled: true
        type: required
        topologyKey: topology.kubernetes.io/zone
    manager:
      workers:
        hpa:
          enabled: true
          minReplicas: 2
          maxReplicas: 10
          targetCPUUtilizationPercentage: 80
    dashboard:
      hpa:
        enabled: true
        minReplicas: 2
        maxReplicas: 5
```

### Gateway API Configuration

```yaml
cluster:
  spec:
    dashboard:
      gatewayAPI:
        enabled: true
        gatewayRef:
          name: wazuh-gateway
          namespace: gateway-system
        hostnames:
          - dashboard.wazuh.example.com
        http:
          pathPrefix: /
    manager:
      workers:
        gatewayAPI:
          enabled: true
          gatewayRef:
            name: wazuh-gateway
          tcp:
            enabled: true
            enrollmentEnabled: true
            eventsEnabled: true
```

### Ingress Configuration

```yaml
cluster:
  spec:
    dashboard:
      ingress:
        enabled: true
        ingressClassName: nginx
        hosts:
          - host: dashboard.wazuh.example.com
            paths:
              - path: /
                pathType: Prefix
        tls:
          - secretName: dashboard-tls
            hosts:
              - dashboard.wazuh.example.com
    indexer:
      ingress:
        enabled: true
        ingressClassName: nginx
        annotations:
          nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
        hosts:
          - host: indexer.wazuh.example.com
            paths:
              - path: /
                pathType: Prefix
    manager:
      master:
        ingress:
          enabled: true
          ingressClassName: nginx
          hosts:
            - host: manager.wazuh.example.com
              paths:
                - path: /
                  pathType: Prefix
      workers:
        ingress:
          enabled: true
          ingressClassName: nginx
          hosts:
            - host: manager-workers.wazuh.example.com
              paths:
                - path: /
                  pathType: Prefix
```

> **Note:** Ingress and Gateway API cannot both be enabled for the same component.

## Security Considerations

**IMPORTANT**: The default passwords in this chart are for demonstration purposes only.

For production use, you **MUST**:

1. Change all default passwords
2. Use External Secrets Operator for credential management
3. Enable TLS for all communications
4. Review and apply appropriate RBAC policies
5. Enable anti-affinity for high availability
6. Configure network policies

## Support

- GitHub Issues: <https://github.com/MaximeWewer/wazuh-operator/issues>
- Documentation: <https://documentation.wazuh.com/>
