# Filebeat Configuration CRD

This guide covers the WazuhFilebeat CRD for managing Filebeat configuration in your Wazuh deployment.

## Overview

The `WazuhFilebeat` CRD provides declarative management of Filebeat configuration, including:

- `filebeat.yml` configuration
- `wazuh-template.json` (OpenSearch index template)
- `pipeline.json` (ingest pipeline with GeoIP enrichment)

| CRD             | Short Name | Purpose                       |
| --------------- | ---------- | ----------------------------- |
| `WazuhFilebeat` | `wfb`      | Manage Filebeat configuration |

## WazuhFilebeat

Configure Filebeat for shipping Wazuh alerts and archives to OpenSearch.

### Spec Reference

| Field        | Type                                            | Required | Description                     |
| ------------ | ----------------------------------------------- | -------- | ------------------------------- |
| `clusterRef` | [WazuhClusterReference](#wazuhclusterreference) | Yes      | Reference to the WazuhCluster   |
| `alerts`     | [AlertsConfig](#alertsconfig)                   | No       | Alerts module configuration     |
| `archives`   | [ArchivesConfig](#archivesconfig)               | No       | Archives module configuration   |
| `template`   | [TemplateConfig](#templateconfig)               | No       | Index template configuration    |
| `pipeline`   | [PipelineConfig](#pipelineconfig)               | No       | Ingest pipeline configuration   |
| `logging`    | [LoggingConfig](#loggingconfig)                 | No       | Filebeat logging settings       |
| `ssl`        | [SSLConfig](#sslconfig)                         | No       | SSL/TLS settings                |
| `output`     | [OutputConfig](#outputconfig)                   | No       | OpenSearch output configuration |

#### WazuhClusterReference

| Field       | Type   | Required | Description                          |
| ----------- | ------ | -------- | ------------------------------------ |
| `name`      | string | Yes      | Name of the WazuhCluster             |
| `namespace` | string | No       | Namespace (defaults to CR namespace) |

#### AlertsConfig

| Field     | Type | Default | Description                    |
| --------- | ---- | ------- | ------------------------------ |
| `enabled` | bool | `true`  | Enable/disable alerts shipping |

#### ArchivesConfig

| Field     | Type | Default | Description                      |
| --------- | ---- | ------- | -------------------------------- |
| `enabled` | bool | `false` | Enable/disable archives shipping |

#### TemplateConfig

| Field                | Type                                          | Default | Description                               |
| -------------------- | --------------------------------------------- | ------- | ----------------------------------------- |
| `shards`             | int32                                         | `3`     | Number of primary shards (1-100)          |
| `replicas`           | int32                                         | `0`     | Number of replica shards (0-10)           |
| `refreshInterval`    | string                                        | `5s`    | Index refresh interval                    |
| `fieldLimit`         | int32                                         | `10000` | Maximum fields per document (1000-100000) |
| `customTemplateRef`  | [ConfigMapKeySelector](#configmapkeyselector) | -       | Custom template from ConfigMap            |
| `additionalMappings` | object                                        | -       | Custom field mappings (raw JSON)          |

#### PipelineConfig

| Field                    | Type                                          | Default            | Description                        |
| ------------------------ | --------------------------------------------- | ------------------ | ---------------------------------- |
| `geoipEnabled`           | bool                                          | `true`             | Enable GeoIP enrichment processors |
| `indexPrefix`            | string                                        | `wazuh-alerts-4.x` | Index name prefix                  |
| `additionalRemoveFields` | []string                                      | -                  | Additional fields to remove        |
| `timestampFormat`        | string                                        | `ISO8601`          | Timestamp parsing format           |
| `customPipelineRef`      | [ConfigMapKeySelector](#configmapkeyselector) | -                  | Custom pipeline from ConfigMap     |

#### LoggingConfig

| Field       | Type   | Default | Description                                    |
| ----------- | ------ | ------- | ---------------------------------------------- |
| `level`     | string | `info`  | Log level: `debug`, `info`, `warning`, `error` |
| `toFiles`   | bool   | `true`  | Enable logging to files                        |
| `keepFiles` | int32  | `7`     | Number of log files to retain (1-100)          |

#### SSLConfig

| Field                 | Type                          | Default | Description                      |
| --------------------- | ----------------------------- | ------- | -------------------------------- |
| `verificationMode`    | string                        | `full`  | `full`, `certificate`, or `none` |
| `caCertSecretRef`     | [SecretKeyRef](#secretkeyref) | -       | CA certificate secret reference  |
| `clientCertSecretRef` | [SecretKeyRef](#secretkeyref) | -       | Client certificate secret        |
| `clientKeySecretRef`  | [SecretKeyRef](#secretkeyref) | -       | Client key secret                |

#### OutputConfig

| Field                  | Type                 | Default | Description                  |
| ---------------------- | -------------------- | ------- | ---------------------------- |
| `hosts`                | []string             | -       | OpenSearch host list         |
| `credentialsSecretRef` | CredentialsSecretRef | -       | Credentials secret reference |
| `protocol`             | string               | `https` | `http` or `https`            |
| `port`                 | int32                | `9200`  | OpenSearch port (1-65535)    |

#### ConfigMapKeySelector

| Field  | Type   | Required | Description          |
| ------ | ------ | -------- | -------------------- |
| `name` | string | Yes      | ConfigMap name       |
| `key`  | string | Yes      | Key in the ConfigMap |

#### SecretKeyRef

| Field  | Type   | Required | Description       |
| ------ | ------ | -------- | ----------------- |
| `name` | string | Yes      | Secret name       |
| `key`  | string | Yes      | Key in the Secret |

### Status

| Field                | Type        | Description                              |
| -------------------- | ----------- | ---------------------------------------- |
| `phase`              | string      | `Pending`, `Ready`, `Failed`, `Updating` |
| `conditions`         | []Condition | Standard Kubernetes conditions           |
| `configMapRef`       | object      | Reference to generated ConfigMap         |
| `lastAppliedTime`    | Time        | When config was last applied             |
| `observedGeneration` | int64       | Last observed generation                 |
| `message`            | string      | Additional status information            |
| `templateVersion`    | string      | Applied template version                 |
| `pipelineVersion`    | string      | Applied pipeline version                 |
| `configHash`         | string      | Hash of current configuration            |

## Examples

### Basic Configuration

Minimal configuration with default settings:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhFilebeat
metadata:
  name: wazuh-filebeat
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-test
    namespace: wazuh
  alerts:
    enabled: true
  archives:
    enabled: false
  logging:
    level: info
    keepFiles: 7
  ssl:
    verificationMode: full
```

### Advanced Configuration

Configuration with custom template and pipeline settings:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhFilebeat
metadata:
  name: wazuh-filebeat-advanced
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-test
    namespace: wazuh
  alerts:
    enabled: true
  archives:
    enabled: true
  template:
    shards: 5
    replicas: 1
    refreshInterval: "10s"
    fieldLimit: 15000
  pipeline:
    geoipEnabled: true
    indexPrefix: "wazuh-alerts-4.x"
    additionalRemoveFields:
      - "custom_debug_field"
      - "internal_metadata"
    timestampFormat: "ISO8601"
  logging:
    level: debug
    keepFiles: 14
  ssl:
    verificationMode: full
```

### Custom Template from ConfigMap

Using a fully custom template and pipeline from ConfigMaps:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhFilebeat
metadata:
  name: wazuh-filebeat-custom
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh-test
    namespace: wazuh
  alerts:
    enabled: true
  template:
    customTemplateRef:
      name: custom-wazuh-template
      key: wazuh-template.json
  pipeline:
    customPipelineRef:
      name: custom-wazuh-pipeline
      key: pipeline.json
  logging:
    level: info
    keepFiles: 7
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: custom-wazuh-template
  namespace: wazuh
data:
  wazuh-template.json: |
    {
      "order": 1,
      "index_patterns": ["wazuh-alerts-4.x-*"],
      "settings": {
        "index.refresh_interval": "5s",
        "index.number_of_shards": "3",
        "index.number_of_replicas": "1"
      },
      "mappings": {
        "dynamic_templates": [
          {
            "string_as_keyword": {
              "match_mapping_type": "string",
              "mapping": { "type": "keyword" }
            }
          }
        ],
        "properties": {
          "@timestamp": { "type": "date" },
          "agent": {
            "properties": {
              "id": { "type": "keyword" },
              "name": { "type": "keyword" }
            }
          }
        }
      }
    }
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: custom-wazuh-pipeline
  namespace: wazuh
data:
  pipeline.json: |
    {
      "description": "Custom Wazuh alerts pipeline",
      "processors": [
        {
          "json": {
            "field": "message",
            "add_to_root": true
          }
        },
        {
          "date": {
            "field": "timestamp",
            "target_field": "@timestamp",
            "formats": ["ISO8601"]
          }
        },
        {
          "remove": {
            "field": ["message"],
            "ignore_missing": true
          }
        }
      ]
    }
```

## How It Works

1. **Create WazuhFilebeat CR**: Define your Filebeat configuration
2. **Operator generates ConfigMap**: The operator creates a ConfigMap with:
   - `filebeat.yml`: Filebeat configuration
   - `wazuh-template.json`: Index template for OpenSearch
   - `pipeline.json`: Ingest pipeline definition
3. **Manager pods mount ConfigMap**: The WazuhCluster reconciler automatically mounts the generated ConfigMap to Manager pods
4. **Rolling updates**: Changes to WazuhFilebeat trigger rolling updates via ConfigMap hash annotation

## Monitoring Status

Check the status of your WazuhFilebeat configuration:

```bash
# List all WazuhFilebeat resources
kubectl get wazuhfilebeats -n wazuh

# Describe a specific WazuhFilebeat
kubectl describe wazuhfilebeat wazuh-filebeat -n wazuh

# Check the generated ConfigMap
kubectl get configmap -n wazuh -l app.kubernetes.io/component=filebeat
```

## Troubleshooting

### WazuhFilebeat stuck in Pending

1. Check the WazuhCluster exists and is Ready:

   ```bash
   kubectl get wazuhcluster -n wazuh
   ```

2. Check the WazuhFilebeat events:
   ```bash
   kubectl describe wazuhfilebeat wazuh-filebeat -n wazuh
   ```

### ConfigMap not being created

1. Check operator logs:

   ```bash
   kubectl logs -n wazuh-system deploy/wazuh-operator-controller-manager
   ```

2. Verify RBAC permissions for ConfigMaps

### Custom template/pipeline not applied

1. Verify the referenced ConfigMap exists:

   ```bash
   kubectl get configmap custom-wazuh-template -n wazuh
   ```

2. Check the key name matches exactly

3. Validate JSON syntax in the ConfigMap data
