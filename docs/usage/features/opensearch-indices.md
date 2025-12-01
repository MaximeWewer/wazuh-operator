# OpenSearch Index Management CRDs

This guide covers CRDs for managing OpenSearch indices, templates, and lifecycle policies.

## Overview

| CRD                           | Short Name | Purpose                           |
| ----------------------------- | ---------- | --------------------------------- |
| `OpenSearchIndex`             | `osidx`    | Create and manage indices         |
| `OpenSearchIndexTemplate`     | `osidxt`   | Index templates for auto-creation |
| `OpenSearchComponentTemplate` | `osct`     | Reusable template components      |
| `OpenSearchISMPolicy`         | `osism`    | Index State Management policies   |
| `OpenSearchSnapshotPolicy`    | `ossnap`   | Backup/snapshot policies          |

## OpenSearchIndex

Create and manage individual indices.

### Spec Reference

| Field             | Type     | Required | Description       |
| ----------------- | -------- | -------- | ----------------- |
| `clusterRef.name` | string   | Yes      | WazuhCluster name |
| `settings`        | object   | No       | Index settings    |
| `mappings`        | object   | No       | Field mappings    |
| `aliases`         | []object | No       | Index aliases     |

#### Settings

| Field              | Type   | Default | Description                     |
| ------------------ | ------ | ------- | ------------------------------- |
| `numberOfShards`   | int    | 1       | Primary shards                  |
| `numberOfReplicas` | int    | 1       | Replica shards                  |
| `refreshInterval`  | string | -       | Refresh interval (e.g., "5s")   |
| `codec`            | string | -       | `default` or `best_compression` |
| `custom`           | object | -       | Additional raw settings         |

#### Mappings

| Field              | Type   | Description                  |
| ------------------ | ------ | ---------------------------- |
| `properties`       | object | Field definitions (raw JSON) |
| `dynamic`          | string | `true`, `false`, or `strict` |
| `dateDetection`    | bool   | Auto-detect dates            |
| `numericDetection` | bool   | Auto-detect numbers          |

### Examples

#### Basic Index

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchIndex
metadata:
  name: custom-logs
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  settings:
    numberOfShards: 3
    numberOfReplicas: 1
    refreshInterval: "5s"
```

#### Index with Mappings

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchIndex
metadata:
  name: application-events
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  settings:
    numberOfShards: 2
    numberOfReplicas: 1
    codec: best_compression
  mappings:
    dynamic: "strict"
    properties:
      timestamp:
        type: date
      level:
        type: keyword
      message:
        type: text
      service:
        type: keyword
      trace_id:
        type: keyword
```

#### Index with Aliases

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchIndex
metadata:
  name: logs-2024-01
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  settings:
    numberOfShards: 3
    numberOfReplicas: 1
  aliases:
    - name: logs-current
      isWriteIndex: true
    - name: logs-all
    - name: logs-filtered
      filter:
        term:
          level: "error"
```

### Status Fields

```bash
kubectl get osidx -n wazuh
```

| Field           | Description                     |
| --------------- | ------------------------------- |
| `health`        | Index health (green/yellow/red) |
| `docsCount`     | Number of documents             |
| `storageSize`   | Total storage size              |
| `primaryShards` | Number of primary shards        |
| `replicaShards` | Number of replica shards        |

## OpenSearchIndexTemplate

Define templates for automatic index creation.

### Spec Reference

| Field             | Type     | Required | Description                    |
| ----------------- | -------- | -------- | ------------------------------ |
| `clusterRef.name` | string   | Yes      | WazuhCluster name              |
| `indexPatterns`   | []string | Yes      | Patterns to match              |
| `template`        | object   | No       | Template definition            |
| `composedOf`      | []string | No       | Component templates to include |
| `priority`        | int      | No       | Template priority              |
| `version`         | int      | No       | Template version               |
| `dataStream`      | object   | No       | Data stream configuration      |

### Examples

#### Basic Template

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchIndexTemplate
metadata:
  name: logs-template
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  indexPatterns:
    - "logs-*"
  priority: 100
  template:
    settings:
      numberOfShards: 2
      numberOfReplicas: 1
      refreshInterval: "10s"
    mappings:
      properties:
        "@timestamp":
          type: date
        message:
          type: text
```

#### Template with Component Templates

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchIndexTemplate
metadata:
  name: wazuh-custom-template
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  indexPatterns:
    - "wazuh-custom-*"
  composedOf:
    - base-settings
    - wazuh-mappings
  priority: 200
  template:
    settings:
      numberOfShards: 3
    aliases:
      wazuh-custom-all: {}
```

#### Data Stream Template

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchIndexTemplate
metadata:
  name: metrics-stream
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  indexPatterns:
    - "metrics-*"
  dataStream:
    timestampField:
      name: "@timestamp"
    hidden: false
  template:
    settings:
      numberOfShards: 1
      numberOfReplicas: 1
```

## OpenSearchComponentTemplate

Create reusable template components.

### Spec Reference

| Field             | Type   | Required | Description         |
| ----------------- | ------ | -------- | ------------------- |
| `clusterRef.name` | string | Yes      | WazuhCluster name   |
| `template`        | object | Yes      | Template definition |
| `version`         | int    | No       | Component version   |
| `_meta`           | object | No       | Metadata            |

### Examples

#### Settings Component

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchComponentTemplate
metadata:
  name: base-settings
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  template:
    settings:
      numberOfShards: 2
      numberOfReplicas: 1
      codec: best_compression
      index.mapping.total_fields.limit: 2000
```

#### Mappings Component

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchComponentTemplate
metadata:
  name: wazuh-mappings
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  template:
    mappings:
      properties:
        "@timestamp":
          type: date
        agent:
          properties:
            id:
              type: keyword
            name:
              type: keyword
            ip:
              type: ip
        rule:
          properties:
            id:
              type: keyword
            description:
              type: text
            level:
              type: integer
```

## OpenSearchISMPolicy

Index State Management policies for lifecycle management.

### Spec Reference

| Field             | Type     | Required | Description           |
| ----------------- | -------- | -------- | --------------------- |
| `clusterRef.name` | string   | Yes      | WazuhCluster name     |
| `description`     | string   | No       | Policy description    |
| `defaultState`    | string   | Yes      | Initial state name    |
| `states`          | []object | Yes      | State definitions     |
| `ismTemplate`     | []object | No       | Auto-apply to indices |

#### State

| Field         | Type     | Description        |
| ------------- | -------- | ------------------ |
| `name`        | string   | State name         |
| `actions`     | []object | Actions to perform |
| `transitions` | []object | State transitions  |

#### Action

| Field     | Type   | Description                     |
| --------- | ------ | ------------------------------- |
| `config`  | object | Action configuration (raw JSON) |
| `timeout` | string | Action timeout                  |
| `retry`   | object | Retry configuration             |

#### Transition

| Field        | Type   | Description           |
| ------------ | ------ | --------------------- |
| `stateName`  | string | Target state          |
| `conditions` | object | Transition conditions |

#### Transition Conditions

| Field         | Type   | Description            |
| ------------- | ------ | ---------------------- |
| `minIndexAge` | string | Minimum index age      |
| `minDocCount` | int    | Minimum document count |
| `minSize`     | string | Minimum index size     |
| `cron`        | object | CRON schedule          |

### Examples

#### Basic Retention Policy

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchISMPolicy
metadata:
  name: wazuh-retention-30d
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  description: "Delete Wazuh indices after 30 days"
  defaultState: hot
  states:
    - name: hot
      transitions:
        - stateName: delete
          conditions:
            minIndexAge: "30d"
    - name: delete
      actions:
        - config:
            delete: {}
  ismTemplate:
    - indexPatterns:
        - "wazuh-alerts-*"
      priority: 100
```

#### Hot-Warm-Cold Policy

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchISMPolicy
metadata:
  name: wazuh-tiered-storage
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  description: "Move data through storage tiers"
  defaultState: hot
  states:
    - name: hot
      actions:
        - config:
            rollover:
              minIndexAge: "1d"
              minSize: "50gb"
      transitions:
        - stateName: warm
          conditions:
            minIndexAge: "7d"
    - name: warm
      actions:
        - config:
            replicaCount:
              numberOfReplicas: 1
        - config:
            indexPriority:
              priority: 50
      transitions:
        - stateName: cold
          conditions:
            minIndexAge: "30d"
    - name: cold
      actions:
        - config:
            replicaCount:
              numberOfReplicas: 0
        - config:
            indexPriority:
              priority: 0
      transitions:
        - stateName: delete
          conditions:
            minIndexAge: "90d"
    - name: delete
      actions:
        - config:
            delete: {}
  ismTemplate:
    - indexPatterns:
        - "wazuh-alerts-*"
        - "wazuh-archives-*"
      priority: 100
```

#### Force Merge Policy

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchISMPolicy
metadata:
  name: optimize-indices
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  defaultState: open
  states:
    - name: open
      transitions:
        - stateName: force_merge
          conditions:
            minIndexAge: "1d"
    - name: force_merge
      actions:
        - config:
            forceMerge:
              maxNumSegments: 1
          timeout: "24h"
          retry:
            count: 3
            backoff: exponential
            delay: "1h"
      transitions:
        - stateName: readonly
          conditions:
            minIndexAge: "2d"
    - name: readonly
      actions:
        - config:
            readOnly: {}
```

### Available Actions

| Action          | Purpose                 |
| --------------- | ----------------------- |
| `delete`        | Delete the index        |
| `rollover`      | Roll over to new index  |
| `readOnly`      | Set index to read-only  |
| `readWrite`     | Set index to read-write |
| `replicaCount`  | Change replica count    |
| `forceMerge`    | Merge segments          |
| `shrink`        | Reduce shard count      |
| `indexPriority` | Set recovery priority   |
| `close`         | Close the index         |
| `open`          | Open the index          |
| `snapshot`      | Take a snapshot         |
| `allocation`    | Change allocation rules |

## OpenSearchSnapshotPolicy

Automated backup policies.

### Spec Reference

| Field             | Type   | Required | Description            |
| ----------------- | ------ | -------- | ---------------------- |
| `clusterRef.name` | string | Yes      | WazuhCluster name      |
| `description`     | string | No       | Policy description     |
| `enabled`         | bool   | No       | Enable/disable policy  |
| `snapshotConfig`  | object | Yes      | Snapshot configuration |
| `schedule`        | object | Yes      | Execution schedule     |
| `retention`       | object | No       | Retention settings     |

### Example

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchSnapshotPolicy
metadata:
  name: daily-backup
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  description: "Daily snapshot of all indices"
  enabled: true
  snapshotConfig:
    repository: wazuh-backups
    indices: "wazuh-*"
    ignoreUnavailable: true
    includeGlobalState: false
    partial: false
  schedule:
    cron:
      expression: "0 0 * * *"
      timezone: "UTC"
  retention:
    expireAfter: "30d"
    minCount: 7
    maxCount: 30
```

## Common Operations

### List All Index Resources

```bash
# Indices
kubectl get osidx -n wazuh

# Templates
kubectl get osidxt -n wazuh

# ISM Policies
kubectl get osism -n wazuh
```

### Check ISM Policy Status

```bash
kubectl get osism -n wazuh

# Output:
NAME                    CLUSTER   DEFAULT STATE   PHASE   DRIFT   AGE
wazuh-retention-30d     wazuh     hot             Ready   false   5d
wazuh-tiered-storage    wazuh     hot             Ready   false   3d
```

### Debug Index Issues

```bash
# Check index health
kubectl get osidx -n wazuh

# Get detailed status
kubectl describe osidx custom-logs -n wazuh

# View in OpenSearch
kubectl exec -n wazuh wazuh-indexer-0 -- \
  curl -sk -u admin:$PASSWORD https://localhost:9200/_cat/indices?v
```

## See Also

- [OpenSearch Security CRDs](opensearch-security.md)
- [Monitoring Guide](monitoring.md)
- [CRD Reference](../CRD-REFERENCE.md)
