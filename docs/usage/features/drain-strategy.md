# Drain Strategy for Safe Scale-Down

The Wazuh Operator provides a comprehensive drain strategy for safely scaling down StatefulSets. This ensures data integrity and service continuity during maintenance operations.

## Overview

When scaling down a Wazuh cluster, the operator performs safe drain operations:

1. **Indexer Scale-Down**: Relocates OpenSearch shards from nodes being removed
2. **Manager Scale-Down**: Drains event queues before removing worker nodes
3. **Dashboard Protection**: PodDisruptionBudget prevents complete service disruption

## Configuration

### Basic Drain Configuration

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: my-cluster
spec:
  drain:
    # Enable dry-run mode to preview changes
    dryRun: false

    # Indexer drain settings
    indexer:
      timeout: 30m
      healthCheckInterval: 10s
      minGreenHealthTimeout: 5m

    # Manager drain settings
    manager:
      timeout: 15m
      queueCheckInterval: 5s
      gracePeriod: 30s

    # Retry settings for failed operations
    retry:
      maxAttempts: 3
      initialDelay: 5m
      backoffMultiplier: 2.0
      maxDelay: 30m
```

### Indexer Drain Configuration

| Field                   | Default | Description                               |
| ----------------------- | ------- | ----------------------------------------- |
| `timeout`               | 30m     | Maximum time to wait for shard relocation |
| `healthCheckInterval`   | 10s     | Interval between shard status checks      |
| `minGreenHealthTimeout` | 5m      | Wait time for cluster green health        |

### Manager Drain Configuration

| Field                | Default | Description                          |
| -------------------- | ------- | ------------------------------------ |
| `timeout`            | 15m     | Maximum time to wait for queue drain |
| `queueCheckInterval` | 5s      | Interval between queue depth checks  |
| `gracePeriod`        | 30s     | Wait time after queue is empty       |

### Retry Configuration

| Field               | Default | Description                             |
| ------------------- | ------- | --------------------------------------- |
| `maxAttempts`       | 3       | Maximum retry attempts before giving up |
| `initialDelay`      | 5m      | Initial delay before first retry        |
| `backoffMultiplier` | 2.0     | Exponential backoff factor              |
| `maxDelay`          | 30m     | Maximum delay between retries           |

## Indexer Drain Process

When reducing indexer replicas, the operator:

1. **Detects Scale-Down**: Identifies when replicas decrease from current state
2. **Sets Allocation Exclusion**: Configures OpenSearch to exclude target nodes from shard allocation
3. **Monitors Relocation**: Tracks shard movement to remaining nodes
4. **Verifies Completion**: Ensures no shards remain on excluded nodes
5. **Allows Pod Removal**: StatefulSet can safely remove the pod

### Example: Scale from 3 to 2 Indexers

```yaml
# Before
spec:
  indexer:
    replicas: 3

# After (triggers drain)
spec:
  indexer:
    replicas: 2
```

The operator will:

1. Mark `indexer-2` for exclusion from shard allocation
2. Wait for all shards to relocate from `indexer-2`
3. Allow the StatefulSet to terminate `indexer-2`

## Manager Drain Process

When reducing manager worker replicas, the operator:

1. **Detects Scale-Down**: Identifies when worker replicas decrease
2. **Initiates Graceful Shutdown**: Signals the worker to stop accepting new events
3. **Monitors Queue**: Tracks pending events in worker queues
4. **Verifies Empty Queue**: Ensures all events are processed
5. **Applies Grace Period**: Waits for any in-flight processing
6. **Allows Pod Removal**: StatefulSet can safely remove the worker

### Example: Scale from 2 to 1 Workers

```yaml
# Before
spec:
  manager:
    worker:
      replicas: 2

# After (triggers drain)
spec:
  manager:
    worker:
      replicas: 1
```

## Dashboard PDB Protection

The operator creates a PodDisruptionBudget for Dashboard pods to prevent complete service disruption during voluntary disruptions (node drains, upgrades).

### Configuration

```yaml
spec:
  dashboard:
    replicas: 2
    podDisruptionBudget:
      enabled: true
      minAvailable: 1
```

### Behavior

- **Default**: PDB is created automatically when dashboard is configured
- **minAvailable**: Ensures at least 1 dashboard pod remains available
- **Disable**: Set `enabled: false` to disable PDB creation

## Dry-Run Mode

Preview the feasibility of scale-down operations before committing:

```yaml
spec:
  drain:
    dryRun: true
```

### Dry-Run Results

Results are reported in the cluster status:

```yaml
status:
  drain:
    dryRun:
      feasible: true
      evaluatedAt: "2025-01-15T10:30:00Z"
      indexerResult:
        canDrain: true
        shardsToRelocate: 10
        estimatedTime: "5m"
      managerResult:
        canDrain: true
        queueDepth: 1500
        estimatedTime: "2m"
      dashboardResult:
        canDrain: true
        pdbSatisfied: true
```

### Dry-Run Events

Kubernetes events are emitted with dry-run results:

```bash
kubectl get events -n wazuh --field-selector reason=DryRunResult
```

## Monitoring

### Prometheus Metrics

| Metric                         | Type      | Description                      |
| ------------------------------ | --------- | -------------------------------- |
| `wazuh_drain_operations_total` | Counter   | Total drain operations by result |
| `wazuh_drain_duration_seconds` | Histogram | Drain operation duration         |
| `wazuh_drain_in_progress`      | Gauge     | Whether drain is active          |
| `wazuh_drain_progress_percent` | Gauge     | Current drain progress (0-100)   |
| `wazuh_drain_phase`            | Gauge     | Current drain phase (numeric)    |
| `wazuh_drain_rollbacks_total`  | Counter   | Total rollback operations        |
| `wazuh_drain_retries_total`    | Counter   | Total retry operations           |
| `wazuh_indexer_shard_count`    | Gauge     | Shards per indexer node          |
| `wazuh_manager_queue_depth`    | Gauge     | Queue depth per manager          |

### Kubernetes Events

The operator emits events at each stage:

| Event            | Description                  |
| ---------------- | ---------------------------- |
| `DrainStarted`   | Drain operation initiated    |
| `DrainProgress`  | Progress milestone reached   |
| `DrainCompleted` | Drain completed successfully |
| `DrainFailed`    | Drain operation failed       |
| `DrainRollback`  | Rollback initiated           |
| `DrainRetry`     | Retry scheduled              |
| `DryRunResult`   | Dry-run evaluation completed |

## Automatic Rollback and Retry

### Rollback Behavior

If a drain operation fails:

1. **Immediate Rollback**: Restores replica count to previous value
2. **Clear Exclusions**: Removes any OpenSearch allocation exclusions
3. **Event Emission**: Reports rollback in Kubernetes events
4. **Status Update**: Updates cluster status with failure details

### Retry Behavior

After rollback, the operator schedules retries:

1. **Exponential Backoff**: Delay increases with each attempt
2. **Maximum Attempts**: Stops after configured max attempts
3. **Status Tracking**: Reports retry count and next retry time

### Example Status During Retry

```yaml
status:
  drain:
    indexer:
      phase: Pending
      retryCount: 2
      lastFailure: "timeout waiting for shard relocation"
      nextRetryAt: "2025-01-15T10:45:00Z"
```

## Troubleshooting

### Drain Stuck

If drain is taking too long:

1. Check OpenSearch cluster health: `GET _cluster/health`
2. Check shard allocation status: `GET _cat/shards?v`
3. Verify node exclusion settings: `GET _cluster/settings`
4. Check operator logs for errors

### Rollback Triggered

If rollbacks keep occurring:

1. Check cluster capacity (can remaining nodes hold all shards?)
2. Verify network connectivity between nodes
3. Check for disk space issues
4. Review OpenSearch logs for errors

### PDB Blocking Operations

If cluster operations are blocked by PDB:

1. Check PDB status: `kubectl get pdb -n wazuh`
2. Verify dashboard pod health
3. Temporarily disable PDB if needed for maintenance

## Best Practices

1. **Use Dry-Run First**: Always test with dry-run before production changes
2. **Scale Gradually**: Reduce replicas one at a time for large clusters
3. **Monitor During Operations**: Watch metrics and events during scale-down
4. **Ensure Sufficient Capacity**: Remaining nodes must handle all data
5. **Plan for Retries**: Configure appropriate retry settings for your environment
