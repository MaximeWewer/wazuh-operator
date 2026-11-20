# Advanced Indexer Topology

The Wazuh Operator supports advanced OpenSearch indexer topology with dedicated node roles, allowing you to deploy production-grade clusters with specialized nodes for different workloads.

## Overview

OpenSearch clusters can operate in two modes:

| Mode         | Configuration            | Use Case                                                   |
| ------------ | ------------------------ | ---------------------------------------------------------- |
| **Simple**   | `spec.indexer.replicas`  | Small to medium deployments where all nodes have all roles |
| **Advanced** | `spec.indexer.nodePools` | Large deployments requiring dedicated node roles           |

## When to Use Advanced Mode

### Use Simple Mode When

- Cluster size is 1-5 nodes
- Workload is relatively uniform
- You want simpler management
- Resource constraints don't require specialization

### Use Advanced Mode When

- Cluster size exceeds 5 nodes
- You need dedicated cluster_manager nodes for stability
- Hot/warm/cold data tiers are required
- Different storage classes are needed per node type
- You want to isolate query coordination from data processing

## Node Roles

OpenSearch 2.x supports the following node roles:

| Role                    | Description                                                                         |
| ----------------------- | ----------------------------------------------------------------------------------- |
| `cluster_manager`       | Manages cluster state, node membership, and shard allocation (minimum 3 for quorum) |
| `data`                  | Stores data and executes search/indexing operations                                 |
| `ingest`                | Pre-processes documents before indexing (parsing, enrichment)                       |
| `search`                | Dedicated search nodes, reduces load on data nodes                                  |
| `ml`                    | Machine learning workloads                                                          |
| `remote_cluster_client` | Cross-cluster search capabilities                                                   |
| `coordinating_only`     | Routes requests to data nodes, aggregates results (no data storage)                 |

## Configuration

### Simple Mode Example

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.14.1"
  indexer:
    replicas: 3 # All nodes have all roles
```

### Advanced Mode Example

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.14.1"
  indexer:
    nodePools:
      # Dedicated cluster_manager nodes (minimum 3 for quorum)
      - name: masters
        replicas: 3
        roles:
          - cluster_manager
        resources:
          requests:
            cpu: "500m"
            memory: "2Gi"
          limits:
            cpu: "1"
            memory: "4Gi"
        storageSize: "10Gi"
        storageClass: "standard"

      # Data nodes
      - name: data
        replicas: 5
        roles:
          - data
          - ingest
        resources:
          requests:
            cpu: "2"
            memory: "8Gi"
          limits:
            cpu: "4"
            memory: "16Gi"
        storageSize: "500Gi"
        storageClass: "fast-ssd"

      # Coordinating nodes for query routing
      - name: coord
        replicas: 2
        roles:
          - coordinating_only
        resources:
          requests:
            cpu: "1"
            memory: "4Gi"
          limits:
            cpu: "2"
            memory: "8Gi"
        storageSize: "10Gi"
```

## Shard Allocation Awareness

Use node attributes to configure shard allocation awareness for hot/warm/cold data tiers or availability zones:

### Hot/Warm/Cold Tiers

```yaml
nodePools:
  - name: data-hot
    replicas: 3
    roles:
      - data
      - ingest
    attributes:
      temp: hot
    storageClass: "fast-nvme"
    storageSize: "500Gi"

  - name: data-warm
    replicas: 3
    roles:
      - data
    attributes:
      temp: warm
    storageClass: "standard-ssd"
    storageSize: "2Ti"

  - name: data-cold
    replicas: 2
    roles:
      - data
    attributes:
      temp: cold
    storageClass: "archive-hdd"
    storageSize: "10Ti"
```

The attributes are rendered as `node.attr.<key>: <value>` in opensearch.yml, enabling:

- Index Lifecycle Management (ILM) policies
- Shard routing based on data temperature
- Zone-aware shard allocation

### Availability Zone Awareness

```yaml
nodePools:
  - name: data-az1
    replicas: 2
    roles:
      - data
    attributes:
      zone: us-east-1a
    nodeSelector:
      topology.kubernetes.io/zone: us-east-1a

  - name: data-az2
    replicas: 2
    roles:
      - data
    attributes:
      zone: us-east-1b
    nodeSelector:
      topology.kubernetes.io/zone: us-east-1b
```

## Per-NodePool Storage Configuration

Each nodePool can have its own storage configuration:

```yaml
nodePools:
  - name: masters
    replicas: 3
    roles: [cluster_manager]
    storageSize: "10Gi"
    storageClass: "standard" # Low IOPS, high durability

  - name: data
    replicas: 5
    roles: [data]
    storageSize: "1Ti"
    storageClass: "fast-ssd" # High IOPS for indexing
```

## Safe Scale-Down with Drain

When scaling down data nodePools, the operator integrates with the drain strategy to safely relocate shards before terminating pods.

### Enable Drain for Scale-Down

```yaml
spec:
  drain:
    indexer:
      enabled: true
      timeout: 30m
      healthCheckInterval: 10s
```

### Scale-Down Behavior

1. **Data nodes**: Shards are relocated to other nodes before pod termination
2. **Cluster_manager nodes**: Quorum is validated before scale-down (minimum 3 nodes maintained)
3. **Coordinating nodes**: No drain needed (no shards stored)

### Example: Scaling Down Data Nodes

```bash
# Original configuration
nodePools:
  - name: data
    replicas: 5

# After update to replicas: 3
# 1. Operator detects scale-down (5 -> 3)
# 2. Allocations exclusion is set for data-3 and data-4
# 3. Shards relocate to remaining nodes
# 4. Once complete, StatefulSet is updated
# 5. Pods data-3 and data-4 are terminated
```

## Validation Rules

The operator validates nodePool configurations:

| Rule                   | Description                                                |
| ---------------------- | ---------------------------------------------------------- |
| Mode Exclusivity       | Cannot set both `replicas` and `nodePools`                 |
| Cluster Manager Quorum | Minimum 3 cluster_manager nodes required                   |
| Data Node Minimum      | At least 1 data node required                              |
| Unique Names           | NodePool names must be unique                              |
| Valid Roles            | Only valid OpenSearch roles accepted                       |
| Name Format            | DNS-compatible names (lowercase alphanumeric with hyphens) |

## Sizing Guidelines

### Small Deployment (< 100 agents)

Use simple mode:

```yaml
indexer:
  replicas: 3
```

### Medium Deployment (100-500 agents)

```yaml
nodePools:
  - name: masters
    replicas: 3
    roles: [cluster_manager, data]
    storageSize: "100Gi"
```

### Large Deployment (500-2000 agents)

```yaml
nodePools:
  - name: masters
    replicas: 3
    roles: [cluster_manager]
    storageSize: "20Gi"
  - name: data
    replicas: 5
    roles: [data, ingest]
    storageSize: "500Gi"
```

### Enterprise Deployment (2000+ agents)

```yaml
nodePools:
  - name: masters
    replicas: 5
    roles: [cluster_manager]
    storageSize: "20Gi"
  - name: data-hot
    replicas: 5
    roles: [data, ingest]
    attributes: { temp: hot }
    storageSize: "1Ti"
    storageClass: "fast-nvme"
  - name: data-warm
    replicas: 3
    roles: [data]
    attributes: { temp: warm }
    storageSize: "5Ti"
    storageClass: "standard-ssd"
  - name: coord
    replicas: 3
    roles: [coordinating_only]
    storageSize: "10Gi"
```

## Monitoring NodePools

NodePool status is available in the cluster status:

```yaml
status:
  indexer:
    topologyMode: advanced
    nodePoolStatuses:
      masters:
        phase: Running
        readyReplicas: 3
        replicas: 3
      data:
        phase: Running
        readyReplicas: 5
        replicas: 5
      coord:
        phase: Running
        readyReplicas: 2
        replicas: 2
```

## Removing a NodePool

Removing a pool from `spec.indexer.nodePools` does not delete its nodes right away: their data is moved to the remaining pools first.

1. Preflight: the cluster must be green, the remaining data nodes must hold all the data within 80% of their `storageSize`, and offer enough data nodes for every index's replicas. While a check fails, the pool keeps running, nothing is moved, and a `NodePoolRemovalBlocked` warning event says why.
2. The pool's nodes are excluded from shard allocation, and its cluster_manager nodes from voting (`NodePoolDraining` event). A `NodePoolDrainStalled` warning is raised when shards are left and none is moving (disk watermarks, allocation filters).
3. Once they hold no shard and the cluster is green, the StatefulSet is scaled down (`NodePoolDrained`).
4. Once its pods are gone, the StatefulSet, headless Service and ConfigMap are deleted and the exclusions lifted (`NodePoolDeleted`). The PVCs are kept: delete them when their data is no longer needed.

## Migrating Between Simple and Advanced Mode

Switching `spec.indexer` between `replicas` and `nodePools` migrates the running cluster in place, in either direction, without downtime and without a snapshot: the new nodes join the existing OpenSearch cluster and OpenSearch moves the shards to them.

```yaml
# Before: simple mode
spec:
  indexer:
    replicas: 1
    storageSize: 50Gi

# After: replace replicas by nodePools
spec:
  indexer:
    nodePools:
      - name: hot
        replicas: 3
        roles: [cluster_manager, data, ingest]
        storageSize: 100Gi
```

The operator then runs these phases, reported in `status.indexerMigration` (and as events on the WazuhCluster):

| Phase | What happens |
|-------|--------------|
| `Blocked` | Preflight checks run; **nothing is changed** while one fails. The failures are in `status.indexerMigration.message` and a `IndexerMigrationBlocked` warning event, and are checked again every 30 seconds |
| `Joining` | The new StatefulSets are created. Their nodes join the running cluster: they have no `cluster.initial_master_nodes` and use the cluster-wide headless Service as seed host |
| `TransferringClusterManager` | The old cluster_manager nodes are excluded from voting (`_cluster/voting_config_exclusions`), so a new node is elected and the quorum survives their removal |
| `Draining` | The old nodes are excluded from shard allocation (`cluster.routing.allocation.exclude._name`) and their shards relocate to the new nodes |
| `Removing` | Once the old nodes hold no shard and the cluster is green, their StatefulSets are scaled down |
| `Completed` | The old StatefulSets (and old nodePool Services/ConfigMaps) are deleted and the exclusions lifted |

```bash
kubectl get wazuhcluster <name> -o jsonpath='{.status.indexerMigration}' | jq
kubectl get events --field-selector involvedObject.name=<name> | grep IndexerMigration
```

### Preflight checks

The migration starts only when all of these pass:

- The old StatefulSets have all their pods ready, and every running indexer pod belongs to the cluster the operator reaches (nodes that bootstrapped a separate cluster are refused).
- The cluster is green, with no relocating, initializing or unassigned shard.
- The new topology declares at least one data node and one cluster_manager node.
- **Disk**: all the data, replicas included, fits within 80% of the new data nodes' `storageSize` (below OpenSearch's default 85% low disk watermark), and the largest shard fits on one new data node.
- Every index's `number_of_replicas` (indices without `auto_expand_replicas`) can be placed: replicas + 1 ≤ new data nodes.
- No index has an `index.routing.allocation.require` or `include` filter, which the new nodes may not match and which would stop the drain.
- No voting configuration exclusion and no `cluster.routing.allocation.exclude._name` is set, and `cluster.routing.allocation.enable` allows allocation.

### Rolling back

Switching `spec.indexer` back during a migration reverses it: the exclusions are lifted, and a migration back to the declared topology starts (with its own preflight checks). Data is never removed before it has been moved: until `Removing`, the old nodes still hold every shard they have not handed over.

### After the migration

- The volumes (PVCs) of the removed nodes are kept. Delete them once their data is no longer needed.
- Existing indices are spread over all the data nodes. To place them on `hot`/`warm` pools, set node attributes on the pools and an ISM policy that sets `index.routing.allocation.require.<attribute>` (see [Shard Allocation Awareness](#shard-allocation-awareness)).
- The nodes created by the migration keep their "join" configuration (ConfigMap annotation `wazuh.com/indexer-join-existing-cluster`), so the end of the migration does not restart them.
- During the migration the indexer certificate covers the pods of both topologies.

## Troubleshooting

### Common Issues

**Issue**: NodePool stuck in Creating phase

- Check pod events: `kubectl describe pod <cluster>-indexer-<pool>-0`
- Verify storage class exists
- Check resource quotas

**Issue**: Cluster health yellow after scale-down

- Verify replica count allows proper shard distribution
- Check if drain completed successfully
- Review allocation exclusion settings

**Issue**: Validation error "replicas and nodePools are mutually exclusive"

- Remove either `spec.indexer.replicas` or `spec.indexer.nodePools`
- Cannot use both configurations simultaneously

### Debug Commands

```bash
# Check nodePool StatefulSets
kubectl get sts -l wazuh.com/component=indexer

# View OpenSearch cluster health
kubectl exec <cluster>-indexer-<pool>-0 -- curl -k https://localhost:9200/_cluster/health

# Check shard allocation
kubectl exec <cluster>-indexer-<pool>-0 -- curl -k https://localhost:9200/_cat/shards

# View allocation settings
kubectl exec <cluster>-indexer-<pool>-0 -- curl -k https://localhost:9200/_cluster/settings
```

## Related Documentation

- [Drain Strategy](drain-strategy.md) - Safe scale-down operations
- [Volume Expansion](volume-expansion.md) - Storage management
- [Sizing Guide](sizing.md) - Resource recommendations
