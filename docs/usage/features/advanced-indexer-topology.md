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
apiVersion: resources.wazuh.com/v1alpha1
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
apiVersion: resources.wazuh.com/v1alpha1
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

## Migration Considerations

**Important**: Transitioning between simple and advanced mode is not supported. If you need to change modes:

1. Back up your data
2. Create a new cluster with the desired topology
3. Restore data to the new cluster
4. Update applications to point to the new cluster
5. Decommission the old cluster

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
