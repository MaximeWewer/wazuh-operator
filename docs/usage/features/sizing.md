# Cluster Sizing Profiles

This guide explains the predefined sizing profiles for Wazuh clusters.

## Overview

The Wazuh Operator Helm chart provides predefined sizing profiles for quick deployment. These profiles configure:

- **Indexer**: OpenSearch nodes for data storage and search
- **Manager**: Wazuh Manager master and workers for agent management
- **Dashboard**: Web interface for visualization

## Available Profiles

### XS (Extra Small) - Testing Only

Minimal profile for testing purposes only. **Not recommended for production.**

| Component | Replicas | CPU (req/lim) | Memory (req/lim) | Storage |
|-----------|----------|---------------|------------------|---------|
| Indexer | 1 | 200m / 1 | 1.5Gi / 2Gi | 10Gi |
| Manager Master | 1 | 100m / 500m | 256Mi / 512Mi | 5Gi |
| Manager Workers | 0 | - | - | - |
| Dashboard | 1 | 100m / 500m | 256Mi / 512Mi | - |

**Total Resources:**
- CPU: ~400m requests, ~2 cores limits
- Memory: ~2Gi requests, ~3Gi limits
- Storage: ~15Gi

**Use case:** Local development, CI/CD pipelines, quick testing

```bash
helm install wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=XS \
  --namespace wazuh --create-namespace
```

### S (Small) - Development/Test

Suitable for development environments and small test deployments.

| Component | Replicas | CPU (req/lim) | Memory (req/lim) | Storage |
|-----------|----------|---------------|------------------|---------|
| Indexer | 1 | 500m / 1 | 1Gi / 2Gi | 20Gi |
| Manager Master | 1 | 500m / 1 | 1Gi / 2Gi | 10Gi |
| Manager Workers | 1 | 500m / 1 | 1Gi / 2Gi | 10Gi |
| Dashboard | 1 | 250m / 500m | 512Mi / 1Gi | - |

**Total Resources:**
- CPU: ~1.75 cores requests, ~3.5 cores limits
- Memory: ~3.5Gi requests, ~7Gi limits
- Storage: ~40Gi

**Use case:** Development teams, small labs, up to 50 agents

```bash
helm install wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=S \
  --namespace wazuh --create-namespace
```

### M (Medium) - Small Production

Balanced profile for small production environments with high availability.

| Component | Replicas | CPU (req/lim) | Memory (req/lim) | Storage |
|-----------|----------|---------------|------------------|---------|
| Indexer | 3 | 2 / 4 | 4Gi / 8Gi | 50Gi |
| Manager Master | 1 | 1 / 2 | 2Gi / 4Gi | 20Gi |
| Manager Workers | 2 | 1 / 2 | 2Gi / 4Gi | 20Gi |
| Dashboard | 1 | 500m / 1 | 1Gi / 2Gi | - |

**Total Resources:**
- CPU: ~9.5 cores requests, ~19 cores limits
- Memory: ~19Gi requests, ~38Gi limits
- Storage: ~210Gi

**Use case:** Small production, 50-500 agents, requires 3+ node cluster

```bash
helm install wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=M \
  --namespace wazuh --create-namespace
```

### L (Large) - Production

High-capacity profile for production environments with high availability.

| Component | Replicas | CPU (req/lim) | Memory (req/lim) | Storage |
|-----------|----------|---------------|------------------|---------|
| Indexer | 3 | 4 / 8 | 8Gi / 16Gi | 100Gi |
| Manager Master | 1 | 2 / 4 | 4Gi / 8Gi | 50Gi |
| Manager Workers | 3 | 2 / 4 | 4Gi / 8Gi | 50Gi |
| Dashboard | 2 | 1 / 2 | 2Gi / 4Gi | - |

**Total Resources:**
- CPU: ~22 cores requests, ~44 cores limits
- Memory: ~44Gi requests, ~88Gi limits
- Storage: ~500Gi

**Use case:** Production environments, 500-5000 agents, requires 5+ node cluster

```bash
helm install wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=L \
  --namespace wazuh --create-namespace
```

### XL (Extra Large) - Enterprise

Enterprise-grade profile for large-scale deployments.

| Component | Replicas | CPU (req/lim) | Memory (req/lim) | Storage |
|-----------|----------|---------------|------------------|---------|
| Indexer | 5 | 8 / 16 | 16Gi / 32Gi | 200Gi |
| Manager Master | 1 | 4 / 8 | 8Gi / 16Gi | 100Gi |
| Manager Workers | 5 | 4 / 8 | 8Gi / 16Gi | 100Gi |
| Dashboard | 3 | 2 / 4 | 4Gi / 8Gi | - |

**Total Resources:**
- CPU: ~70 cores requests, ~140 cores limits
- Memory: ~140Gi requests, ~280Gi limits
- Storage: ~1700Gi

**Use case:** Enterprise deployments, 5000+ agents, requires 10+ node cluster

```bash
helm install wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=XL \
  --namespace wazuh --create-namespace
```

## Profile Comparison

| Profile | Indexer | Workers | Dashboard | Total CPU | Total Memory | Total Storage | Max Agents |
|---------|---------|---------|-----------|-----------|--------------|---------------|------------|
| XS | 1 | 0 | 1 | ~2 cores | ~3Gi | ~15Gi | Testing |
| S | 1 | 1 | 1 | ~3.5 cores | ~7Gi | ~40Gi | ~50 |
| M | 3 | 2 | 1 | ~19 cores | ~38Gi | ~210Gi | ~500 |
| L | 3 | 3 | 2 | ~44 cores | ~88Gi | ~500Gi | ~5000 |
| XL | 5 | 5 | 3 | ~140 cores | ~280Gi | ~1700Gi | 5000+ |

## Customizing Profiles

Profiles provide defaults that can be overridden. Custom values take precedence:

```yaml
# values.yaml
sizing:
  profile: M
  storageClassName: fast-ssd  # Custom storage class

cluster:
  spec:
    indexer:
      replicas: 5  # Override M profile's 3 replicas
      storageSize: 100Gi  # Override M profile's 50Gi
```

### Custom Storage Class

```bash
helm install wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=M \
  --set sizing.storageClassName=gp3 \
  --namespace wazuh --create-namespace
```

### Override Specific Values

```bash
helm install wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=M \
  --set cluster.spec.indexer.replicas=5 \
  --set cluster.spec.indexer.storageSize=100Gi \
  --namespace wazuh --create-namespace
```

## Without Profiles

You can skip profiles entirely and specify all values manually:

```yaml
# values.yaml - No profile
sizing:
  profile: ""  # Empty = no profile

cluster:
  spec:
    indexer:
      replicas: 3
      storageSize: 50Gi
      resources:
        requests:
          cpu: 2
          memory: 4Gi
        limits:
          cpu: 4
          memory: 8Gi
    manager:
      master:
        storageSize: 20Gi
        resources:
          requests:
            cpu: 1
            memory: 2Gi
      workers:
        replicas: 2
        storageSize: 20Gi
    dashboard:
      replicas: 1
      resources:
        requests:
          cpu: 500m
          memory: 1Gi
```

## Capacity Planning

### Storage Considerations

- **Indexer**: ~2-5GB per day per 100 agents (varies by log volume)
- **Manager**: ~1GB per 100 agents for state/rules
- Retention policies affect storage needs significantly

### Memory Considerations

- OpenSearch (Indexer) requires ~50% of memory for JVM heap
- Wazuh Manager memory scales with active agent connections
- Dashboard memory is relatively constant

### CPU Considerations

- Indexer CPU scales with search/indexing load
- Manager CPU scales with agent count and rule complexity
- Dashboard CPU is relatively constant

## Recommendations

| Environment | Profile | Notes |
|-------------|---------|-------|
| Local dev | XS | Single node, minimal resources |
| CI/CD testing | XS | Quick spin-up, tear-down |
| Dev team shared | S | Multiple developers |
| Staging | M | Production-like testing |
| Small production | M | Up to 500 agents |
| Production | L | Up to 5000 agents |
| Enterprise | XL | Large scale, HA required |

## See Also

- [Quick Start Guide](../getting-started/quick-start.md)
- [Production Examples](../examples/production/)
- [CRD Reference](../CRD-REFERENCE.md)
