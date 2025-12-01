# Config Samples

This directory contains sample CRD manifests for **development and testing** of the Wazuh Operator.

## Purpose

These samples are used with `kustomize` for:

- Local development testing
- CI/CD pipelines
- Integration tests

## Usage

```bash
# Apply all samples (development)
kubectl apply -k config/samples/

# Apply specific sample
kubectl apply -f config/samples/wazuh_v1alpha1_wazuhcluster_minimal.yaml
```

## User Documentation

For production-ready examples and documentation, see:

- [Quick Start Examples](../../docs/usage/examples/quick-start/)
- [Production Examples](../../docs/usage/examples/production/)
- [OpenSearch CRDs Examples](../../docs/usage/examples/opensearch-crds/)

## Available Samples

### WazuhCluster

- `wazuh_v1alpha1_wazuhcluster_minimal.yaml` - Minimal cluster for development
- `wazuh_v1alpha1_wazuhcluster_authd_password.yaml` - With agent enrollment
- `wazuh_v1alpha1_wazuhcluster_monitoring.yaml` - With Prometheus monitoring
- `wazuh_v1alpha1_wazuhcluster_tls.yaml` - With TLS configuration

### OpenSearch Security

- `opensearch_v1alpha1_user.yaml` - Custom user
- `opensearch_v1alpha1_role.yaml` - Custom role
- `opensearch_v1alpha1_rolemapping.yaml` - Role mapping
- `opensearch_v1alpha1_tenant.yaml` - Multi-tenancy
- `opensearch_v1alpha1_actiongroup.yaml` - Action groups

### OpenSearch Index Management

- `opensearch_v1alpha1_indextemplate.yaml` - Index template
- `opensearch_v1alpha1_ismpolicy.yaml` - ISM policy
- `opensearch_v1alpha1_index.yaml` - Custom index
- `opensearch_v1alpha1_componenttemplate.yaml` - Component template
- `opensearch_v1alpha1_snapshotpolicy.yaml` - Snapshot policy

### OpenSearch Authentication

- `opensearch_v1alpha1_authconfig_basic.yaml` - Basic auth configuration

### Wazuh Configuration

- `wazuh_v1alpha1_rule.yaml` - Custom detection rule
- `wazuh_v1alpha1_decoder.yaml` - Custom log decoder
