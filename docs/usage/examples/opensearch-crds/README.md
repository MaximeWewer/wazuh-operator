# OpenSearch CRD Examples

This directory contains examples for managing OpenSearch security and index lifecycle through Kubernetes CRDs.

## Available CRDs

| CRD                     | Description                   | Example                                    |
| ----------------------- | ----------------------------- | ------------------------------------------ |
| OpenSearchUser          | Manage internal users         | [user.yaml](./user.yaml)                   |
| OpenSearchRole          | Define roles with permissions | [role.yaml](./role.yaml)                   |
| OpenSearchRoleMapping   | Map roles to users            | [rolemapping.yaml](./rolemapping.yaml)     |
| OpenSearchIndexTemplate | Index templates               | [indextemplate.yaml](./indextemplate.yaml) |
| OpenSearchISMPolicy     | Index State Management        | [ismpolicy.yaml](./ismpolicy.yaml)         |

## Prerequisites

- A running WazuhCluster with an accessible indexer
- The operator must have connectivity to the OpenSearch cluster

## Usage Examples

### Create a Read-Only User

1. Create the user:

```bash
kubectl apply -f user.yaml
```

2. Create a role with read permissions:

```bash
kubectl apply -f role.yaml
```

3. Map the role to the user:

```bash
kubectl apply -f rolemapping.yaml
```

### Set Up Index Lifecycle Management

1. Create an ISM policy:

```bash
kubectl apply -f ismpolicy.yaml
```

2. Create an index template that uses the policy:

```bash
kubectl apply -f indextemplate.yaml
```

## Verifying Resources

```bash
# Check CRD status
kubectl get opensearchusers,opensearchroles,opensearchrolemappings -n wazuh

# Verify in OpenSearch (from indexer pod)
kubectl exec -it wazuh-cluster-indexer-0 -n wazuh -- \
  curl -k -u admin:$PASSWORD https://localhost:9200/_plugins/_security/api/internalusers
```

## Cleanup

```bash
# Delete all OpenSearch CRDs
kubectl delete opensearchusers,opensearchroles,opensearchrolemappings --all -n wazuh
```

## Additional CRDs

See [config/samples/](../../../config/samples/) for more OpenSearch CRD examples:

- `opensearch_v1alpha1_tenant.yaml` - Multi-tenancy
- `opensearch_v1alpha1_snapshotpolicy.yaml` - Automated backups
- `opensearch_v1alpha1_componenttemplate.yaml` - Reusable template components
- `opensearch_v1alpha1_actiongroup.yaml` - Permission groups
