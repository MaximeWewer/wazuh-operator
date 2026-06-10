# OpenSearch CRD Examples

Manage OpenSearch security and index lifecycle through Kubernetes CRDs.

## Prerequisites

- A running `WazuhCluster` with an accessible indexer
- The operator must have connectivity to the OpenSearch cluster

## Security

| File | Kind | Description |
| ---- | ---- | ----------- |
| [opensearchuser-basic.yaml](opensearchuser-basic.yaml) | OpenSearchUser | Internal user |
| [opensearchrole-basic.yaml](opensearchrole-basic.yaml) | OpenSearchRole | Role with permissions |
| [opensearchrole-wazuh-admin.yaml](opensearchrole-wazuh-admin.yaml) | OpenSearchRole | Wazuh admin role |
| [opensearchrole-wazuh-viewer.yaml](opensearchrole-wazuh-viewer.yaml) | OpenSearchRole | Wazuh read-only role |
| [opensearchrolemapping-basic.yaml](opensearchrolemapping-basic.yaml) | OpenSearchRoleMapping | Map a role to users/backend roles |
| [opensearchrolemapping-wazuh-admin.yaml](opensearchrolemapping-wazuh-admin.yaml) | OpenSearchRoleMapping | Mapping for the admin role |
| [opensearchrolemapping-wazuh-viewer.yaml](opensearchrolemapping-wazuh-viewer.yaml) | OpenSearchRoleMapping | Mapping for the viewer role |
| [opensearchtenant-basic.yaml](opensearchtenant-basic.yaml) | OpenSearchTenant | Dashboards multi-tenancy |
| [opensearchactiongroup-basic.yaml](opensearchactiongroup-basic.yaml) | OpenSearchActionGroup | Reusable permission group |
| [opensearchauthconfig-basic.yaml](opensearchauthconfig-basic.yaml) | OpenSearchAuthConfig | Authentication backend config |

## Index Management

| File | Kind | Description |
| ---- | ---- | ----------- |
| [opensearchindex-basic.yaml](opensearchindex-basic.yaml) | OpenSearchIndex | Managed index |
| [opensearchindextemplate-basic.yaml](opensearchindextemplate-basic.yaml) | OpenSearchIndexTemplate | Index template |
| [opensearchcomponenttemplate-basic.yaml](opensearchcomponenttemplate-basic.yaml) | OpenSearchComponentTemplate | Reusable template component |
| [opensearchismpolicy-basic.yaml](opensearchismpolicy-basic.yaml) | OpenSearchISMPolicy | Index State Management policy |

## Usage

```bash
# Read-only user: create role, user, then map them
kubectl apply -f opensearchrole-wazuh-viewer.yaml
kubectl apply -f opensearchuser-basic.yaml
kubectl apply -f opensearchrolemapping-wazuh-viewer.yaml

# Index lifecycle: ISM policy + index template that references it
kubectl apply -f opensearchismpolicy-basic.yaml
kubectl apply -f opensearchindextemplate-basic.yaml
```

## Verifying Resources

```bash
kubectl get opensearchusers,opensearchroles,opensearchrolemappings -n wazuh

# From the indexer pod
kubectl exec -it wazuh-cluster-indexer-0 -n wazuh -- \
  curl -k -u admin:$PASSWORD https://localhost:9200/_plugins/_security/api/internalusers
```

## Cleanup

```bash
kubectl delete opensearchusers,opensearchroles,opensearchrolemappings --all -n wazuh
```

## Related Documentation

- [OpenSearch Security](../../features/opensearch-security.md)
- [OpenSearch Indices](../../features/opensearch-indices.md)
