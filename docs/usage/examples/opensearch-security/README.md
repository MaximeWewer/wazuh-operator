# OpenSearch Security Examples

Manage OpenSearch security: users, roles, role mappings, tenants, action groups
and authentication backends. For index/ISM management, see
[../opensearch-index/](../opensearch-index/).

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

## Usage

```bash
# Read-only access: create role, user, then map them
kubectl apply -f opensearchrole-wazuh-viewer.yaml
kubectl apply -f opensearchuser-basic.yaml
kubectl apply -f opensearchrolemapping-wazuh-viewer.yaml
```

## Related Documentation

- [OpenSearch Security](../../features/opensearch-security.md)
