# Wazuh API RBAC Examples

Manage Wazuh Manager API access with `WazuhRole`, `WazuhUser`, and external-IdP
role mapping.

| File | Kind | Description |
| ---- | ---- | ----------- |
| [wazuhrole-admin.yaml](wazuhrole-admin.yaml) | WazuhRole | Full-access API role (`wazuh-api-admin`) |
| [wazuhrole-viewer.yaml](wazuhrole-viewer.yaml) | WazuhRole | Read-only API role (`wazuh-api-viewer`) |
| [wazuhuser-basic.yaml](wazuhuser-basic.yaml) | WazuhUser | Internal API user (`api-automation`) |
| [rbac-external-idp.yaml](rbac-external-idp.yaml) | Secret + RBAC | Map an external OIDC identity to Wazuh API roles |

## Usage

```bash
kubectl apply -f wazuhrole-admin.yaml
kubectl apply -f wazuhuser-basic.yaml
```

## Related Documentation

- [Wazuh API RBAC](../../features/wazuh-api-rbac.md)
