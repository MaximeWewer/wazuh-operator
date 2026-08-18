# Wazuh Content Examples

Declarative Wazuh Manager content: detection rules, log decoders, CDB lists,
active response scripts, agent groups and custom integrations. These CRDs target
one or more clusters via `spec.clusterRefs`; the operator mounts the content into
the manager pods and injects the matching `ossec.conf` blocks. See the
[Detection Content guide](../../features/detection-content.md) for the full model.

| File | Kind | Description |
| ---- | ---- | ----------- |
| [wazuhrule-basic.yaml](wazuhrule-basic.yaml) | WazuhRule | Custom SSH brute-force detection rule |
| [wazuhdecoder-basic.yaml](wazuhdecoder-basic.yaml) | WazuhDecoder | Custom JSON log decoder |
| [wazuhcdblist-static.yaml](wazuhcdblist-static.yaml) | WazuhCDBList | Static key/value list (malicious domains) |
| [wazuhcdblist-url-iplist.yaml](wazuhcdblist-url-iplist.yaml) | WazuhCDBList | IP block list fetched from a URL (`iplist` converter) |
| [wazuhcdblist-url-keylist.yaml](wazuhcdblist-url-keylist.yaml) | WazuhCDBList | MD5 hash list fetched from a URL (`keylist` + `skipLines`) |
| [wazuhactiveresponse-firewall-drop.yaml](wazuhactiveresponse-firewall-drop.yaml) | WazuhActiveResponse | Firewall-drop stateful active response |
| [wazuhagentgroup-basic.yaml](wazuhagentgroup-basic.yaml) | WazuhAgentGroup | Agent group (`linux-servers`) |
| [wazuhagentgroupassignment-basic.yaml](wazuhagentgroupassignment-basic.yaml) | WazuhAgentGroupAssignment | Authoritative agent-to-group assignment by name/OS (union), with optional exclusion and restrictive OS filter |
| [wazuhintegration-basic.yaml](wazuhintegration-basic.yaml) | Secret + WazuhIntegration | Integration with an external API (Slack) |

## Related Documentation

- [Detection Content guide](../../features/detection-content.md)
- [CRD Reference](../../CRD-REFERENCE.md)
