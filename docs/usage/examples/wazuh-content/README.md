# Wazuh Content Examples

Declarative Wazuh Manager content: detection rules, log decoders, agent groups
and custom integrations. These CRDs target one or more clusters via
`spec.clusterRefs`.

| File | Kind | Description |
| ---- | ---- | ----------- |
| [wazuhrule-basic.yaml](wazuhrule-basic.yaml) | WazuhRule | Custom SSH brute-force detection rule |
| [wazuhdecoder-basic.yaml](wazuhdecoder-basic.yaml) | WazuhDecoder | Custom JSON log decoder |
| [wazuhagentgroup-basic.yaml](wazuhagentgroup-basic.yaml) | WazuhAgentGroup | Agent group (`linux-servers`) |
| [wazuhintegration-basic.yaml](wazuhintegration-basic.yaml) | Secret + WazuhIntegration | Integration with an external API (Slack) |

## Related Documentation

- [CRD Reference](../../CRD-REFERENCE.md)
