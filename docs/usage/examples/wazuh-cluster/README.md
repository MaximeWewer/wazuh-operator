# Wazuh Cluster Examples

`WazuhCluster` variations showing individual features, plus samples of the
cluster-scoped content CRDs (agent groups, decoders, integrations, rules).

| File | Kind | Description |
| ---- | ---- | ----------- |
| [wazuhcluster-tls.yaml](wazuhcluster-tls.yaml) | WazuhCluster | Advanced TLS / certificate configuration |
| [wazuhcluster-drain.yaml](wazuhcluster-drain.yaml) | WazuhCluster | Safe scale-down via drain strategy |
| [wazuhcluster-monitoring.yaml](wazuhcluster-monitoring.yaml) | WazuhCluster | Prometheus monitoring enabled |
| [wazuhcluster-authd-password.yaml](wazuhcluster-authd-password.yaml) | WazuhCluster | Agent enrollment with authd password |
| [wazuhcluster-multi-namespace.yaml](wazuhcluster-multi-namespace.yaml) | Namespace + WazuhCluster | Multi-namespace deployment |
| [wazuhagentgroup-basic.yaml](wazuhagentgroup-basic.yaml) | WazuhAgentGroup | Agent group (`linux-servers`) |
| [wazuhdecoder-basic.yaml](wazuhdecoder-basic.yaml) | WazuhDecoder | Custom JSON log decoder |
| [wazuhrule-basic.yaml](wazuhrule-basic.yaml) | WazuhRule | Custom SSH brute-force detection rule |
| [wazuhintegration-basic.yaml](wazuhintegration-basic.yaml) | Secret + WazuhIntegration | Integration with an external API (Slack) |

## Related Documentation

- [TLS Configuration](../../features/tls.md)
- [Drain Strategy](../../features/drain-strategy.md)
- [Monitoring](../../features/monitoring.md)
