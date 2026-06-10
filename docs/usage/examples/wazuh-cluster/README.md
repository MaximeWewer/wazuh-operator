# Wazuh Cluster Examples

`WazuhCluster` feature variations. For content CRDs (rules, decoders,
integrations, agent groups) see [../wazuh-content/](../wazuh-content/);
for certificates see [../wazuh-certificate/](../wazuh-certificate/).

| File | Description |
| ---- | ----------- |
| [wazuhcluster-tls.yaml](wazuhcluster-tls.yaml) | Advanced TLS / certificate configuration |
| [wazuhcluster-drain.yaml](wazuhcluster-drain.yaml) | Safe scale-down via drain strategy |
| [wazuhcluster-monitoring.yaml](wazuhcluster-monitoring.yaml) | Prometheus monitoring enabled |
| [wazuhcluster-authd-password.yaml](wazuhcluster-authd-password.yaml) | Agent enrollment with authd password |
| [wazuhcluster-multi-namespace.yaml](wazuhcluster-multi-namespace.yaml) | Multi-namespace deployment |
| [wazuhcluster-gateway-api.yaml](wazuhcluster-gateway-api.yaml) | Expose services via Gateway API (HTTPRoute/TCPRoute/UDPRoute) |

## Related Documentation

- [TLS Configuration](../../features/tls.md)
- [Drain Strategy](../../features/drain-strategy.md)
- [Monitoring](../../features/monitoring.md)
- [Gateway API](../../features/gateway-api.md)
