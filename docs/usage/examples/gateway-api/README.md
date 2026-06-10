# Gateway API Examples

Expose Wazuh services (dashboard, API, agent enrollment/reporting) through the
Kubernetes Gateway API instead of Ingress.

| File | Kind | Description |
| ---- | ---- | ----------- |
| [wazuhcluster-gateway-api.yaml](wazuhcluster-gateway-api.yaml) | WazuhCluster | Cluster exposing services via Gateway API (HTTPRoute / TCPRoute / UDPRoute) |

## Prerequisites

A Gateway API implementation must be installed in the cluster (e.g. Envoy
Gateway, Istio, Cilium) with a `GatewayClass` available.

## Related Documentation

- [Gateway API](../../features/gateway-api.md)
