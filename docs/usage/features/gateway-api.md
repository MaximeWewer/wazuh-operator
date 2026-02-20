# Gateway API Integration

The Wazuh Operator supports exposing Wazuh services via [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) as an alternative to traditional Ingress resources.

## Overview

Gateway API is the next-generation Kubernetes networking API that provides more expressive, extensible, and role-oriented interfaces for managing traffic routing. The Wazuh Operator supports:

- **HTTPRoute**: For Dashboard UI, Manager API, and Indexer REST API
- **TCPRoute**: For Agent enrollment (1515), events (1514), and cluster communication (1516)
- **UDPRoute**: For Syslog traffic (514)

## Prerequisites

### 1. Gateway API Implementation

Install a Gateway API implementation. Popular options include:

- [Envoy Gateway](https://gateway.envoyproxy.io/)
- [Istio](https://istio.io/)
- [Traefik](https://traefik.io/)
- [NGINX Gateway Fabric](https://github.com/nginxinc/nginx-gateway-fabric)

### 2. Gateway API CRDs

Install the Gateway API Custom Resource Definitions:

```bash
# Standard CRDs (HTTPRoute) - required for HTTP traffic
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# Experimental CRDs (TCPRoute, UDPRoute) - required for agent traffic and syslog
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/experimental-install.yaml
```

### 3. Gateway Resource

Create a Gateway resource that your routes will reference:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: wazuh-gateway
  namespace: gateway-system
spec:
  gatewayClassName: envoy  # Or your implementation's class
  listeners:
    # HTTP listener for Dashboard, Manager API, Indexer
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: All
    # HTTPS listener (recommended for production)
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - name: wazuh-tls-secret
      allowedRoutes:
        namespaces:
          from: All
    # TCP listeners for agent traffic
    - name: agent-enrollment
      protocol: TCP
      port: 1515
      allowedRoutes:
        namespaces:
          from: All
    - name: agent-events
      protocol: TCP
      port: 1514
      allowedRoutes:
        namespaces:
          from: All
    # UDP listener for syslog
    - name: syslog
      protocol: UDP
      port: 514
      allowedRoutes:
        namespaces:
          from: All
```

## Enabling Gateway API in the Operator

Gateway API support is **disabled by default** to avoid startup errors when Gateway API CRDs are not installed.

### Enable via Helm

```bash
helm install wazuh-operator ./charts/wazuh-operator \
  --namespace wazuh-system \
  --create-namespace \
  --set gatewayAPI.enabled=true
```

### Enable via Environment Variable

```yaml
env:
  - name: GATEWAY_API_ENABLED
    value: "true"
```

## Configuring WazuhCluster for Gateway API

Once Gateway API is enabled in the operator, configure it in your WazuhCluster spec:

### Dashboard

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh
  namespace: wazuh
spec:
  dashboard:
    replicas: 1
    gatewayAPI:
      enabled: true
      gatewayRef:
        name: wazuh-gateway
        namespace: gateway-system
      hostnames:
        - "wazuh.example.com"
      http:
        pathPrefix: "/"
```

### Manager (with TCP/UDP routes)

```yaml
spec:
  manager:
    master:
      gatewayAPI:
        enabled: true
        gatewayRef:
          name: wazuh-gateway
          namespace: gateway-system
        hostnames:
          - "wazuh-api.example.com"
        http:
          pathPrefix: "/"
        tcp:
          enabled: true
          enrollmentEnabled: true  # Port 1515
          eventsEnabled: true      # Port 1514
          clusterEnabled: false    # Port 1516 (usually internal)
        udp:
          enabled: true
          syslogPort: 514
```

### Indexer

```yaml
spec:
  indexer:
    replicas: 3
    gatewayAPI:
      enabled: true
      gatewayRef:
        name: wazuh-gateway
        namespace: gateway-system
      hostnames:
        - "opensearch.example.com"
      http:
        pathPrefix: "/"
```

## Complete Example

See the full example at: [config/samples/wazuh_v1_wazuhcluster_gatewayapi.yaml](../../../config/samples/wazuh_v1_wazuhcluster_gatewayapi.yaml)

## Important Notes

### Mutual Exclusion with Ingress

Gateway API and Ingress cannot be enabled simultaneously for the same component. The webhook validation will reject configurations that enable both.

### CRD Availability

- **HTTPRoute** (standard): Required for Dashboard, Manager API, and Indexer REST API
- **TCPRoute** (experimental): Required for agent enrollment, events, and cluster communication
- **UDPRoute** (experimental): Required for syslog traffic

If experimental CRDs are not installed, TCP and UDP routes will fail with clear error messages indicating how to install them.

### Operator Behavior

| Operator Setting | Cluster Setting | Behavior |
|------------------|-----------------|----------|
| `gatewayAPI.enabled=false` | `gatewayAPI.enabled=true` | Warning event, routes not created |
| `gatewayAPI.enabled=true` | `gatewayAPI.enabled=false` | No routes created (as expected) |
| `gatewayAPI.enabled=true` | `gatewayAPI.enabled=true` | Routes created and managed |

## Troubleshooting

### "Gateway API support is disabled"

If you see this warning:

```text
GatewayAPI is configured but operator Gateway API support is disabled
```

Enable Gateway API support in the operator:

```bash
helm upgrade wazuh-operator ./charts/wazuh-operator --set gatewayAPI.enabled=true
```

### "Gateway API CRDs not installed"

Install the required CRDs:

```bash
# For HTTPRoute
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml

# For TCPRoute and UDPRoute
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/experimental-install.yaml
```

### Routes not being created

1. Verify Gateway API is enabled in the operator
2. Check that the Gateway resource exists and is ready
3. Verify the `gatewayRef` in your WazuhCluster points to the correct Gateway
4. Check operator logs for detailed error messages

```bash
kubectl logs -n wazuh-system deployment/wazuh-operator-controller-manager | grep -i gateway
```
