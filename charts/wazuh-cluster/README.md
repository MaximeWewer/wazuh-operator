# Wazuh Cluster Helm Chart

This Helm chart deploys Wazuh cluster instances via the Wazuh Operator.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- Wazuh Operator installed (use the `wazuh-operator` chart)

## Documentation

For complete documentation, examples, and guides, see:

- **[User Documentation](../../docs/usage/README.md)** - Full usage guide
- **[Quick Start Examples](../../docs/usage/examples/quick-start/)** - Minimal deployment examples
- **[Production Examples](../../docs/usage/examples/production/)** - Production-ready configurations
- **[Sizing Profiles](../../docs/usage/features/sizing.md)** - Cluster sizing guide
- **[CRD Reference](../../docs/usage/CRD-REFERENCE.md)** - Complete API documentation

## Installation

### Quick Start

1. Install the Wazuh Operator first (if not already installed):

```bash
helm install wazuh-operator ./charts/wazuh-operator
```

2. Install the chart with a sizing profile:

```bash
helm install my-wazuh-cluster ./charts/wazuh-cluster \
  --set sizing.profile=M \
  --namespace wazuh --create-namespace
```

## Configuration

### Secrets

The chart creates the following secrets required by Wazuh clusters:

| Secret Name                 | Description                              | Keys                               |
| --------------------------- | ---------------------------------------- | ---------------------------------- |
| `wazuh-api-credentials`     | API credentials for Wazuh                | `username`, `password`             |
| `indexer-admin-credentials` | Admin credentials for OpenSearch indexer | `admin-username`, `admin-password` |
| `wazuh-authd-pass`          | Password for agent enrollment            | `authd.pass`                       |

### Cluster Configuration

Define your Wazuh cluster in your values file. The chart deploys ONE WazuhCluster per Helm release.

Example:

```yaml
cluster:
  enabled: true
  name: wazuh-production
  spec:
    version: "4.9.0"
    indexer:
      replicas: 3
      storageSize: 100Gi
    manager:
      master:
        storageSize: 50Gi
      workers:
        replicas: 2
    dashboard:
      replicas: 1
```

## Examples

See the [documentation examples](../../docs/usage/examples/) for complete configuration examples:

- [Quick Start](../../docs/usage/examples/quick-start/) - Minimal deployment for development
- [Production](../../docs/usage/examples/production/) - Production-ready configuration with high availability

## Upgrading

To upgrade an existing installation:

```bash
helm upgrade my-wazuh-cluster ./charts/wazuh-cluster -f my-values.yaml
```

## Uninstallation

```bash
helm uninstall my-wazuh-cluster
```

**Note:** This will delete all WazuhCluster resources and secrets. The operator will clean up all associated Kubernetes resources.

## Parameters

### Global Parameters

| Parameter         | Description                          | Default |
| ----------------- | ------------------------------------ | ------- |
| `namespace`       | Namespace for Wazuh clusters         | `wazuh` |
| `createNamespace` | Create namespace if it doesn't exist | `true`  |

### Secrets Parameters

| Parameter                       | Description                  | Default                          |
| ------------------------------- | ---------------------------- | -------------------------------- |
| `secrets.wazuhApi.username`     | API username                 | `wazuh-api`                      |
| `secrets.wazuhApi.password`     | API password                 | `CHANGE_ME_STRONG_PASSWORD_HERE` |
| `secrets.indexerAdmin.username` | Indexer admin username       | `admin`                          |
| `secrets.indexerAdmin.password` | Indexer admin password       | `CHANGE_ME_STRONG_PASSWORD_HERE` |
| `secrets.wazuhAuthd.enabled`    | Create authd password secret | `true`                           |
| `secrets.wazuhAuthd.password`   | Agent enrollment password    | `CHANGE_ME_STRONG_PASSWORD_HERE` |

**Note:** The secrets are automatically created if `username` and `password` are provided. The `enabled` flag is only used for `wazuhAuthd`.

### Cluster Parameters

| Parameter         | Description                       | Default         |
| ----------------- | --------------------------------- | --------------- |
| `cluster.enabled` | Enable cluster deployment         | `true`          |
| `cluster.name`    | Name of the WazuhCluster resource | `wazuh-cluster` |
| `cluster.spec`    | WazuhCluster CRD specification    | See values.yaml |

### Sizing Profiles

The chart supports predefined sizing profiles for quick deployment. See **[Sizing Guide](../../docs/usage/features/sizing.md)** for full details.

| Parameter                 | Description                        | Default |
| ------------------------- | ---------------------------------- | ------- |
| `sizing.profile`          | Sizing profile: XS, S, M, L, or XL | `""`    |
| `sizing.storageClassName` | Custom storage class               | `""`    |

**Available Profiles:**

- **XS (Extra Small)**: Testing only - single node, minimal resources
- **S (Small)**: Dev/Test - 1 indexer, 1 worker
- **M (Medium)**: Small Production - 3 indexers, 2 workers
- **L (Large)**: Production - 3 indexers, 3 workers, HA dashboard
- **XL (Extra Large)**: Enterprise - 5 indexers, 5 workers, 3 dashboards

## Ingress Configuration

The WazuhCluster CRD supports Ingress for the Dashboard, Indexer, and Manager components.

### Dashboard Ingress Example

```yaml
dashboard:
  service:
    type: ClusterIP # Use ClusterIP when using Ingress
  ingress:
    enabled: true
    ingressClassName: nginx
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
      nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
    hosts:
      - host: wazuh.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: wazuh-dashboard-tls
        hosts:
          - wazuh.example.com
```

### Prerequisites for Ingress

1. **Ingress Controller** must be installed (e.g., NGINX Ingress Controller, Traefik)

   ```bash
   # Example: Install NGINX Ingress Controller
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml
   ```

2. **Cert-Manager** (optional, for automatic TLS certificate management)

   ```bash
   # Install cert-manager
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
   ```

3. **DNS Configuration** - Ensure your domain points to the Ingress Controller's external IP

### Common Ingress Annotations

#### NGINX Ingress Controller

```yaml
annotations:
  # TLS
  cert-manager.io/cluster-issuer: letsencrypt-prod
  nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
  nginx.ingress.kubernetes.io/ssl-redirect: "true"

  # Timeouts
  nginx.ingress.kubernetes.io/proxy-connect-timeout: "300"
  nginx.ingress.kubernetes.io/proxy-read-timeout: "300"

  # Body size
  nginx.ingress.kubernetes.io/proxy-body-size: "50m"
```

#### Traefik

```yaml
annotations:
  cert-manager.io/cluster-issuer: letsencrypt-prod
  traefik.ingress.kubernetes.io/router.tls: "true"
```

#### AWS ALB Ingress

```yaml
annotations:
  kubernetes.io/ingress.class: alb
  alb.ingress.kubernetes.io/scheme: internet-facing
  alb.ingress.kubernetes.io/target-type: ip
  alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:region:account:certificate/id
```

## Security Considerations

⚠️ **IMPORTANT**: The default passwords in this chart are for demonstration purposes only.

For production use, you **MUST**:

1. Change all default passwords
2. Consider using external secret management (e.g., Sealed Secrets, External Secrets Operator)
3. Enable TLS for all communications
4. Review and apply appropriate RBAC policies

## Support

For issues and questions:

- GitHub Issues: https://github.com/MaximeWewer/wazuh-operator/issues
- Documentation: https://documentation.wazuh.com/
