# TLS Configuration

The Wazuh Operator provides comprehensive TLS management for secure communication between all components.

## Overview

TLS is enabled by default and supports three modes:

1. **Auto-generated certificates** (default): Operator generates and manages certificates
2. **Cert-manager integration**: Use cert-manager for certificate lifecycle
3. **Custom certificates**: Bring your own certificates

## Configuration

TLS is configured in the `tls` section of the WazuhCluster spec:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.9.0"
  tls:
    enabled: true
    certConfig:
      validityDays: 365
      renewalThresholdDays: 30
      caValidityDays: 730
      caRenewalThresholdDays: 60
    hotReload:
      enabled: true
```

## Auto-Generated Certificates

By default, the operator generates a self-signed CA and node certificates.

### Certificate Configuration

| Field                    | Type   | Default      | Description                      |
| ------------------------ | ------ | ------------ | -------------------------------- |
| `country`                | string | `US`         | X.509 Country                    |
| `state`                  | string | `California` | X.509 State                      |
| `locality`               | string | `California` | X.509 Locality                   |
| `organization`           | string | `Wazuh`      | X.509 Organization               |
| `organizationalUnit`     | string | `Wazuh`      | X.509 OU                         |
| `commonName`             | string | `admin`      | X.509 Common Name                |
| `validityDays`           | int    | `365`        | Node certificate validity (days) |
| `renewalThresholdDays`   | int    | `30`         | Days before expiry to renew      |
| `caValidityDays`         | int    | `730`        | CA certificate validity (days)   |
| `caRenewalThresholdDays` | int    | `60`         | Days before CA expiry to renew   |

### Generated Certificates

The operator creates the following certificates:

- **Root CA**: Self-signed CA for all certificates
- **Admin certificate**: For OpenSearch security initialization
- **Indexer certificates**: Per-node certificates for indexer cluster
- **Dashboard certificate**: For dashboard HTTPS
- **Filebeat certificate**: For log shipping to indexer

### Certificate Secrets

Certificates are stored in Kubernetes Secrets:

| Secret Name                | Contents                            |
| -------------------------- | ----------------------------------- |
| `<cluster>-ca-cert`        | CA certificate and private key      |
| `<cluster>-admin-cert`     | Admin certificate for securityadmin |
| `<cluster>-indexer-cert`   | Indexer node certificates           |
| `<cluster>-dashboard-cert` | Dashboard certificate               |
| `<cluster>-filebeat-cert`  | Filebeat certificate                |

## Hot Reload

Certificate hot reload allows updating certificates without pod restarts.

### Configuration

```yaml
tls:
  hotReload:
    enabled: true # Enable hot reload
    forceAPIReload: false # Force API reload even for newer versions
```

### Version Behavior

| Wazuh Version | OpenSearch | Hot Reload Method              |
| ------------- | ---------- | ------------------------------ |
| 4.9.x         | 2.13-2.18  | Config + API call              |
| 5.0+          | 2.19+      | Automatic file-based detection |

### How It Works

1. Operator detects certificate renewal is needed
2. New certificates are generated and stored in Secrets
3. For Wazuh 4.9.x: Operator calls the reload certificates API
4. For Wazuh 5.0+: OpenSearch automatically detects file changes
5. Components reload certificates without restart

## Cert-Manager Integration

Use cert-manager for certificate lifecycle management:

```yaml
tls:
  certManager:
    enabled: true
    issuerName: "wazuh-ca-issuer"
    issuerKind: "ClusterIssuer"
```

### Configuration Options

| Field        | Type   | Default  | Description                      |
| ------------ | ------ | -------- | -------------------------------- |
| `enabled`    | bool   | `false`  | Enable cert-manager integration  |
| `issuerName` | string | -        | Name of the Issuer/ClusterIssuer |
| `issuerKind` | string | `Issuer` | `Issuer` or `ClusterIssuer`      |

### Prerequisites

1. Install cert-manager in your cluster
2. Create an Issuer or ClusterIssuer

Example ClusterIssuer:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: wazuh-ca-issuer
spec:
  ca:
    secretName: wazuh-ca-secret
```

## Custom Certificates

Bring your own certificates:

```yaml
tls:
  customCerts:
    caSecretRef:
      name: my-ca-secret
      key: ca.crt
    nodeSecretRef:
      name: my-node-secret
      key: tls.crt
    adminSecretRef:
      name: my-admin-secret
      key: tls.crt
    filebeatSecretRef:
      name: my-filebeat-secret
      key: tls.crt
```

### Secret Format

Custom certificate secrets should contain:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-node-secret
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-certificate>
  tls.key: <base64-encoded-private-key>
  ca.crt: <base64-encoded-ca-certificate>
```

## Certificate Renewal

### Automatic Renewal

The operator automatically renews certificates before expiry based on the threshold settings:

- Node certificates: Renewed when `renewalThresholdDays` before expiry
- CA certificates: Renewed when `caRenewalThresholdDays` before expiry

### Manual Renewal

To force certificate renewal, delete the certificate secrets:

```bash
kubectl delete secret -n wazuh <cluster>-indexer-cert
```

The operator will regenerate the certificates on the next reconciliation.

### CA Renewal Impact

CA renewal requires pod restarts because the trust store must be updated:

- All indexer pods will be rolled
- Dashboard pods will be rolled
- Manager pods will be updated

## Verifying TLS

### Check Certificate Status

```bash
# View certificate expiry
kubectl get secret -n wazuh <cluster>-indexer-cert -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -noout -dates
```

### Verify Certificate Chain

```bash
# From inside a pod
kubectl exec -n wazuh <indexer-pod> -- \
  openssl s_client -connect localhost:9200 -CAfile /etc/ssl/ca.crt
```

### Check Hot Reload Status

```bash
# Check if certificates were reloaded
kubectl logs -n wazuh <indexer-pod> | grep -i "certificate"
```

## Troubleshooting

### Certificate Errors

1. Check certificate secrets exist:

   ```bash
   kubectl get secrets -n wazuh | grep cert
   ```

2. Verify certificate validity:
   ```bash
   kubectl get secret -n wazuh <secret> -o jsonpath='{.data.tls\.crt}' | \
     base64 -d | openssl x509 -noout -text
   ```

### Hot Reload Not Working

1. Check Wazuh version supports hot reload (4.9.0+)
2. Verify `hotReload.enabled` is true
3. Check operator logs for reload attempts

### Connection Errors

1. Verify CA certificate is trusted:

   ```bash
   kubectl exec -n wazuh <pod> -- cat /etc/ssl/ca.crt
   ```

2. Check certificate SANs include the service DNS name
