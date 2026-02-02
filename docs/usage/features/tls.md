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
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  version: "4.9.0"
  tls:
    enabled: true
    certConfig:
      # Duration string format (recommended)
      validity: "365d"           # Node certificate validity
      renewalThreshold: "30d"    # Renew when expires within this duration
      caValidity: "3650d"        # CA certificate validity (10 years)
      caRenewalThreshold: "60d"  # CA renewal threshold
    hotReload:
      enabled: true
```

### Duration Format

Certificate validity and renewal thresholds can be specified using duration strings:

| Unit | Example | Description          |
|------|---------|----------------------|
| `d`  | `365d`  | Days (24 hours each) |
| `h`  | `24h`   | Hours                |
| `m`  | `30m`   | Minutes              |

**Examples:**

- `365d` - 1 year
- `730d` - 2 years
- `24h` - 1 day
- `30m` - 30 minutes (useful for testing)

> **Note:** Minute and hour granularity is useful for testing certificate renewal scenarios. In production, use day-based durations.

## Auto-Generated Certificates

By default, the operator generates a self-signed CA and node certificates.

### Certificate Configuration

| Field                | Type   | Default      | Description                                             |
| -------------------- | ------ | ------------ | ------------------------------------------------------- |
| `country`            | string | `FR`         | X.509 Country                                           |
| `state`              | string | `Alsace`     | X.509 State                                             |
| `locality`           | string | `Srasbourg`  | X.509 Locality                                          |
| `organization`       | string | `Wazuh`      | X.509 Organization                                      |
| `organizationalUnit` | string | `Wazuh`      | X.509 OU                                                |
| `commonName`         | string | `admin`      | X.509 Common Name                                       |
| `validity`           | string | `365d`       | Node certificate validity (duration string)             |
| `renewalThreshold`   | string | `30d`        | Renew when expires within this duration                 |
| `caValidity`         | string | `3650d`      | CA certificate validity (duration string)               |
| `caRenewalThreshold` | string | `60d`        | CA renewal threshold (duration string)                  |
| `keyAlgorithm`       | string | `RSA`        | Key algorithm: `RSA` or `ECDSA`                         |
| `ecdsaCurve`         | string | `P256`       | ECDSA curve: `P256`, `P384`, or `P521` (only for ECDSA) |

### Key Algorithm

The operator supports two key algorithms:

- **RSA** (default): 2048-bit keys, widely compatible with all systems
- **ECDSA**: Elliptic curve keys, smaller keys with equivalent security
  - **P-256**: ~128 bits security, best performance (default)
  - **P-384**: ~192 bits security, larger keys
  - **P-521**: ~256 bits security, highest level

Example with ECDSA P-521 (maximum security):

```yaml
tls:
  certConfig:
    keyAlgorithm: ECDSA
    ecdsaCurve: P521  # or P256/P384
```

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
| 4.12+         | 2.19+      | Automatic file-based detection |

### How It Works

1. Operator detects certificate renewal is needed
2. New certificates are generated and stored in Secrets
3. For Wazuh 4.9.x: Operator calls the reload certificates API
4. For Wazuh 4.12+: OpenSearch automatically detects file changes
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

- Node certificates: Renewed when `renewalThreshold` duration remains before expiry
- CA certificates: Renewed when `caRenewalThreshold` duration remains before expiry

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

For certificate-related issues, see [Common Issues](../troubleshooting/common-issues.md#certificate-issues).

**Quick checks:**

```bash
# List certificate secrets
kubectl get secrets -n wazuh | grep cert

# Check certificate expiry
kubectl get secret -n wazuh wazuh-indexer-certs \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -dates
```
