# Credentials Management

This guide explains how the Wazuh Operator manages credentials for OpenSearch and Wazuh API components.

## Overview

The Wazuh Operator follows a **secure-by-default** approach for credential management:

- **No hardcoded default passwords** - All passwords are generated dynamically
- **Cryptographically secure** - Uses `crypto/rand` for password generation
- **Kubernetes Secrets** - All credentials stored in Kubernetes Secrets
- **User override** - Users can provide custom credentials via Helm values or external secrets

## Auto-Generated Credentials

### OpenSearch Admin Password

When deploying a WazuhCluster, the operator automatically generates a **24-character random password** for the OpenSearch admin user.

**Secret location:**

```bash
kubectl get secret -n <namespace> <cluster-name>-indexer-credentials -o yaml
```

**Retrieve password:**

```bash
# Get admin password
kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d

# Get admin username (always "admin")
kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-username}' | base64 -d
```

### Wazuh API Password

When monitoring with Wazuh exporter is enabled, the operator generates a **20-character random password** with special characters for the Wazuh API.

**Password requirements:**

- Minimum 20 characters
- Contains alphanumeric characters
- Contains at least one special character from: `. * + ? -`
- Must **not** contain backslash (`\`) characters

**Secret location:**

```bash
kubectl get secret -n <namespace> <cluster-name>-api-credentials -o yaml
```

**Retrieve password:**

```bash
# Get API password
kubectl get secret -n wazuh wazuh-api-credentials \
  -o jsonpath='{.data.password}' | base64 -d

# Get API username (always "wazuh")
kubectl get secret -n wazuh wazuh-api-credentials \
  -o jsonpath='{.data.username}' | base64 -d
```

### Wazuh Cluster Key

The operator generates a **32-character hex key** (equivalent to `openssl rand -hex 16`) for cluster node communication.

**Secret location:**

```bash
kubectl get secret -n <namespace> <cluster-name>-cluster-key -o yaml
```

**Retrieve key:**

```bash
kubectl get secret -n wazuh wazuh-cluster-key \
  -o jsonpath='{.data.cluster-key}' | base64 -d
```

## Password Validation

The operator validates all passwords (both auto-generated and user-provided) against the following rules:

- Backslash (`\`) characters are **not allowed**. The backslash character is incompatible with Wazuh JSON configuration and will cause parsing errors. This validation is enforced in `internal/validation/password_validation.go`.

If a custom password fails validation, the operator will reject it during reconciliation and emit a warning event.

## Custom Credentials

### Via Helm Chart Values

You can provide custom credentials when installing the wazuh-cluster Helm chart:

```yaml
# values.yaml
secrets:
  # OpenSearch admin credentials
  indexerAdmin:
    username: admin
    password: MySecureOpenSearchPassword123!

  # Wazuh API credentials
  wazuhApi:
    username: wazuh
    password: MySecureWazuhPassword.2025

  # Cluster key (32 hex characters)
  clusterKey: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
```

```bash
helm template wazuh-cluster oci://ghcr.io/maximewewer/charts/wazuh-cluster \
  --namespace wazuh \
  -f values.yaml | kubectl apply -f -
```

### Via External Secrets

Reference pre-existing Kubernetes secrets:

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh
spec:
  indexer:
    credentialsRef:
      secretName: my-opensearch-credentials
      usernameKey: username
      passwordKey: password

  dashboard:
    wazuhPlugin:
      defaultApiEndpoint:
        credentialsSecret:
          secretName: my-wazuh-api-credentials
          usernameKey: username
          passwordKey: password
```

## Credential Secrets Reference

| Secret Name | Keys | Description |
|------------|------|-------------|
| `<cluster>-indexer-credentials` | `admin-username`, `admin-password` | OpenSearch admin credentials |
| `<cluster>-api-credentials` | `username`, `password` | Wazuh API credentials |
| `<cluster>-cluster-key` | `cluster-key` | Wazuh cluster communication key |
| `<cluster>-manager-certs` | `root-ca.pem`, `node.pem`, `node-key.pem` | Manager TLS certificates |
| `<cluster>-indexer-certs` | `root-ca.pem`, `admin.pem`, `admin-key.pem` | Indexer TLS certificates |
| `<cluster>-dashboard-certs` | `root-ca.pem`, `dashboard.pem`, `dashboard-key.pem` | Dashboard TLS certificates |

## Credential Recovery (PVC Reuse)

When a WazuhCluster CR is deleted and recreated, PersistentVolumeClaims (PVCs) may survive the deletion (depending on your `reclaimPolicy`). In this scenario:

1. The operator generates **new random passwords** for the recreated cluster
2. The OpenSearch security index on the existing PVC still contains the **old password hashes**
3. OpenSearch only reads `internal_users.yml` from disk on first initialization (when the security index doesn't exist)

This causes an authentication mismatch: the new passwords don't match the old hashes stored in the security index.

### Automatic Recovery

The operator automatically detects and recovers from this situation:

1. During credential synchronization, the operator attempts to update passwords via the OpenSearch REST API
2. If the REST API returns a `401 Unauthorized` or `403 Forbidden` error, the operator detects the mismatch
3. The operator falls back to `securityadmin.sh`, which authenticates using **TLS admin certificates** (not passwords) to force-push the new `internal_users.yml` into the OpenSearch security index
4. The dashboard deployment is automatically restarted to pick up the new credentials
5. On the next reconciliation cycle, the REST API succeeds with the new passwords

You can observe this recovery in the operator logs:

```
REST API returned auth error during credential sync, attempting recovery via securityadmin.sh
Credentials pushed via securityadmin.sh, will sync via REST API on next reconciliation
Dashboard restart triggered after credential recovery
```

A Kubernetes event `SecurityCredentialsRecovered` is also emitted on the WazuhCluster resource.

### Manual Recovery

If automatic recovery fails for any reason:

```bash
# 1. Check the operator logs for errors
kubectl logs -n <operator-namespace> deploy/wazuh-operator-controller-manager | grep securityadmin

# 2. Verify the indexer pod is running
kubectl get pods -n <namespace> -l app.kubernetes.io/component=wazuh-indexer

# 3. Manually run securityadmin.sh if needed
kubectl exec -n <namespace> <cluster-name>-indexer-0 -- bash -c \
  "OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk \
   /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
   -f /usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml \
   -t internalusers -icl -nhnv \
   -cacert /usr/share/wazuh-indexer/config/certs/ca.crt \
   -cert /usr/share/wazuh-indexer/config/certs/admin/tls.crt \
   -key /usr/share/wazuh-indexer/config/certs/admin/tls.key"

# 4. Restart the dashboard to pick up the new credentials
kubectl rollout restart deployment/<cluster-name>-dashboard -n <namespace>
```

## Security Best Practices

### 1. Never Commit Credentials

```bash
# Add to .gitignore
secrets/
*-credentials.yaml
```

### 2. Use External Secret Managers

For production, consider using:

- **HashiCorp Vault** with External Secrets Operator
- **AWS Secrets Manager**
- **Azure Key Vault**
- **GCP Secret Manager**

Example with External Secrets Operator:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: wazuh-opensearch-credentials
  namespace: wazuh
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: wazuh-indexer-credentials
  data:
    - secretKey: admin-username
      remoteRef:
        key: wazuh/opensearch
        property: username
    - secretKey: admin-password
      remoteRef:
        key: wazuh/opensearch
        property: password
```

### 3. Rotate Credentials Regularly

```bash
# Delete the secret to trigger regeneration
kubectl delete secret -n wazuh wazuh-indexer-credentials

# Force reconciliation
kubectl annotate wazuhcluster wazuh -n wazuh --overwrite \
  wazuh.com/force-reconcile=$(date +%s)
```

### 4. Restrict Secret Access

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: wazuh-secrets-reader
  namespace: wazuh
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames:
      - "wazuh-indexer-credentials"
      - "wazuh-api-credentials"
    verbs: ["get"]
```

## Troubleshooting

For credential-related issues, see [Common Issues](../troubleshooting/common-issues.md).

**Quick checks:**

```bash
# Verify secret exists
kubectl get secret -n wazuh wazuh-indexer-credentials

# Get password
kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d && echo
```

## See Also

- [OpenSearch Security CRDs](opensearch-security.md)
- [Wazuh API Hosts Configuration](wazuh-api-hosts.md)
- [TLS Configuration](tls.md)
