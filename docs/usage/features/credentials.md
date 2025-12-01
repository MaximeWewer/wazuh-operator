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
helm install wazuh-cluster oci://ghcr.io/maximewewer/charts/wazuh-cluster \
  --namespace wazuh \
  -f values.yaml
```

### Via External Secrets

Reference pre-existing Kubernetes secrets:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
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

### Password Not Working

```bash
# Verify secret exists
kubectl get secret -n wazuh wazuh-indexer-credentials

# Check secret data
kubectl get secret -n wazuh wazuh-indexer-credentials -o yaml

# Verify password format (should be base64 encoded)
kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d && echo
```

### Secret Not Being Created

```bash
# Check operator logs
kubectl logs -n wazuh-operator deployment/wazuh-operator-controller-manager

# Check WazuhCluster status
kubectl describe wazuhcluster wazuh -n wazuh
```

### Dashboard Can't Connect to API

```bash
# Verify API credentials match
kubectl get secret -n wazuh wazuh-api-credentials \
  -o jsonpath='{.data.password}' | base64 -d

# Check wazuh.yml in dashboard pod
kubectl exec -n wazuh deploy/wazuh-dashboard -- \
  cat /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

## See Also

- [OpenSearch Security CRDs](opensearch-security.md)
- [Wazuh API Hosts Configuration](wazuh-api-hosts.md)
- [TLS Configuration](tls.md)
