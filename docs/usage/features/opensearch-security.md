# OpenSearch Security CRDs

This guide covers all OpenSearch Security CRDs for managing users, roles, and access control.

## Overview

The Wazuh Operator provides Kubernetes-native management of OpenSearch security through Custom Resource Definitions (CRDs):

| CRD                     | Short Name | Purpose                         |
| ----------------------- | ---------- | ------------------------------- |
| `OpenSearchUser`        | `osuser`   | Internal users                  |
| `OpenSearchRole`        | `osrole`   | Security roles with permissions |
| `OpenSearchRoleMapping` | `osrmap`   | Map users/backends to roles     |
| `OpenSearchTenant`      | `ostenant` | Multi-tenancy isolation         |
| `OpenSearchActionGroup` | `osag`     | Reusable permission groups      |

## The Admin User

### Default Behavior

By default, the operator creates an `admin` user automatically when deploying a WazuhCluster. This user has full administrative privileges.

**Default admin credentials:**

- Username: `admin`
- Password: **Auto-generated 24-character random password** stored in Secret `<cluster-name>-indexer-credentials`

> **Security Note:** The operator never uses hardcoded default passwords. All passwords are cryptographically generated using `crypto/rand` for maximum security.

```bash
# Get admin password
kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d

# Get admin username
kubectl get secret -n wazuh wazuh-indexer-credentials \
  -o jsonpath='{.data.admin-username}' | base64 -d
```

For more details on credential management, see the [Credentials Management Guide](credentials.md).

### Custom Admin User via CRD

You can declare your own admin user using the `OpenSearchUser` CRD with `defaultAdmin: true`:

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchUser
metadata:
  name: admin
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  defaultAdmin: true # This user becomes the default admin
  passwordSecret:
    secretName: my-admin-credentials
    passwordKey: password
  backendRoles:
    - admin
  openSearchRoles:
    - all_access
  description: "Custom admin user managed by CRD"
```

### Admin User Behavior

| Scenario                                 | Behavior                                                  |
| ---------------------------------------- | --------------------------------------------------------- |
| No `defaultAdmin: true` CRD              | Operator creates auto-generated `admin` user              |
| One CRD with `defaultAdmin: true`        | That user becomes the admin                               |
| Multiple CRDs with `defaultAdmin: true`  | First by creation timestamp is used, others emit warnings |
| CRD named `admin` without `defaultAdmin` | Normal user, auto-admin still created                     |

**Important:** The `admin` user is used by internal components (Dashboard, Filebeat) to authenticate with OpenSearch. If you override it, ensure the credentials are also updated in the relevant secrets.

### Cluster Status

Check which admin is active:

```bash
kubectl get wazuhcluster wazuh -n wazuh -o jsonpath='{.status.security}'
```

Output:

```json
{
  "initialized": true,
  "defaultAdminUser": "admin",
  "defaultAdminSource": "crd", // or "auto"
  "syncedUsers": 3
}
```

## OpenSearchUser

Manage internal users in OpenSearch.

### Spec Reference

| Field             | Type     | Required | Description                         |
| ----------------- | -------- | -------- | ----------------------------------- |
| `clusterRef.name` | string   | Yes      | WazuhCluster name                   |
| `defaultAdmin`    | bool     | No       | Mark as default admin               |
| `passwordSecret`  | object   | No       | Password from Secret                |
| `hash`            | string   | No       | Pre-computed BCrypt hash            |
| `backendRoles`    | []string | No       | Backend roles for LDAP/SAML mapping |
| `openSearchRoles` | []string | No       | OpenSearch roles to assign          |
| `attributes`      | map      | No       | Custom user attributes              |
| `description`     | string   | No       | User description                    |

### Examples

#### Basic User

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchUser
metadata:
  name: readonly-user
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  passwordSecret:
    secretName: readonly-user-secret
    passwordKey: password
  openSearchRoles:
    - readall
  description: "Read-only user for dashboards"
```

#### User with Backend Roles (for LDAP/SAML)

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchUser
metadata:
  name: ldap-mapped-user
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  passwordSecret:
    secretName: ldap-user-secret
    passwordKey: password
  backendRoles:
    - security-team
    - soc-analysts
  attributes:
    department: "Security"
    location: "US-East"
```

#### User with Pre-computed Hash

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchUser
metadata:
  name: hashed-user
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  # BCrypt hash of password
  hash: "$2y$12$abcdef..."
  openSearchRoles:
    - kibana_user
```

Generate hash:

```bash
# Using htpasswd
htpasswd -bnBC 12 "" 'MyPassword' | tr -d ':\n'

# Using Python
python3 -c "import bcrypt; print(bcrypt.hashpw(b'MyPassword', bcrypt.gensalt(12)).decode())"
```

## OpenSearchRole

Define custom security roles with granular permissions.

### Spec Reference

| Field                | Type     | Required | Description               |
| -------------------- | -------- | -------- | ------------------------- |
| `clusterRef.name`    | string   | Yes      | WazuhCluster name         |
| `clusterPermissions` | []string | No       | Cluster-level permissions |
| `indexPermissions`   | []object | No       | Index-level permissions   |
| `tenantPermissions`  | []object | No       | Tenant-level permissions  |
| `description`        | string   | No       | Role description          |

### Index Permissions

| Field            | Type     | Required | Description                            |
| ---------------- | -------- | -------- | -------------------------------------- |
| `indexPatterns`  | []string | Yes      | Index patterns (e.g., `logs-*`)        |
| `allowedActions` | []string | Yes      | Permitted actions                      |
| `dls`            | string   | No       | Document-Level Security query          |
| `fls`            | []string | No       | Field-Level Security (include/exclude) |
| `maskedFields`   | []string | No       | Fields to mask                         |

### Examples

#### Read-Only Role for Wazuh Alerts

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRole
metadata:
  name: wazuh-alerts-reader
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  clusterPermissions:
    - cluster_composite_ops_ro
  indexPermissions:
    - indexPatterns:
        - "wazuh-alerts-*"
      allowedActions:
        - read
        - search
  description: "Read-only access to Wazuh alerts"
```

#### Role with Document-Level Security

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRole
metadata:
  name: team-a-alerts
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  indexPermissions:
    - indexPatterns:
        - "wazuh-alerts-*"
      allowedActions:
        - read
        - search
      # Only see alerts from specific agents
      dls: '{"bool":{"must":[{"match":{"agent.name":"team-a-*"}}]}}'
```

#### Role with Field-Level Security

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRole
metadata:
  name: restricted-fields
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  indexPermissions:
    - indexPatterns:
        - "wazuh-alerts-*"
      allowedActions:
        - read
      # Include only these fields
      fls:
        - "timestamp"
        - "rule.description"
        - "agent.name"
        - "~data.srcip" # Exclude with ~
      # Mask sensitive fields
      maskedFields:
        - "data.srcuser"
        - "data.dstuser"
```

#### Admin Role for Specific Indices

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRole
metadata:
  name: logs-admin
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  clusterPermissions:
    - cluster_monitor
    - indices:admin/template/get
  indexPermissions:
    - indexPatterns:
        - "logs-*"
        - "application-*"
      allowedActions:
        - crud
        - create_index
        - manage
  description: "Full admin for log indices"
```

### Common Actions

**Cluster-level:**

- `cluster_all` - All cluster operations
- `cluster_monitor` - Monitor cluster health
- `cluster_composite_ops_ro` - Read-only composite operations
- `manage_snapshots` - Manage snapshots

**Index-level:**

- `read` - Read documents
- `search` - Search documents
- `write` - Write documents
- `delete` - Delete documents
- `crud` - Create, read, update, delete
- `create_index` - Create indices
- `manage` - Manage index settings

## OpenSearchRoleMapping

Map users, backend roles, or hosts to OpenSearch roles.

### Spec Reference

| Field             | Type     | Required | Description                     |
| ----------------- | -------- | -------- | ------------------------------- |
| `clusterRef.name` | string   | Yes      | WazuhCluster name               |
| `users`           | []string | No       | Internal users to map           |
| `backendRoles`    | []string | No       | Backend roles to map (OR logic) |
| `andBackendRoles` | []string | No       | Backend roles (AND logic)       |
| `hosts`           | []string | No       | Host patterns to map            |
| `description`     | string   | No       | Mapping description             |

**Note:** The CR name is used as the role name in OpenSearch.

### Examples

#### Map Users to Role

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRoleMapping
metadata:
  name: wazuh-alerts-reader # Role name
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  users:
    - readonly-user
    - analyst-user
  description: "Map users to alerts reader role"
```

#### Map Backend Roles (LDAP/SAML Groups)

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRoleMapping
metadata:
  name: all_access
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  backendRoles:
    - cn=admins,ou=groups,dc=example,dc=com
    - security-admins
```

#### Map with AND Logic

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRoleMapping
metadata:
  name: sensitive-data-access
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  # User must have BOTH backend roles
  andBackendRoles:
    - security-cleared
    - data-access-approved
```

#### Map by Host

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRoleMapping
metadata:
  name: internal-full-access
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  hosts:
    - "192.168.1.*"
    - "10.0.0.*"
```

## OpenSearchTenant

Create isolated spaces in OpenSearch Dashboards for multi-tenancy.

### Spec Reference

| Field             | Type   | Required | Description        |
| ----------------- | ------ | -------- | ------------------ |
| `clusterRef.name` | string | Yes      | WazuhCluster name  |
| `description`     | string | No       | Tenant description |

### Example

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchTenant
metadata:
  name: team-security
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  description: "Security team private space"
---
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchTenant
metadata:
  name: team-devops
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  description: "DevOps team private space"
```

### Grant Tenant Access

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchRole
metadata:
  name: security-team-role
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  tenantPermissions:
    - tenantPatterns:
        - "team-security"
      allowedActions:
        - kibana_all_write # Full access
    - tenantPatterns:
        - "team-devops"
      allowedActions:
        - kibana_all_read # Read-only
```

## OpenSearchActionGroup

Create reusable permission groups.

### Spec Reference

| Field             | Type     | Required | Description                  |
| ----------------- | -------- | -------- | ---------------------------- |
| `clusterRef.name` | string   | Yes      | WazuhCluster name            |
| `allowedActions`  | []string | Yes      | Actions or action groups     |
| `type`            | string   | No       | `cluster`, `index`, or `all` |
| `description`     | string   | No       | Group description            |

### Examples

```yaml
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchActionGroup
metadata:
  name: wazuh-read
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  type: index
  allowedActions:
    - read
    - search
    - get
  description: "Read operations for Wazuh indices"
---
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchActionGroup
metadata:
  name: wazuh-write
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  type: index
  allowedActions:
    - write
    - index
    - bulk
  description: "Write operations for Wazuh indices"
---
apiVersion: resources.wazuh.com/v1alpha1
kind: OpenSearchActionGroup
metadata:
  name: wazuh-full
  namespace: wazuh
spec:
  clusterRef:
    name: wazuh
  type: index
  allowedActions:
    - wazuh-read # Reference other action groups
    - wazuh-write
    - delete
  description: "Full CRUD for Wazuh indices"
```

## Status and Drift Detection

All OpenSearch CRDs support:

- **Phase**: `Pending`, `Ready`, `Failed`, `Conflict`
- **Drift Detection**: Detects manual changes in OpenSearch
- **Conflict Detection**: Detects multiple CRDs targeting same resource

### Check Status

```bash
# List all users
kubectl get osuser -n wazuh

# Example output:
NAME            CLUSTER   PHASE   DRIFT   AGE
admin           wazuh     Ready   false   2d
readonly-user   wazuh     Ready   false   1d
analyst         wazuh     Ready   true    5h  # Drift detected!

# Get details
kubectl describe osuser analyst -n wazuh
```

### Handle Drift

When `driftDetected: true`:

1. Someone modified the resource directly in OpenSearch
2. The operator will reconcile to match the CRD spec
3. To keep manual changes, update the CRD

## See Also

- [OpenSearch Index Management](opensearch-indices.md)
- [Authentication Configuration](opensearch-auth.md)
- [CRD Reference](../CRD-REFERENCE.md)
