# Wazuh Manager API RBAC (`WazuhRole` / `WazuhUser`)

The Wazuh dashboard talks to two backends:

- the **OpenSearch indexer** — governed by `OpenSearchRole` / `OpenSearchUser`
  (index reads, dashboard tenants);
- the **Wazuh Manager API** (port 55000) — governs the management menus
  (Management, Rules, Decoders, Agents config, Server management, Dev Tools…).

By default the dashboard reaches the Manager API with a single shared admin API
user (`run_as: false`), so **every** logged-in dashboard user sees and can edit
the management menus regardless of their OpenSearch role. To restrict those
menus per user, you map the authenticated identity onto a Wazuh **API** role.

The operator manages Wazuh API RBAC through two CRDs that push to the Manager
API and reconcile per target cluster:

| CRD | Purpose |
|-----|---------|
| `WazuhRole` (`wrole`) | A Wazuh API role with inline **policies** (actions/resources/effect) and inline auth-context **rules** (run_as mapping). |
| `WazuhUser` (`wuser`) | An internal Wazuh API user (username + password from a Secret) linked to one or more roles. |

## Enabling run_as (opt-in)

`run_as` lets the dashboard forward the logged-in identity's authentication
context to the Manager API, where **rules** map it to a role. It is **off by
default** and enabled per dashboard API endpoint in the `WazuhCluster` spec:

```yaml
apiVersion: resources.wazuh.com/v1
kind: WazuhCluster
metadata:
  name: wazuh-cluster
  namespace: wazuh
spec:
  dashboard:
    wazuhPlugin:
      defaultApiEndpoint:
        runAs: true          # <- enable run_as
```

Toggling this single field is enough — the operator drives the whole flow:

- sets the dashboard container's `RUN_AS` env so the effective `wazuh.yml`
  renders `run_as: true`, and rolls out the dashboard (the value is part of the
  deployment spec hash);
- sets `allow_run_as: true` on the dashboard's Manager API user
  (`DashboardReconciler.ensureAPIUserRunAs`, best-effort) so impersonation is
  permitted.

Both revert automatically when `runAs` is set back to `false`. (The
`allowRunAs` field on a `WazuhUser` is unrelated — it governs impersonation for
that *direct* API user, not the dashboard's shared user.)

## Read-only dashboard user (run_as flow)

1. Enable `runAs: true` (above).
2. Create a `WazuhRole` with read-only policies and an auth-context rule that
   matches your OpenSearch dashboard viewer (full manifest in
   `examples/wazuh-rbac/wazuhrole-viewer.yaml`):

   ```yaml
   kind: WazuhRole
   spec:
     clusterRefs: [{name: wazuh-cluster, namespace: wazuh}]
     policies:
       - name: wazuh-api-viewer-rules
         effect: allow
         actions: [rules:read]
         resources: ["rule:file:*"]      # typed resource — see note below
       - name: wazuh-api-viewer-agents
         effect: allow
         actions: [agent:read]
         resources: ["agent:id:*", "agent:group:*"]
       # ... one policy per resource type (mirrors built-in "readonly")
     rules:
       - name: map-viewers
         body: { FIND: { user_name: test-viewer } }
   ```

The CR `metadata.name` (or `spec.roleName`) becomes the Wazuh API role name.
Reserved Wazuh roles/policies/rules (ID < 100) are immutable — the operator
never modifies or deletes them, and a name collision with a reserved object is
reported as `Failed`. Use distinct names.

`examples/wazuh-rbac/wazuhrole-admin.yaml` shows the admin counterpart (the
built-in `administrator` role is reserved and cannot take custom rules, so
run_as admins need a dedicated role that enumerates the full typed action set).

### Resource typing (important)

Wazuh API resources are **typed per action**, and the dashboard performs
per-section permission checks against the *specific* resource. A generic
`"*:*:*"` resource is accepted by the raw API for some actions but **fails the
dashboard's section checks** — e.g. `rules:read` is checked against
`rule:file:*`, `security:read` against `user:id:*` and `role:id:*`, `agent:read`
against `agent:id:*`/`agent:group:*`. Always use the typed resource for each
action. The viewer/admin examples mirror the built-in `readonly` / `administrator`
action→resource pairs; recover them with:

```bash
# readonly = role_ids=2, administrator = role_ids=1
GET /security/roles?role_ids=2   # then GET /security/policies?policy_ids=<its policies>
```

## Direct API user (no dashboard)

For scripts/integrations, create a `WazuhUser` with a password Secret and the
roles to assign (`examples/wazuh-rbac/wazuhuser-basic.yaml`). `roles` may
reference a `WazuhRole` (by its resolved `roleName`) or a built-in role such as
`administrator` / `readonly`.

## Status & cleanup

Both CRDs report an aggregate `phase` (Pending/Ready/Failed) and per-cluster
status including the resolved Wazuh API object IDs. Reconciliation is
idempotent and self-heals drift. A finalizer removes the created role, policies,
rules and users from the Manager API on deletion (reserved objects are left
intact); if the API is unreachable during deletion the finalizer is still
removed and the objects may need manual cleanup.

## Verify

```bash
kubectl -n wazuh get wrole,wuser
kubectl -n wazuh describe wrole wazuh-api-viewer   # Phase=Ready, per-cluster RoleID >= 100
# On the Manager API:
#   GET /security/roles, /security/policies, /security/rules, /security/users
```
