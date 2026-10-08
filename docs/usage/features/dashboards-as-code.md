# Dashboards as code (`OpenSearchDashboardObject`)

`OpenSearchDashboardObject` manages OpenSearch Dashboards **saved objects** - dashboards,
visualizations, index patterns, saved searches - from an NDJSON export kept in Git. Build a
dashboard once in the UI, export it, commit the export, and the operator keeps every target
cluster in line with it.

For the exhaustive API, see the [CRD Reference](../CRD-REFERENCE.md#opensearchdashboardobject).
A ready-to-apply manifest lives in
[examples/opensearch-dashboards/](../examples/opensearch-dashboards/opensearchdashboardobject-configmap.yaml).

## Git is the source of truth

| Situation | What the operator does |
| --------- | ---------------------- |
| Export added or changed (spec or ConfigMap) | Imports it right away, overwriting the objects with the same type and id |
| Nothing changed | Re-imports it every `resyncInterval` (default `10m`) |
| A managed object edited or deleted in the Dashboards UI | The edit is lost at the next sync: the object is restored from the export |
| An object removed from the export | Deleted from the dashboard (`prune: true`, the default) |
| `tenant` changed | Objects imported into the new tenant, deleted from the old one |
| Resource deleted | Its objects are deleted from every target cluster (finalizer) |
| An object created in the UI that was never in the export | Never touched |

To change a managed dashboard, edit it in the UI, export it again and commit the new export -
otherwise the change disappears at the next sync. To give users a dashboard they may edit
freely, import it once by hand instead of managing it with this resource.

## Workflow

1. Build the dashboard in OpenSearch Dashboards.
2. Export it: **Dashboards Management > Saved objects**, select the dashboard, **Export**,
   keep **Include related objects** checked so its visualizations and index pattern come along.
   The export is an NDJSON file, one saved object per line.
3. Store it in a ConfigMap (or inline in `spec.source.ndjson` for small exports):

   ```bash
   kubectl create configmap soc-dashboards -n wazuh \
     --from-file=export.ndjson=soc-overview.ndjson \
     --dry-run=client -o yaml > soc-dashboards-configmap.yaml
   ```

4. Reference it from an `OpenSearchDashboardObject` and commit both:

   ```yaml
   apiVersion: resources.wazuh.com/v1
   kind: OpenSearchDashboardObject
   metadata:
     name: soc-overview
     namespace: wazuh
   spec:
     clusterRefs:
       - name: wazuh-cluster
         namespace: wazuh
     tenant: global
     source:
       configMapRef:
         name: soc-dashboards        # key defaults to export.ndjson
     resyncInterval: 10m
     prune: true
   ```

5. Check the sync:

   ```bash
   kubectl get osdashobj -n wazuh
   # NAME           TENANT   OBJECTS   PHASE   LAST SYNC   AGE
   # soc-overview   global   4         Ready   12s         1m
   ```

The ConfigMap must live in the same namespace as the resource. A change to it is picked up
immediately, without waiting for the resync.

## Tenants

`tenant` selects the OpenSearch Dashboards tenant the objects are imported into:

| Value | Tenant |
| ----- | ------ |
| `global` (default) | The shared global tenant |
| `private` | The private tenant of the operator's admin user (rarely useful) |
| any other name | A custom tenant, e.g. one created with an [`OpenSearchTenant`](opensearch-security.md) |

Multi-tenancy is enabled on a stock Wazuh dashboard, so objects imported without a tenant
would land in the admin user's private tenant, invisible to everyone else - hence the
`global` default.

Who can see the imported dashboards is governed by the usual OpenSearch security model:
`OpenSearchRole` tenant permissions and `OpenSearchRoleMapping`.

## How it works

- The operator calls the Dashboards saved objects API
  (`POST /api/saved_objects/_import?overwrite=true`) on the in-cluster dashboard Service, with
  the indexer admin credentials it already manages, sent as an `Authorization: Basic` header.
  The dashboard forwards any `Authorization` header to the indexer, which always keeps its
  internal basic-auth domain, so this works whatever the dashboard sign-in method: basic auth,
  OIDC, SAML, or JWT with the default `Authorization` header (verified on a JWT-only dashboard).
  The one exception is a JWT-only setup with a custom header (`OpenSearchAuthConfig`
  `jwt.jwtHeader`, e.g. Teleport's `Teleport-Jwt-Assertion`): the dashboard then only
  recognizes that header and answers 401 to the operator. On **Wazuh 4.12+**, enable
  `basicAuth` next to `jwt` in the `OpenSearchAuthConfig`, with a higher `order` than `jwt`
  (the operator rejects the reverse, which would hide the JWT domain): the dashboard
  switches to multiple authentication, where the basic handler accepts the operator's
  `Authorization` header whatever the JWT header is. Verified on Wazuh 4.14 with a custom
  header: JWT users sign in through the dashboard and the operator imports its objects. Side effect: the dashboard login page also offers the
  username/password form for internal users. This combination is not available on Wazuh 4.9
  to 4.11 (their dashboard cannot combine `jwt` with another method).
- HTTPS is verified against the dashboard's own CA (`<cluster>-dashboard-certs`), or plain
  HTTP is used when `spec.dashboard.enableSSL: false` on the `WazuhCluster`.
- The export is validated before anything is sent: each line must be a JSON object with a
  `type` and an `id`, and ids must be unique. The export summary line
  (`{"exportedCount": ...}`) is ignored.
- An object rejected by the dashboard (for example a visualization whose index pattern is
  missing from the export) fails the sync and is reported in `status.clusterStatuses[].message`
  and as a `SyncFailed` event.
- `status.objects` lists the managed objects; it is what pruning and deletion rely on, so
  objects that never came from the resource are never deleted.

## Troubleshooting

```bash
kubectl describe osdashobj soc-overview -n wazuh          # phase, message, events
kubectl get osdashobj soc-overview -n wazuh -o jsonpath='{.status.clusterStatuses}'
```

| Message | Cause |
| ------- | ----- |
| `Dashboard not reachable: ... has no dashboard` | The target `WazuhCluster` has no dashboard |
| `import failed: HTTP 401` | The dashboard uses JWT alone with a custom `jwtHeader` (on Wazuh 4.12+, also enable `basicAuth`), or the indexer admin credentials were rejected |
| `import rejected N object(s): visualization/x (missing_references)` | The export lacks an object it references - export again with related objects included |
| `invalid NDJSON export: ...` | The source is not a saved objects export |
| `failed to get ConfigMap ...` | The ConfigMap is missing or in another namespace |
