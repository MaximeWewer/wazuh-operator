# Detection Content

This guide covers the CRDs that manage **Wazuh Manager content** declaratively:
custom detection rules, log decoders, CDB lists, active response scripts,
integrations, and agent group files. It explains the shared model these CRDs
follow - how content reaches the manager pods and how it is wired into
`ossec.conf` - so you can reason about all of them at once.

For the exhaustive per-field API, see the [CRD Reference](../CRD-REFERENCE.md).
Ready-to-apply manifests live in [examples/wazuh-content/](../examples/wazuh-content/).

## Content CRDs at a glance

| CRD | Purpose | Mounted at | `ossec.conf` injection |
| --- | ------- | ---------- | ---------------------- |
| [WazuhRule](../CRD-REFERENCE.md#wazuhrule) | Custom detection rules (XML) | `/var/ossec/etc/rules/<name>.xml` | auto-scanned (`<rule_dir>`) |
| [WazuhDecoder](../CRD-REFERENCE.md#wazuhdecoder) | Custom log decoders (XML) | `/var/ossec/etc/decoders/<name>.xml` | auto-scanned (`<decoder_dir>`) |
| [WazuhCDBList](../CRD-REFERENCE.md#wazuhcdblist) | Key/value lookup lists | `/var/ossec/etc/lists/<listName>` | `<list>etc/lists/<listName></list>` (auto-injected) |
| [WazuhActiveResponse](../CRD-REFERENCE.md#wazuhactiveresponse) | Response scripts + triggers | `/var/ossec/active-response/bin/<script>` (0750 `root:wazuh`) | `<command>` + `<active-response>` (auto-injected) |
| [WazuhIntegration](../CRD-REFERENCE.md#wazuhintegration) | External integration scripts | `/var/ossec/integrations/custom-<name>` (0750 `root:wazuh`) | `<integration>` (auto-injected) |
| [WazuhAgentGroup](../CRD-REFERENCE.md#wazuhagentgroup) | Agent group shared files / `agent.conf` | `/var/ossec/etc/shared/<group>/<file>` | n/a (shared config) |

## The shared model

All content CRDs follow the same reconciliation pattern:

1. **Target selection.** Each CR references one or more clusters via
   `spec.clusterRefs: [{name, namespace}]` (cross-namespace is supported - the CR
   can live in any namespace). `spec.targetNodes` (`master` / `workers` / `all`,
   default `all`) narrows which manager nodes receive the content.

2. **Content ConfigMap.** The operator renders the content and writes it to a
   ConfigMap in **each target cluster's namespace** (named
   `<cr-namespace>-<cr-name>-<kind>`). Because cross-namespace owner references
   are forbidden, cleanup is **finalizer-driven**: deleting the CR removes the
   ConfigMaps it created.

3. **Mount.** The cluster reconciler mounts each ConfigMap into the manager
   StatefulSets (master and/or worker) at the path in the table above, using a
   read-only `subPath` mount. Executable content (active response, integrations)
   is mounted with `DefaultMode` 0750 which, combined with the pod `fsGroup`
   (`wazuh`), yields `root:wazuh 0750` - exactly what Wazuh requires.

4. **`ossec.conf` injection.** Rules and decoders are picked up automatically
   because Wazuh scans `etc/rules/` and `etc/decoders/`. CDB lists, active
   responses, and integrations must be **declared** in `ossec.conf`, so the
   operator injects the matching block automatically for every applied CR
   targeting the node (de-duplicated against any user-set entries in
   `spec.manager.config`).

5. **Rolling restart on change.** `subPath` ConfigMap mounts do **not** hot-update
   inside a running pod, and Wazuh loads most content at start. The operator
   therefore stamps a content-hash annotation on the pod template
   (`wazuh.com/rule-hash`, `wazuh.com/cdblist-hash`,
   `wazuh.com/activeresponse-hash`, …). When content changes, the hash changes
   and the manager StatefulSet rolls to reload it. Adding/removing a declared
   block (`<list>`, `<command>`, `<integration>`) also changes `ossec.conf`,
   which rolls the manager through the normal config-hash path.

### Change propagation order

```
apply/edit content CR
        │
        ▼
content CR reconciles → ConfigMap written, status → Applied
        │  (watch fires)
        ▼
WazuhCluster reconciles → mounts ConfigMap + injects ossec.conf + bumps hash
        │
        ▼
manager StatefulSet rolls → new pod loads the content
```

A freshly-applied CR only reaches `Applied` once its target `WazuhCluster`
exists. Content is only mounted once the CR is `Applied` (half-reconciled CRs are
skipped), so a transient `Pending` on first apply is normal.

## Per-CRD notes

### Rules and decoders

`WazuhRule` / `WazuhDecoder` carry XML content in `spec.rules` / `spec.decoders`.
They are auto-loaded from `etc/rules/` and `etc/decoders/` - no `ossec.conf` edit
needed. Use custom rule IDs in the `100000`–`999999` range; the operator
validates XML and flags duplicate IDs across CRs on overlapping clusters.

See: [wazuhrule-basic.yaml](../examples/wazuh-content/wazuhrule-basic.yaml),
[wazuhdecoder-basic.yaml](../examples/wazuh-content/wazuhdecoder-basic.yaml).

### CDB lists

`WazuhCDBList` manages [CDB lists](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)
(`key:value` files) used by rules for allow/block lookups. Content comes from one
of three mutually-exclusive sources:

- `entries` - static inline key/value pairs;
- `content` - raw inline text;
- `source` - a URL the operator fetches (Wazuh managers cannot fetch URLs
  themselves) with an optional `refreshInterval`, auth `headersSecretRef`, and
  `insecureSkipVerify`.

Raw `content`/`source` runs through a converter selected by `format`, after an
optional `skipLines` header strip:

| `format` | Converts | For |
| -------- | -------- | --- |
| `cdb` (default) | passthrough / normalize | hand-written `key:value` lists |
| `iplist` | IP/CIDR list → key-only, keeping the prefix for `/8 /16 /24 /32` | firewall / threat-intel IP lists |
| `keylist` | one key per line → `key:` | hash lists (VirusShare MD5 dumps), domain lists, user lists |

The operator auto-injects `<list>etc/lists/<listName></list>`; reference the list
from a rule with `<list field="...">etc/lists/<listName></list>`.

See: [wazuhcdblist-static.yaml](../examples/wazuh-content/wazuhcdblist-static.yaml),
[wazuhcdblist-url-iplist.yaml](../examples/wazuh-content/wazuhcdblist-url-iplist.yaml),
[wazuhcdblist-url-keylist.yaml](../examples/wazuh-content/wazuhcdblist-url-keylist.yaml).

### Active response

`WazuhActiveResponse` ships an executable script and its trigger. One CR = one
script + one `<command>` + one `<active-response>` block. The `<command><name>`
is `spec.name`; the `<executable>` is the script filename
(`name[.scriptExtension]`). Set `timeoutAllowed: true` and a `timeout` for
stateful (add/delete) responses; use `location` (`local` / `server` /
`defined-agent` / `all`), and at least one trigger (`level`, `rulesID`, or
`rulesGroup`).

See: [wazuhactiveresponse-firewall-drop.yaml](../examples/wazuh-content/wazuhactiveresponse-firewall-drop.yaml).

### Integrations

`WazuhIntegration` ships a `custom-<name>` script to `/var/ossec/integrations/`
and injects the `<integration>` block so `wazuh-integratord` forwards matching
alerts. Secret-backed `hookURL`/`apiKey` are resolved from the target cluster
namespace. See [wazuhintegration-basic.yaml](../examples/wazuh-content/wazuhintegration-basic.yaml).

### Agent groups

`WazuhAgentGroup` manages an agent group's `agent.conf` and shared files under
`/var/ossec/etc/shared/<group>/`. See
[wazuhagentgroup-basic.yaml](../examples/wazuh-content/wazuhagentgroup-basic.yaml).

## Troubleshooting

**A CDB list rule logs `List '...' could not be loaded`.** `wazuh-analysisd`
found a `<list>` declaration whose source file is missing or empty (it never
compiled to a `.cdb`). Confirm the source is present and non-empty in the pod:

```bash
kubectl exec <manager-pod> -n <ns> -c wazuh-manager -- ls -l /var/ossec/etc/lists/
# a loaded list shows both the source file AND a compiled <name>.cdb owned by wazuh:wazuh
```

For a `WazuhCDBList`, an empty result means the CR is not `Applied` (check
`kubectl get wazuhcdblist`) or the entries/URL resolved empty. Note that
sub-directory lists (e.g. `etc/lists/<dir>/<name>`) shipped outside these CRDs
are **not** managed by the operator.

**Active response / integration script does not run.** Verify ownership and mode
- Wazuh refuses scripts that are not `root:wazuh 0750`:

```bash
kubectl exec <manager-pod> -n <ns> -c wazuh-manager -- ls -l /var/ossec/active-response/bin/<script>
# expect: -rwxr-x--- root wazuh
```

**Content edited but the manager did not pick it up.** The manager reloads on a
rolling restart. Confirm the pod-template hash changed:

```bash
kubectl get sts <cluster>-manager-master -n <ns> \
  -o jsonpath='{.spec.template.metadata.annotations}' | tr ',' '\n' | grep wazuh.com
```

If the hash is unchanged, the CR likely did not reach `Applied` - inspect its
`status.clusterStatuses`.

## Related documentation

- [CRD Reference](../CRD-REFERENCE.md) - full field tables for every content CRD
- [Wazuh Content examples](../examples/wazuh-content/)
- [Common Issues](../troubleshooting/common-issues.md)
