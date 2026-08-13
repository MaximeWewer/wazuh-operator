# Wazuh Operator Examples

Ready-to-use manifests, organized by CRD group. Each subdirectory has its own
`README.md`. Start with **quick-start**, then move to **production** and the
group-specific examples as needed.

## Directory Structure

```text
examples/
├── quick-start/          # Minimal deployment, step by step
├── production/           # Production-ready cluster + secrets
├── gitops/               # GitOps deployment (ArgoCD, Flux)
│
├── wazuh-cluster/        # WazuhCluster feature variants (TLS, drain, monitoring, gateway)
├── wazuh-content/        # WazuhRule, WazuhDecoder, WazuhCDBList, WazuhActiveResponse, WazuhIntegration, WazuhAgentGroup, WazuhAgentGroupAssignment
├── wazuh-certificate/    # WazuhCertificate
├── filebeat/             # WazuhFilebeat
├── wazuh-rbac/           # WazuhRole, WazuhUser (+ external IdP)
├── wazuh-backup/         # WazuhBackup, WazuhRestore
│
├── opensearch-security/  # OpenSearch users, roles, mappings, tenants, action groups, auth
├── opensearch-index/     # OpenSearch indices, templates, ISM policies
└── opensearch-backup/    # OpenSearch snapshot repositories, snapshots, policies, restore
```

## CRD Coverage

Every CRD has at least one example. Find the example for a given CRD here:

| CRD | Example(s) |
| --- | ---------- |
| WazuhCluster | [quick-start/](quick-start/), [production/](production/), [wazuh-cluster/](wazuh-cluster/) |
| WazuhCertificate | [wazuh-certificate/](wazuh-certificate/) |
| WazuhRule | [wazuh-content/wazuhrule-basic.yaml](wazuh-content/wazuhrule-basic.yaml) |
| WazuhDecoder | [wazuh-content/wazuhdecoder-basic.yaml](wazuh-content/wazuhdecoder-basic.yaml) |
| WazuhCDBList | [wazuh-content/wazuhcdblist-static.yaml](wazuh-content/wazuhcdblist-static.yaml), [wazuh-content/wazuhcdblist-url-iplist.yaml](wazuh-content/wazuhcdblist-url-iplist.yaml), [wazuh-content/wazuhcdblist-url-keylist.yaml](wazuh-content/wazuhcdblist-url-keylist.yaml) |
| WazuhActiveResponse | [wazuh-content/wazuhactiveresponse-firewall-drop.yaml](wazuh-content/wazuhactiveresponse-firewall-drop.yaml) |
| WazuhIntegration | [wazuh-content/wazuhintegration-basic.yaml](wazuh-content/wazuhintegration-basic.yaml) |
| WazuhAgentGroup | [wazuh-content/wazuhagentgroup-basic.yaml](wazuh-content/wazuhagentgroup-basic.yaml) |
| WazuhAgentGroupAssignment | [wazuh-content/wazuhagentgroupassignment-basic.yaml](wazuh-content/wazuhagentgroupassignment-basic.yaml) |
| WazuhFilebeat | [filebeat/](filebeat/) |
| WazuhRole | [wazuh-rbac/wazuhrole-admin.yaml](wazuh-rbac/wazuhrole-admin.yaml), [wazuh-rbac/wazuhrole-viewer.yaml](wazuh-rbac/wazuhrole-viewer.yaml) |
| WazuhUser | [wazuh-rbac/wazuhuser-basic.yaml](wazuh-rbac/wazuhuser-basic.yaml) |
| WazuhBackup | [wazuh-backup/](wazuh-backup/) |
| WazuhRestore | [wazuh-backup/wazuhrestore-basic.yaml](wazuh-backup/wazuhrestore-basic.yaml) |
| OpenSearchUser | [opensearch-security/opensearchuser-basic.yaml](opensearch-security/opensearchuser-basic.yaml) |
| OpenSearchRole | [opensearch-security/opensearchrole-basic.yaml](opensearch-security/opensearchrole-basic.yaml) |
| OpenSearchRoleMapping | [opensearch-security/opensearchrolemapping-basic.yaml](opensearch-security/opensearchrolemapping-basic.yaml) |
| OpenSearchTenant | [opensearch-security/opensearchtenant-basic.yaml](opensearch-security/opensearchtenant-basic.yaml) |
| OpenSearchActionGroup | [opensearch-security/opensearchactiongroup-basic.yaml](opensearch-security/opensearchactiongroup-basic.yaml) |
| OpenSearchAuthConfig | [opensearch-security/opensearchauthconfig-basic.yaml](opensearch-security/opensearchauthconfig-basic.yaml) |
| OpenSearchIndex | [opensearch-index/opensearchindex-basic.yaml](opensearch-index/opensearchindex-basic.yaml) |
| OpenSearchIndexTemplate | [opensearch-index/opensearchindextemplate-basic.yaml](opensearch-index/opensearchindextemplate-basic.yaml) |
| OpenSearchComponentTemplate | [opensearch-index/opensearchcomponenttemplate-basic.yaml](opensearch-index/opensearchcomponenttemplate-basic.yaml) |
| OpenSearchISMPolicy | [opensearch-index/opensearchismpolicy-basic.yaml](opensearch-index/opensearchismpolicy-basic.yaml) |
| OpenSearchSnapshotRepository | [opensearch-backup/](opensearch-backup/) |
| OpenSearchSnapshot | [opensearch-backup/opensearchsnapshot-manual.yaml](opensearch-backup/opensearchsnapshot-manual.yaml) |
| OpenSearchSnapshotPolicy | [opensearch-backup/opensearchsnapshotpolicy-daily.yaml](opensearch-backup/opensearchsnapshotpolicy-daily.yaml) |
| OpenSearchRestore | [opensearch-backup/opensearchrestore-basic.yaml](opensearch-backup/opensearchrestore-basic.yaml) |

## Quick Start

```bash
cat quick-start/00-prerequisites.md
kubectl apply -f quick-start/01-minimal-cluster.yaml
cat quick-start/02-verify-deployment.md
```

## Production

```bash
# Edit secrets (change all default passwords!) then apply
kubectl apply -f production/secrets-inline.yaml
kubectl apply -f production/wazuhcluster-production.yaml
```

## GitOps

Deploy the operator and clusters with ArgoCD or Flux - see
[gitops/argocd/README.md](gitops/argocd/README.md) and
[gitops/flux/README.md](gitops/flux/README.md).

## Reference

For the full API of every CRD, see the [CRD Reference](../CRD-REFERENCE.md).
