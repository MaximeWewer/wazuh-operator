# Wazuh Operator Examples

Ready-to-use manifests for deploying and operating Wazuh clusters with the Wazuh Operator.

Each subdirectory has its own `README.md` describing the manifests it contains. Start with **quick-start**, then move to **production** and the feature-specific examples as needed.

## Directory Structure

```text
examples/
├── quick-start/       # Minimal deployment, step by step
├── production/        # Production-ready cluster + secrets
├── wazuh-cluster/     # WazuhCluster feature variations (TLS, drain, monitoring, decoders, rules…)
├── wazuh-rbac/        # Wazuh API users and roles (incl. external IdP)
├── opensearch-crds/   # OpenSearch security and index/ISM management CRDs
├── backup-restore/    # Snapshots, repositories, backups and restores
├── filebeat/          # WazuhFilebeat log-forwarding configurations
├── gateway-api/       # Expose services via Gateway API
└── gitops/            # GitOps deployment (ArgoCD, Flux)
    ├── argocd/        # ArgoCD Application / AppProject manifests
    └── flux/          # Flux HelmRelease / GitRepository manifests
```

## Quick Start

Minimal deployment to test the operator (see [quick-start/README.md](quick-start/README.md)):

```bash
# 1. Check prerequisites
cat quick-start/00-prerequisites.md

# 2. Deploy a minimal cluster
kubectl apply -f quick-start/01-minimal-cluster.yaml

# 3. Verify the deployment
cat quick-start/02-verify-deployment.md
```

## Production

Production-ready configuration (see [production/README.md](production/README.md)):

```bash
# 1. Edit secrets (change all default passwords!) then apply
kubectl apply -f production/secrets-inline.yaml

# 2. Deploy the cluster
kubectl apply -f production/wazuhcluster-production.yaml
```

## Wazuh Cluster Variations

`WazuhCluster` examples for individual features (see [wazuh-cluster/README.md](wazuh-cluster/README.md)):
TLS, drain strategy, monitoring, multi-namespace, authd password, plus `WazuhAgentGroup`, `WazuhDecoder`, `WazuhIntegration` and `WazuhRule` samples.

## Wazuh API RBAC

Wazuh API users and roles (see [wazuh-rbac/README.md](wazuh-rbac/README.md)):

```bash
kubectl apply -f wazuh-rbac/wazuhrole-admin.yaml
kubectl apply -f wazuh-rbac/wazuhuser-basic.yaml
# External IdP role mapping:
kubectl apply -f wazuh-rbac/rbac-external-idp.yaml
```

## OpenSearch CRDs

Manage OpenSearch users, roles, tenants, index templates and ISM policies (see [opensearch-crds/README.md](opensearch-crds/README.md)):

```bash
kubectl apply -f opensearch-crds/opensearchuser-basic.yaml
kubectl apply -f opensearch-crds/opensearchrole-basic.yaml
kubectl apply -f opensearch-crds/opensearchrolemapping-basic.yaml
```

## Backup & Restore

Snapshot repositories, snapshots, backups and restores (see [backup-restore/README.md](backup-restore/README.md)):

```bash
# Register a repository, then snapshot the indexer
kubectl apply -f backup-restore/opensearchsnapshotrepository-s3.yaml
kubectl apply -f backup-restore/opensearchsnapshot-manual.yaml
```

## Filebeat

Log-forwarding configurations (see [filebeat/README.md](filebeat/README.md)).

## Gateway API

Expose Wazuh services via the Kubernetes Gateway API (see [gateway-api/README.md](gateway-api/README.md)).

## GitOps

Deploy the operator and clusters with ArgoCD or Flux:

```bash
# ArgoCD
kubectl apply -f gitops/argocd/appproject.yaml
kubectl apply -f gitops/argocd/operator-application.yaml
kubectl apply -f gitops/argocd/cluster-application.yaml

# Flux
kubectl apply -f gitops/flux/
```

See [gitops/argocd/README.md](gitops/argocd/README.md) and [gitops/flux/README.md](gitops/flux/README.md) for details.

## Reference

For the full API of every CRD shown here, see the [CRD Reference](../CRD-REFERENCE.md).
