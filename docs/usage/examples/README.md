# Wazuh Operator Examples

This directory contains ready-to-use examples for deploying Wazuh clusters using the Wazuh Operator.

## Directory Structure

```text
examples/
├── quick-start/         # Minimal examples to get started quickly
├── production/          # Production-ready configurations
├── opensearch-crds/     # OpenSearch security and index management CRDs
└── gitops/              # GitOps deployment examples (ArgoCD, Flux)
    ├── argocd/          # ArgoCD Application manifests
    └── flux/            # Flux HelmRelease and GitRepository manifests
```

## Quick Start

For a minimal deployment to test the operator:

```bash
# 1. Check prerequisites
cat quick-start/00-prerequisites.md

# 2. Deploy a minimal cluster
kubectl apply -f quick-start/01-minimal-cluster.yaml

# 3. Verify deployment
cat quick-start/02-verify-deployment.md
```

## Production Deployment

For production environments with full configuration:

```bash
# 1. Create secrets first
kubectl apply -f production/secrets.yaml

# 2. Deploy the cluster
kubectl apply -f production/wazuh-cluster.yaml
```

## OpenSearch CRDs

Manage OpenSearch users, roles, and index policies:

```bash
# Create a user
kubectl apply -f opensearch-crds/user.yaml

# Create a role
kubectl apply -f opensearch-crds/role.yaml

# Map role to user
kubectl apply -f opensearch-crds/rolemapping.yaml
```

## GitOps Deployment

For GitOps workflows using ArgoCD or Flux:

```bash
# ArgoCD
kubectl apply -f gitops/argocd/appproject.yaml
kubectl apply -f gitops/argocd/operator-application.yaml
kubectl apply -f gitops/argocd/cluster-application.yaml

# Flux
kubectl apply -f gitops/flux/
```

See [gitops/argocd/README.md](gitops/argocd/README.md) and [gitops/flux/README.md](gitops/flux/README.md) for detailed instructions.

## More Examples

See [config/samples/](../../../config/samples/) for additional examples covering:

- TLS configuration
- Email alerts
- Dashboard ingress
- Monitoring integration
- Log rotation
