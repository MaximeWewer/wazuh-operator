# Flux Integration

This directory contains Flux resources for deploying Wazuh Operator and clusters.

## Prerequisites

- Flux v2 installed in your cluster
- Access to the Wazuh Operator Helm charts or Git repository

## Quick Start

1. **Create the GitRepository/HelmRepository source**:

```bash
kubectl apply -f helm-repository.yaml
# Or for Git-based:
kubectl apply -f git-repository.yaml
```

2. **Install the operator HelmRelease**:

```bash
kubectl apply -f operator-helmrelease.yaml
```

3. **Install a Wazuh cluster HelmRelease**:

```bash
kubectl apply -f cluster-helmrelease.yaml
```

## Files

- `helm-repository.yaml` - HelmRepository source for OCI charts
- `git-repository.yaml` - GitRepository source for Git-based deployment
- `operator-helmrelease.yaml` - HelmRelease for the operator
- `cluster-helmrelease.yaml` - HelmRelease for Wazuh clusters
- `kustomization.yaml` - Flux Kustomization for organizing resources

## Using with Flux Kustomization

For a complete GitOps setup, use Flux Kustomization:

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: wazuh
  namespace: flux-system
spec:
  interval: 10m
  path: ./examples/gitops/flux
  prune: true
  sourceRef:
    kind: GitRepository
    name: wazuh-operator
```

## Multi-Environment Setup

For multiple environments, create separate directories:

```
flux/
├── base/
│   ├── operator-helmrelease.yaml
│   └── kustomization.yaml
├── staging/
│   ├── cluster-helmrelease.yaml
│   └── kustomization.yaml
└── production/
    ├── cluster-helmrelease.yaml
    └── kustomization.yaml
```

## Secrets Management

For production, use Flux SOPS or External Secrets:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: wazuh-credentials
type: Opaque
stringData:
  admin-password: ENC[AES256_GCM,data:...,type:str]
```
