# ArgoCD Integration

This directory contains ArgoCD Application manifests for deploying Wazuh Operator and clusters.

## Prerequisites

- ArgoCD installed in your cluster
- Access to the Wazuh Operator Helm charts or Git repository

## Quick Start

1. **Install the operator Application**:

```bash
kubectl apply -f operator-application.yaml
```

2. **Install a Wazuh cluster Application**:

```bash
kubectl apply -f cluster-application.yaml
```

## Files

- `operator-application.yaml` - ArgoCD Application for the operator
- `cluster-application.yaml` - ArgoCD Application for a Wazuh cluster
- `appproject.yaml` - Optional AppProject for isolation

## Customization

### Using Helm Values

Edit the `helm.values` section in the Application manifests to customize:

```yaml
spec:
  source:
    helm:
      values: |
        operator:
          resources:
            limits:
              memory: 1Gi
```

### Using Kustomize

For kustomize-based deployment:

```yaml
spec:
  source:
    repoURL: https://github.com/MaximeWewer/wazuh-operator.git
    path: config/overlays/production
    targetRevision: main
```

## Multi-Environment Setup

For multiple environments, create separate Applications with different:
- `spec.destination.namespace`
- `spec.source.helm.values`
- `spec.source.targetRevision` (for different versions)

## Sync Policies

The examples use manual sync. For automated GitOps:

```yaml
spec:
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```
