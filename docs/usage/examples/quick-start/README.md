# Quick Start Examples

Minimal, step-by-step deployment to try the operator on a test cluster.

| File | Description |
| ---- | ----------- |
| [00-prerequisites.md](00-prerequisites.md) | What you need before deploying |
| [01-minimal-cluster.yaml](01-minimal-cluster.yaml) | Minimal `WazuhCluster` (`wazuh-quickstart`) |
| [02-verify-deployment.md](02-verify-deployment.md) | Verify pods, services and access |

## Usage

```bash
# 1. Read the prerequisites
cat 00-prerequisites.md

# 2. Deploy the minimal cluster
kubectl apply -f 01-minimal-cluster.yaml

# 3. Verify
cat 02-verify-deployment.md
```

For a production-grade setup, see [../production/](../production/).
