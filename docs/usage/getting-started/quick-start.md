# Wazuh Operator - Quick Start Guide

Quick start guide to deploy and test the Wazuh operator locally.

## Quick Start (2 commands)

```bash
# 1. Deploy everything (operator + full cluster)
./wazuh-dev deploy

# 2. Check status
./wazuh-dev status
```

That's it!

## Prerequisites

See [Prerequisites and Requirements](../../requirements.md) for complete requirements.

**Quick check:**

```bash
docker --version && minikube version && kubectl version --client && helm version
```

## Essential Commands

### Deployment

```bash
# Standard deployment (profile S - recommended)
./wazuh-dev deploy

# Minimal deployment (quick tests)
./wazuh-dev deploy XS

# Medium deployment (performance tests)
./wazuh-dev deploy M
```

### Monitoring

```bash
# Global status
./wazuh-dev status

# Logs and events
./wazuh-dev logs

# Specific logs
./wazuh-dev logs-operator
./wazuh-dev logs-manager
./wazuh-dev logs-indexer
./wazuh-dev logs-dashboard
```

### Dashboard Access

```bash
# Option 1: Open in browser (recommended)
./wazuh-dev dashboard

# Option 2: Manual port forwarding
./wazuh-dev port-forward
# Then access: https://localhost:5601
```

**Credentials:**

- Username: `admin`
- Password: `MyS3cureP@ssw0rd`

### Maintenance

```bash
# Full restart
./wazuh-dev restart

# Rebuild image only
./wazuh-dev rebuild

# Full cleanup
./wazuh-dev cleanup
```

### Debug

```bash
# Shell into a pod
./wazuh-dev shell-manager
./wazuh-dev shell-indexer

# Integration tests
./wazuh-dev test
```

## Sizing Profiles

| Profile | Use Case | Resources |
|---------|----------|-----------|
| **XS** | CI/CD, quick tests | ~3Gi RAM, ~1.5 CPU |
| **S** | Local development (recommended) | ~7Gi RAM, ~3.5 CPU |
| **M** | Staging, small production | ~19Gi RAM, ~10 CPU |
| **L/XL** | Production, enterprise | See sizing guide |

For detailed resource requirements, see [Sizing Guide](../features/sizing.md).

## Advanced Configuration

### Resource Customization

Create a `.env` file:

```bash
cp scripts/.env.example .env
```

Edit `.env`:

```bash
# Example: More resources for performance testing
MINIKUBE_CPUS=8
MINIKUBE_MEMORY=16384
SIZING_PROFILE=M
```

Then deploy:

```bash
source .env && ./wazuh-dev deploy
```

### Individual Scripts

If you prefer low-level scripts:

```bash
# Full deployment
./scripts/deploy-local.sh

# Status
./scripts/status.sh

# Cleanup
./scripts/cleanup-local.sh
```

## Troubleshooting

### Problem: Pods in CrashLoopBackOff

```bash
# View logs
kubectl logs -n wazuh <pod-name> --previous

# View events
kubectl describe pod -n wazuh <pod-name>
```

### Problem: Not enough resources

```bash
# Increase Minikube resources
MINIKUBE_CPUS=6 MINIKUBE_MEMORY=12288 ./wazuh-dev deploy
```

### Problem: Image not found

```bash
# Check images in Minikube
minikube ssh --profile wazuh-dev -- docker images | grep wazuh

# Rebuild and redeploy
./wazuh-dev restart
```

### Problem: Minikube won't start

```bash
# Delete and recreate
minikube delete --profile wazuh-dev
./wazuh-dev deploy
```

## Complete Documentation

For more details, see:

- **[scripts/README.md](../../../scripts/README.md)** - Complete scripts documentation
- **[charts/wazuh-operator/](../../../charts/wazuh-operator/)** - Operator Helm chart
- **[charts/wazuh-cluster/](../../../charts/wazuh-cluster/)** - Cluster Helm chart
- **[docs/](../../)** - General documentation

## Deployed Architecture

After a successful deployment (profile S):

```text
+-----------------------------------+
|     Minikube Cluster              |
|     (4 CPUs, 8GB RAM, 40GB disk)  |
|                                   |
|  +-----------------------------+  |
|  |  Namespace: wazuh-operator    |  |
|  |  - Wazuh Operator (1 replica)|  |
|  +-----------------------------+  |
|                                   |
|  +-----------------------------+  |
|  |  Namespace: wazuh           |  |
|  |  - Manager Master (1 replica)|  |
|  |  - Manager Worker (1 replica)|  |
|  |  - Indexer (1 replica)      |  |
|  |  - Dashboard (1 replica)    |  |
|  +-----------------------------+  |
+-----------------------------------+
```

## Typical Development Workflow

```bash
# 1. Initial deployment
./wazuh-dev deploy

# 2. Verify everything works
./wazuh-dev status

# 3. Access dashboard
./wazuh-dev dashboard

# 4. Make code changes...
vim controllers/wazuhcluster_controller.go

# 5. Redeploy with changes
./wazuh-dev restart

# 6. View logs
./wazuh-dev logs-operator

# 7. Debugging
./wazuh-dev shell-manager

# 8. Tests
./wazuh-dev test

# 9. Final cleanup
./wazuh-dev cleanup
```

## Usage Examples

### Quick Development

```bash
# Minimal deployment for quick tests
SIZING_PROFILE=XS ./wazuh-dev deploy

# Integration tests
./wazuh-dev test

# Cleanup
./wazuh-dev cleanup --force
```

### Performance Testing

```bash
# Deployment with more resources
cat > .env << EOF
MINIKUBE_CPUS=8
MINIKUBE_MEMORY=16384
MINIKUBE_DISK_SIZE=80g
SIZING_PROFILE=M
EOF

source .env && ./wazuh-dev deploy
```

### Deep Debugging

```bash
# Real-time logs from all components
./wazuh-dev logs-operator &
./wazuh-dev logs-manager &
./wazuh-dev logs-indexer &
./wazuh-dev logs-dashboard &

# In another terminal
./wazuh-dev status
```

## Tips

1. **Use `./wazuh-dev` instead of individual scripts** for a better experience
2. **Profile S is optimal for local development** (good balance of resources/completeness)
3. **Use `./wazuh-dev restart` rather than cleanup + deploy** (faster)
4. **Builds are cache-free** to ensure clean builds
5. **Old images are automatically cleaned** to save disk space

## Need Help?

```bash
# CLI help
./wazuh-dev help

# Individual script help
./scripts/deploy-local.sh --help
./scripts/cleanup-local.sh --help
./scripts/status.sh --help
```

## Post-Deployment Checklist

- [ ] Minikube starts correctly
- [ ] Operator deployed and ready (1/1)
- [ ] Manager Master ready (1/1)
- [ ] Manager Worker ready (1/1 for profile S)
- [ ] Indexer ready (1/1)
- [ ] Dashboard ready (1/1)
- [ ] WazuhCluster CR status = Ready
- [ ] Dashboard accessible via browser
- [ ] Dashboard authentication works

If all items are checked: **Deployment successful!**

## Release Cycle

```bash
# 1. Development
git checkout -b feature/my-feature
# ... make changes ...

# 2. Local test
./wazuh-dev deploy
./wazuh-dev test

# 3. Commit
git add .
git commit -m "feat: my feature"

# 4. Cleanup
./wazuh-dev cleanup

# 5. Push
git push origin feature/my-feature
```
