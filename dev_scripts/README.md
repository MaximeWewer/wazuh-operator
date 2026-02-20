# Wazuh Operator - Local Development Scripts

Automation scripts for local development and testing of the Wazuh operator.

## Available Scripts

### `deploy-local.sh` - Automated Full Deployment

All-in-one script to deploy the operator and a complete Wazuh cluster on Minikube.

**What it does:**

1. Creates a Minikube cluster with sufficient resources
2. Builds the operator Docker image (no cache)
3. Loads the image into Minikube
4. Cleans up old Docker images
5. Deploys the operator via Helm
6. Deploys a complete Wazuh cluster via Helm
7. Verifies all components are ready
8. Displays access information

**Basic usage:**

```bash
./scripts/deploy-local.sh
```

**Configuration via environment variables:**

```bash
# Cluster size profile (XS, S, M, L, XL)
SIZING_PROFILE=S ./scripts/deploy-local.sh

# Custom Minikube profile
MINIKUBE_PROFILE=my-wazuh MINIKUBE_CPUS=6 MINIKUBE_MEMORY=12288 ./scripts/deploy-local.sh

# Custom image tag
OPERATOR_TAG=v1.0.0-test ./scripts/deploy-local.sh
```

**Available environment variables:**

| Variable             | Description           | Default           |
| -------------------- | --------------------- | ----------------- |
| `MINIKUBE_PROFILE`   | Minikube profile name | `wazuh-dev`       |
| `MINIKUBE_CPUS`      | Number of CPUs        | `4`               |
| `MINIKUBE_MEMORY`    | RAM in MB             | `8192` (8GB)      |
| `MINIKUBE_DISK_SIZE` | Disk size             | `40g`             |
| `MINIKUBE_DRIVER`    | Minikube driver       | `docker`          |
| `SIZING_PROFILE`     | Cluster size profile  | `S`               |
| `OPERATOR_TAG`       | Image tag             | `dev-<timestamp>` |
| `OPERATOR_NAMESPACE` | Operator namespace    | `wazuh-system`    |
| `CLUSTER_NAMESPACE`  | Cluster namespace     | `wazuh`           |
| `CLUSTER_NAME`       | Cluster name          | `wazuh-cluster`   |

### `cleanup-local.sh` - Full Cleanup

Removes all locally deployed components.

**What it does:**

1. Uninstalls the Wazuh cluster (Helm)
2. Uninstalls the operator (Helm)
3. Deletes namespaces
4. Deletes the Minikube cluster
5. Removes Docker images

**Usage:**

```bash
# Interactive mode (asks for confirmation)
./scripts/cleanup-local.sh

# Force mode (no confirmation)
./scripts/cleanup-local.sh --force
```

## Sizing Profiles

The deployment script supports several predefined size profiles:

### XS - Extra Small (Minimal Tests)

- **Use case:** Quick tests, CI/CD
- **Resources:** ~3Gi RAM, ~1.5 CPU, ~15Gi storage
- **Components:**
  - Indexer: 1 replica (1.5-2Gi RAM)
  - Manager Master: 1 replica (256Mi-512Mi RAM)
  - Manager Workers: 0 replicas (disabled)
  - Dashboard: 1 replica (256Mi-512Mi RAM)

### S - Small (Development/Test)

- **Use case:** Local development environment
- **Resources:** ~3.5-7Gi RAM, ~1.75-3.5 CPU, ~40Gi storage
- **Components:**
  - Indexer: 1 replica (1-2Gi RAM)
  - Manager Master: 1 replica (1-2Gi RAM)
  - Manager Workers: 1 replica (1-2Gi RAM)
  - Dashboard: 1 replica (512Mi-1Gi RAM)

### M - Medium (Small Production)

- **Use case:** Staging environment, small production
- **Resources:** ~19Gi RAM, ~10 CPU, ~210Gi storage
- **Components:**
  - Indexer: 3 replicas (4Gi RAM each)
  - Manager Master: 1 replica (2Gi RAM)
  - Manager Workers: 2 replicas (2Gi RAM each)
  - Dashboard: 1 replica (1Gi RAM)

### L - Large (Production)

- **Use case:** Standard production
- **Resources:** ~44Gi RAM, ~22 CPU, ~500Gi storage

### XL - Extra Large (Enterprise)

- **Use case:** Large-scale production
- **Resources:** ~140Gi RAM, ~70 CPU, ~1700Gi storage

## Usage Examples

### Quick Deployment (Profile S - Recommended for Dev)

```bash
# Profile S with all components
SIZING_PROFILE=S ./scripts/deploy-local.sh
```

### Minimal Deployment (Profile XS - Quick Tests)

```bash
# For quick tests with minimal resources
SIZING_PROFILE=XS ./scripts/deploy-local.sh
```

### Deployment with Custom Resources

```bash
# More powerful cluster for performance testing
MINIKUBE_CPUS=8 \
MINIKUBE_MEMORY=16384 \
SIZING_PROFILE=M \
./scripts/deploy-local.sh
```

### Complete Development Cycle

```bash
# 1. Initial deployment
SIZING_PROFILE=S ./scripts/deploy-local.sh

# 2. Make code changes...

# 3. Quick redeploy (delete and recreate)
./scripts/cleanup-local.sh --force && \
SIZING_PROFILE=S ./scripts/deploy-local.sh

# 4. Final cleanup
./scripts/cleanup-local.sh
```

## Dashboard Access

After deployment, the script displays access instructions. Two options:

### Option 1: Minikube Service (Recommended)

```bash
minikube service wazuh-cluster-dashboard -n wazuh --profile wazuh-dev
```

Automatically opens the browser with the correct URL.

### Option 2: Port Forward

```bash
kubectl port-forward -n wazuh svc/wazuh-cluster-dashboard 5601:5601
```

Then access: <https://localhost:5601>

**Default credentials:**

- Username: `admin`
- Password: `MyS3cureP@ssw0rd`

## Useful Commands After Deployment

```bash
# View operator logs
kubectl logs -n wazuh-system -l app.kubernetes.io/name=wazuh-operator -f

# View cluster status
kubectl get wazuhcluster -n wazuh

# View all pods
kubectl get pods -n wazuh

# View PVCs
kubectl get pvc -n wazuh

# Describe WazuhCluster CR
kubectl describe wazuhcluster wazuh-cluster -n wazuh

# Access pod shell
kubectl exec -it -n wazuh wazuh-cluster-manager-master-0 -- bash

# View events
kubectl get events -n wazuh --sort-by='.lastTimestamp'
```

## Troubleshooting

### Problem: Minikube won't start

```bash
# Check status
minikube status --profile wazuh-dev

# Delete and recreate
minikube delete --profile wazuh-dev
./scripts/deploy-local.sh
```

### Problem: Pods in CrashLoopBackOff

```bash
# View logs of problematic pod
kubectl logs -n wazuh <pod-name> --previous

# Describe pod to see events
kubectl describe pod -n wazuh <pod-name>
```

### Problem: Images not found

```bash
# Check images in Minikube
minikube ssh --profile wazuh-dev -- docker images | grep wazuh

# Reload image
minikube image load wazuh-operator:latest --profile wazuh-dev
```

### Problem: Not enough resources

```bash
# Increase Minikube resources
MINIKUBE_CPUS=6 MINIKUBE_MEMORY=12288 ./scripts/deploy-local.sh
```

## Build Without Deployment

If you only want to build the image:

```bash
cd /home/adminsys/wazuh-operator
make docker-build IMG=wazuh-operator:dev
```

## Important Notes

1. **No-Cache Builds:** The script always builds with `--no-cache` to ensure clean builds
2. **Automatic Cleanup:** Old images are automatically cleaned up
3. **Timeout:** Helm deployment has a 10-minute timeout by default
4. **Validation:** The script waits for all components to be ready before finishing
5. **Profile S:** Recommended for local development (good balance of resources/completeness)

## Deployment Architecture

```text
+-----------------------------------+
|         Minikube Cluster          |
|                                   |
|  +-----------------------------+  |
|  |   Namespace: wazuh-system   |  |
|  |                             |  |
|  |   +---------------------+   |  |
|  |   |  Wazuh Operator     |   |  |
|  |   |  (Deployment)       |   |  |
|  |   +---------------------+   |  |
|  +-----------------------------+  |
|                                   |
|  +-----------------------------+  |
|  |   Namespace: wazuh          |  |
|  |                             |  |
|  |   +---------------------+   |  |
|  |   |  Manager Master     |   |  |
|  |   |  (StatefulSet)      |   |  |
|  |   +---------------------+   |  |
|  |                             |  |
|  |   +---------------------+   |  |
|  |   |  Manager Workers    |   |  |
|  |   |  (StatefulSet)      |   |  |
|  |   +---------------------+   |  |
|  |                             |  |
|  |   +---------------------+   |  |
|  |   |  Indexer            |   |  |
|  |   |  (StatefulSet)      |   |  |
|  |   +---------------------+   |  |
|  |                             |  |
|  |   +---------------------+   |  |
|  |   |  Dashboard          |   |  |
|  |   |  (Deployment)       |   |  |
|  |   +---------------------+   |  |
|  +-----------------------------+  |
+-----------------------------------+
```

## Support

For more information on Helm charts:

- Operator Charts: `charts/wazuh-operator/`
- Cluster Charts: `charts/wazuh-cluster/`
- Documentation: `docs/`
