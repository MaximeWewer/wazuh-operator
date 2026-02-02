# Testing Guide

Complete testing guide for the wazuh-operator project.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Unit & Integration Tests](#unit--integration-tests)
- [E2E Tests](#e2e-tests)
- [Testing New Code Changes](#testing-new-code-changes)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Go 1.25.4+
- Make
- Docker
- kubectl 1.24+
- For E2E: Minikube or a Kubernetes cluster

---

## Quick Start

```bash
# Run all tests
make test

# View coverage in browser
make test-coverage

# Run specific package tests
go test ./internal/... -v
```

---

## Unit & Integration Tests

### Running Tests

```bash
# Full test suite with coverage
make test

# Run specific controller tests
KUBEBUILDER_ASSETS="$(bin/setup-envtest use 1.31.0 -p path)" go test ./controllers -v

# Run a specific test
go test ./controllers -run TestWazuhCluster -v
```

### Understanding envtest

The operator uses [envtest](https://book.kubebuilder.io/reference/envtest.html) for integration testing with a real Kubernetes API server.

**How it works:**
1. `make test` downloads Kubernetes binaries via `setup-envtest`
2. `BeforeSuite` starts a local API server (etcd + kube-apiserver)
3. Tests create real CRs, StatefulSets, Deployments, etc.
4. `AfterSuite` stops the API server

**Binary locations:**
- Linux/WSL: `~/.local/share/kubebuilder-envtest/k8s/1.31.0-linux-amd64/`
- macOS: `~/Library/Application Support/io.kubebuilder.envtest/k8s/1.31.0-darwin-amd64/`

### Test Structure

| Type | Location | Framework |
|------|----------|-----------|
| Unit tests | `internal/**/*_test.go` | Ginkgo/Gomega |
| Integration tests | `controllers/*_test.go` | Ginkgo/Gomega + envtest |
| E2E tests | `test/e2e/*_test.go` | Ginkgo/Gomega |
| Test samples | `test/samples/*.yaml` | YAML manifests |

### Writing Tests

```go
var _ = Describe("WazuhCluster Controller", func() {
    Context("When creating a WazuhCluster", func() {
        It("Should create Manager StatefulSet", func() {
            // Create CR
            Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

            // Trigger reconciliation
            _, err := reconciler.Reconcile(ctx, reconcileRequest)
            Expect(err).NotTo(HaveOccurred())

            // Verify outcome
            Eventually(func() error {
                return k8sClient.Get(ctx, key, resource)
            }, timeout, interval).Should(Succeed())
        })
    })
})
```

### Coverage Goals

Target: **80%+ unit test coverage** (NFR-M1)

```bash
make test  # Coverage shown in output
```

---

## E2E Tests

### Setup

```bash
# Deploy test cluster
./wazuh-dev deploy S

# Verify deployment
./wazuh-dev status
```

### Test Scenarios

#### Basic Cluster Deployment

```bash
./test/e2e/scripts/test-deployment.sh
```

**Manual validation:**
```bash
# Verify workloads
kubectl get statefulsets,deployments -n wazuh

# Verify cluster status
kubectl get wazuhcluster wazuh-cluster -n wazuh -o jsonpath='{.status.phase}'
# Expected: Running

# Verify TLS certificates
kubectl get secrets -n wazuh | grep -E "(manager|indexer|dashboard).*cert"
```

#### Topology Scaling

```bash
# Scale up
kubectl patch wazuhcluster wazuh-cluster -n wazuh --type=merge -p '
spec:
  indexer:
    replicas: 3
  manager:
    workers:
      replicas: 2
  dashboard:
    replicas: 2
'

# Monitor
kubectl get statefulsets -n wazuh -w
```

#### Configuration Updates

```bash
./test/e2e/scripts/test-configuration.sh
```

**Manual validation:**
```bash
# Update resources
kubectl patch wazuhcluster wazuh-cluster -n wazuh --type=merge -p '
spec:
  manager:
    master:
      resources:
        limits:
          cpu: "2000m"
          memory: "2Gi"
'

# Watch rolling update
kubectl rollout status statefulset/wazuh-cluster-manager-master -n wazuh
```

#### Deletion with Cleanup

```bash
# Verify finalizer
kubectl get wazuhcluster wazuh-cluster -n wazuh -o jsonpath='{.metadata.finalizers}'

# Delete cluster
kubectl delete wazuhcluster wazuh-cluster -n wazuh

# Verify cleanup
kubectl wait --for=delete wazuhcluster/wazuh-cluster -n wazuh --timeout=120s
kubectl get all -n wazuh  # Should be empty
```

### NFR Validation

| NFR | Test | Target |
|-----|------|--------|
| NFR-P1 | Reconciliation time | < 5 seconds |
| NFR-P4 | Pod readiness | < 10 minutes |
| NFR-S1 | TLS everywhere | All connections encrypted |
| FR6 | Zero downtime | No failures during rolling update |

---

## Testing New Code Changes

When testing new code, ensure you're running the **new codebase**, not an old deployment.

### Quick Cleanup & Rebuild

```bash
# 1. Cleanup existing deployment
kubectl delete wazuhcluster wazuh-cluster -n wazuh
kubectl delete namespace wazuh-system --timeout=60s
kubectl delete namespace wazuh --timeout=60s

# 2. Rebuild operator image
make docker-build IMG=wazuh-operator:latest

# 3. Load into Minikube (if using)
minikube image load wazuh-operator:latest --profile wazuh-dev

# 4. Redeploy
./scripts/wazuh-dev deploy S

# 5. Verify new image
kubectl describe pod -n wazuh-system -l app.kubernetes.io/name=wazuh-operator | grep Image:
```

### Full Reset (Nuclear Option)

```bash
./scripts/wazuh-dev cleanup --force
make docker-build IMG=wazuh-operator:latest
minikube image load wazuh-operator:latest --profile wazuh-dev
./scripts/wazuh-dev deploy S
```

---

## Troubleshooting

### envtest: "etcd: no such file or directory"

Run `make test` instead of `go test ./...`. The Makefile sets up envtest properly.

### Tests are slow

envtest starts a real API server (~2-3 seconds startup). This is normal for integration tests.

### Operator pod shows old image

```bash
kubectl delete pod -n wazuh-system -l app.kubernetes.io/name=wazuh-operator
kubectl get pods -n wazuh-system -w
```

### Namespace stuck in Terminating

```bash
# Check blocking resources
kubectl api-resources --verbs=list --namespaced -o name | \
  xargs -n 1 kubectl get --show-kind --ignore-not-found -n wazuh

# Force deletion (last resort)
kubectl get namespace wazuh -o json | \
  jq '.spec.finalizers = []' | \
  kubectl replace --raw "/api/v1/namespaces/wazuh/finalize" -f -
```

### WazuhCluster stuck in deletion

```bash
# Check operator logs
kubectl logs -n wazuh-system deployment/wazuh-operator-controller-manager --tail=100

# Remove finalizer (DANGEROUS - testing only)
kubectl patch wazuhcluster wazuh-cluster -n wazuh --type='json' \
  -p='[{"op": "remove", "path": "/metadata/finalizers"}]'
```

---

## References

- [Kubebuilder Testing](https://book.kubebuilder.io/reference/testing.html)
- [Ginkgo Documentation](https://onsi.github.io/ginkgo/)
- [Gomega Matchers](https://onsi.github.io/gomega/)
- [envtest API](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest)
