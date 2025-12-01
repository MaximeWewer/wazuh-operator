# Testing Guide

This document describes how to run and write tests for the Wazuh Operator.

## Running Tests

### Unit Tests

```bash
# Run all tests
make test

# Run tests with verbose output
go test -v ./...

# Run tests for a specific package
go test -v ./internal/controller/wazuhcluster/...

# Run a specific test
go test -v ./internal/controller/wazuhcluster/... -run TestReconcile
```

### Integration Tests (envtest)

The operator uses controller-runtime's envtest for integration tests:

```bash
# Run envtest tests
make test

# Set up envtest binaries manually if needed
make envtest
```

### End-to-End Tests

```bash
# Deploy to a test cluster
make deploy IMG=wazuh-operator:dev

# Run e2e tests (requires running cluster)
go test -v ./test/e2e/...
```

## Writing Tests

### Unit Test Structure

```go
package mypackage_test

import (
    "testing"

    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
)

func TestMyPackage(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "MyPackage Suite")
}

var _ = Describe("MyFunction", func() {
    Context("when input is valid", func() {
        It("should return expected result", func() {
            result := MyFunction("input")
            Expect(result).To(Equal("expected"))
        })
    })

    Context("when input is invalid", func() {
        It("should return error", func() {
            _, err := MyFunction("")
            Expect(err).To(HaveOccurred())
        })
    })
})
```

### Controller Tests with envtest

```go
var _ = Describe("WazuhCluster Controller", func() {
    ctx := context.Background()

    BeforeEach(func() {
        // Create test resources
        cluster := &v1alpha1.WazuhCluster{
            ObjectMeta: metav1.ObjectMeta{
                Name:      "test-cluster",
                Namespace: "default",
            },
            Spec: v1alpha1.WazuhClusterSpec{
                Version: "4.9.0",
            },
        }
        Expect(k8sClient.Create(ctx, cluster)).To(Succeed())
    })

    AfterEach(func() {
        // Clean up
        cluster := &v1alpha1.WazuhCluster{}
        Expect(k8sClient.Get(ctx, types.NamespacedName{
            Name:      "test-cluster",
            Namespace: "default",
        }, cluster)).To(Succeed())
        Expect(k8sClient.Delete(ctx, cluster)).To(Succeed())
    })

    It("should create indexer StatefulSet", func() {
        Eventually(func() error {
            sts := &appsv1.StatefulSet{}
            return k8sClient.Get(ctx, types.NamespacedName{
                Name:      "test-cluster-indexer",
                Namespace: "default",
            }, sts)
        }, timeout, interval).Should(Succeed())
    })
})
```

### Mocking External Dependencies

```go
// Mock OpenSearch client
type mockOpenSearchClient struct {
    mock.Mock
}

func (m *mockOpenSearchClient) CreateUser(ctx context.Context, user string) error {
    args := m.Called(ctx, user)
    return args.Error(0)
}

// In test
mockClient := &mockOpenSearchClient{}
mockClient.On("CreateUser", mock.Anything, "testuser").Return(nil)
```

## Test Fixtures

### Sample CRDs

Test fixtures are in `config/samples/`:

```bash
# Apply a test cluster
kubectl apply -f config/samples/wazuh_v1alpha1_wazuhcluster_minimal.yaml
```

### Test Mode for Certificates

Enable test mode for faster certificate expiry:

```bash
# Run operator with test mode
make run ARGS="--cert-test-mode"

# Or via Helm
helm install wazuh-operator ./charts/wazuh-operator \
  --set certTestMode=true
```

## Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage in browser
go tool cover -html=coverage.out

# Check coverage percentage
go tool cover -func=coverage.out
```

## Debugging Tests

### Verbose Logging

```go
// In test file
import "sigs.k8s.io/controller-runtime/pkg/log/zap"

var _ = BeforeSuite(func() {
    logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
})
```

### Slow Test Debugging

```bash
# Run with race detection
go test -race ./...

# Run with timeout
go test -timeout 5m ./...
```

## Common Test Patterns

### Testing Reconciliation

```go
It("should reconcile to ready state", func() {
    // Trigger reconciliation
    _, err := reconciler.Reconcile(ctx, ctrl.Request{
        NamespacedName: types.NamespacedName{
            Name:      "test-cluster",
            Namespace: "default",
        },
    })
    Expect(err).NotTo(HaveOccurred())

    // Verify state
    cluster := &v1alpha1.WazuhCluster{}
    Expect(k8sClient.Get(ctx, /* key */, cluster)).To(Succeed())
    Expect(cluster.Status.Phase).To(Equal(v1alpha1.ClusterPhaseRunning))
})
```

### Testing Status Updates

```go
It("should update status on error", func() {
    // Create invalid cluster
    cluster := &v1alpha1.WazuhCluster{
        Spec: v1alpha1.WazuhClusterSpec{
            Version: "invalid",
        },
    }

    // Reconcile
    _, _ = reconciler.Reconcile(ctx, /* request */)

    // Check status
    Eventually(func() string {
        k8sClient.Get(ctx, /* key */, cluster)
        return string(cluster.Status.Phase)
    }).Should(Equal("Failed"))
})
```

## CI/CD Integration

Tests run automatically in CI:

```yaml
# .github/workflows/test.yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - name: Run tests
        run: make test
```
