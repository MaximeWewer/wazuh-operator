# Code Style Guide

This document describes coding conventions for the Wazuh Operator.

## Go Conventions

### General

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Run `golangci-lint` before committing

### Naming

```go
// Package names: lowercase, single word
package wazuhcluster

// Exported types: PascalCase
type WazuhClusterReconciler struct {}

// Unexported types: camelCase
type reconcileResult struct {}

// Constants: PascalCase for exported, camelCase for unexported
const DefaultReplicas = 3
const maxRetries = 5

// Variables: camelCase
var clusterName string
```

### Error Handling

```go
// Always check errors
if err != nil {
    return fmt.Errorf("failed to create resource: %w", err)
}

// Use error wrapping for context
if err := r.Client.Create(ctx, resource); err != nil {
    return fmt.Errorf("creating indexer StatefulSet: %w", err)
}

// Custom errors
var ErrClusterNotFound = errors.New("cluster not found")
```

### Comments

```go
// Package wazuhcluster implements the WazuhCluster controller.
package wazuhcluster

// WazuhClusterReconciler reconciles a WazuhCluster object.
// It manages the lifecycle of all Wazuh cluster components including
// the indexer, manager, and dashboard.
type WazuhClusterReconciler struct {
    client.Client
    Scheme *runtime.Scheme
}

// Reconcile handles the reconciliation loop for WazuhCluster resources.
// It ensures the actual state matches the desired state defined in the CR.
func (r *WazuhClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    // Implementation
}
```

## Project Structure

### File Organization

```
internal/controller/wazuhcluster/
├── wazuhcluster_controller.go    # Main reconciler
├── indexer_reconciler.go         # Indexer component
├── manager_reconciler.go         # Manager component
├── dashboard_reconciler.go       # Dashboard component
└── wazuhcluster_controller_test.go  # Tests
```

### Builder Pattern

```go
// Builder for complex objects
type IndexerStatefulSetBuilder struct {
    cluster *v1alpha1.WazuhCluster
    labels  map[string]string
}

func NewIndexerStatefulSetBuilder(cluster *v1alpha1.WazuhCluster) *IndexerStatefulSetBuilder {
    return &IndexerStatefulSetBuilder{
        cluster: cluster,
        labels:  make(map[string]string),
    }
}

func (b *IndexerStatefulSetBuilder) WithLabels(labels map[string]string) *IndexerStatefulSetBuilder {
    b.labels = labels
    return b
}

func (b *IndexerStatefulSetBuilder) Build() *appsv1.StatefulSet {
    // Build and return StatefulSet
}
```

## Kubernetes Conventions

### Labels

Use standard Kubernetes labels:

```go
labels := map[string]string{
    "app.kubernetes.io/name":       "wazuh-indexer",
    "app.kubernetes.io/instance":   cluster.Name,
    "app.kubernetes.io/component":  "wazuh-indexer",
    "app.kubernetes.io/part-of":    "wazuh",
    "app.kubernetes.io/managed-by": "wazuh-operator",
    "app.kubernetes.io/version":    cluster.Spec.Version,
}
```

### Annotations

Use `wazuh.com/` prefix for custom annotations:

```go
annotations := map[string]string{
    "wazuh.com/cert-hash":   certHash,
    "wazuh.com/config-hash": configHash,
}
```

### Owner References

Always set owner references:

```go
if err := ctrl.SetControllerReference(cluster, resource, r.Scheme); err != nil {
    return err
}
```

## Controller Conventions

### Reconciler Structure

```go
type MyReconciler struct {
    client.Client
    Scheme *runtime.Scheme
    Log    logr.Logger
}

func (r *MyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    log := r.Log.WithValues("resource", req.NamespacedName)

    // 1. Fetch the resource
    resource := &v1alpha1.MyResource{}
    if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
        if errors.IsNotFound(err) {
            return ctrl.Result{}, nil
        }
        return ctrl.Result{}, err
    }

    // 2. Handle deletion
    if !resource.DeletionTimestamp.IsZero() {
        return r.handleDeletion(ctx, resource)
    }

    // 3. Reconcile
    if err := r.reconcile(ctx, resource); err != nil {
        log.Error(err, "reconciliation failed")
        return ctrl.Result{}, err
    }

    // 4. Requeue
    return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}
```

### Status Updates

```go
// Update status in a separate function
func (r *MyReconciler) updateStatus(ctx context.Context, resource *v1alpha1.MyResource) error {
    resource.Status.Phase = "Running"
    resource.Status.ObservedGeneration = resource.Generation

    if err := r.Status().Update(ctx, resource); err != nil {
        if errors.IsConflict(err) {
            // Retry on conflict
            return r.updateStatus(ctx, resource)
        }
        return err
    }
    return nil
}
```

## Testing Conventions

### Test File Naming

```
mypackage/
├── myfile.go
└── myfile_test.go
```

### Test Structure

```go
var _ = Describe("Component", func() {
    var (
        ctx     context.Context
        cluster *v1alpha1.WazuhCluster
    )

    BeforeEach(func() {
        ctx = context.Background()
        cluster = &v1alpha1.WazuhCluster{
            // Setup
        }
    })

    Describe("Operation", func() {
        Context("when condition", func() {
            It("should behave correctly", func() {
                // Test
            })
        })
    })
})
```

## Documentation

### Code Comments

- All exported types and functions must have comments
- Comments should be complete sentences
- Start with the name of the thing being documented

### Inline Comments

```go
// Use sparingly for complex logic
result := computeHash(data) // SHA256 hash of certificate data
```

## Linting

Run before committing:

```bash
# Format
gofmt -w .

# Lint
golangci-lint run

# Vet
go vet ./...
```
