# Operator Design

This document describes the overall architecture and design decisions of the Wazuh Operator.

## Overview

The Wazuh Operator is a Kubernetes operator built with Kubebuilder v4 that manages Wazuh security platform deployments. It follows the operator pattern to provide declarative management of Wazuh clusters.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Kubernetes API Server                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Wazuh Operator                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐          │
│  │ WazuhCluster    │  │ OpenSearch CRD  │  │ Wazuh Config    │          │
│  │ Controller      │  │ Controllers     │  │ Controllers     │          │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘          │
│           │                    │                    │                   │
│           ▼                    ▼                    ▼                   │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │                    Reconciliation Engine                     │       │
│  │  - Certificate Management                                    │       │
│  │  - Resource Building                                         │       │
│  │  - Status Updates                                            │       │
│  └─────────────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Managed Resources                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐         │
│  │ StatefulSet│  │ Deployment │  │  Service   │  │   Secret   │         │
│  │ (Indexer)  │  │ (Dashboard)│  │            │  │ (Certs)    │         │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐         │
│  │ StatefulSet│  │  ConfigMap │  │    PVC     │  │  CronJob   │         │
│  │ (Manager)  │  │            │  │            │  │ (LogRot)   │         │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Controllers

### WazuhCluster Controller

The main controller that orchestrates all components:

- **Location**: `internal/controller/wazuhcluster/`
- **Responsibilities**:
  - Reconcile certificate secrets
  - Deploy Indexer (OpenSearch) StatefulSet
  - Deploy Manager (master + workers) StatefulSets
  - Deploy Dashboard Deployment
  - Create Services, ConfigMaps, PVCs
  - Manage Log Rotation CronJob

### OpenSearch CRD Controllers

Controllers for managing OpenSearch security and index management:

- **Location**: `internal/controller/opensearch/`
- **CRDs Managed**:
  - OpenSearchUser, OpenSearchRole, OpenSearchRoleMapping
  - OpenSearchTenant, OpenSearchActionGroup
  - OpenSearchIndexTemplate, OpenSearchComponentTemplate
  - OpenSearchISMPolicy, OpenSearchSnapshotPolicy, OpenSearchIndex

### Wazuh Config Controllers

Controllers for managing Wazuh detection rules and decoders:

- **Location**: `internal/controller/wazuh/`
- **CRDs Managed**:
  - WazuhRule - Custom detection rules
  - WazuhDecoder - Custom log decoders

## Design Patterns

### Config vs Builder Separation

The codebase separates domain logic from infrastructure:

```
internal/{wazuh,opensearch}/
├── config/                    # Domain logic: generates config file CONTENT
│   ├── ossec_conf.go          # → string (ossec.conf content)
│   ├── filebeat_config.go     # → string (filebeat.yml content)
│   └── opensearch_yml.go      # → string (opensearch.yml content)
│
└── builder/                   # Infrastructure: builds K8s resources
    ├── configmaps/            # ConfigMapBuilder.Build() → *corev1.ConfigMap
    ├── deployments/           # DeploymentBuilder.Build() → *appsv1.Deployment
    └── services/              # ServiceBuilder.Build() → *corev1.Service
```

### Resource Building

Resources are built using the builder pattern:

```go
// Example: Building a ConfigMap
ossecContent := config.DefaultOSSECConfig(name, namespace).Build()  // → string
configMap := configmaps.NewManagerConfigMapBuilder(name, namespace).
    WithOSSECConfig(ossecContent).
    Build()  // → *corev1.ConfigMap
```

### Status Management

Status updates use conditions for rich status reporting:

```go
// Set condition
conditions.SetCondition(&cluster.Status.Conditions, metav1.Condition{
    Type:    "Ready",
    Status:  metav1.ConditionTrue,
    Reason:  "AllComponentsReady",
    Message: "All cluster components are running",
})
```

## API Groups

**Primary Group**: `resources.wazuh.com/v1alpha1`

All CRDs use this single API group for consistency.

## Labels and Annotations

### Standard Labels

```yaml
app.kubernetes.io/name: wazuh-manager
app.kubernetes.io/instance: my-cluster
app.kubernetes.io/component: wazuh-manager # or wazuh-indexer, wazuh-dashboard
app.kubernetes.io/part-of: wazuh
app.kubernetes.io/managed-by: wazuh-operator
```

### Custom Annotations

```yaml
wazuh.com/cert-hash: "sha256:..." # Certificate hash for rollout triggers
wazuh.com/config-hash: "sha256:..." # ConfigMap hash for rollout triggers
```

## Error Handling

1. **Transient Errors**: Requeue with exponential backoff
2. **Permanent Errors**: Update status with error condition
3. **Conflict Errors**: Retry with fresh resource version

## Metrics

The operator exposes Prometheus metrics:

- `wazuh_cluster_reconcile_total` - Total reconciliations
- `wazuh_cluster_reconcile_errors_total` - Reconciliation errors
- `wazuh_cluster_reconcile_duration_seconds` - Reconciliation duration

## Future Improvements

1. **Webhooks**: Admission webhooks for validation
2. **Backup/Restore**: Automated backup and restore
3. **Multi-cluster**: Federation support
4. **OLM**: OperatorHub integration
