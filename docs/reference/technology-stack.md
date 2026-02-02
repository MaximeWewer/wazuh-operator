# Technology Stack

## Overview

The Wazuh Operator is a Kubernetes operator built with Go and Kubebuilder, following the operator pattern for managing Wazuh security platform deployments on Kubernetes.

## Technology Decision Table

| Category                     | Technology                       | Version                  | Justification                                                                                               |
| ---------------------------- | -------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------- |
| **Core Language**            | Go                               | 1.25.4                   | Primary language for Kubernetes operators, native support for concurrency and efficient resource management |
| **Operator Framework**       | Kubebuilder                      | controller-tools v0.17.0 | Industry-standard framework for building Kubernetes operators with code generation and scaffolding          |
| **Controller Runtime**       | controller-runtime               | v0.22.4                  | Core library for building Kubernetes controllers with reconciliation loops and caching                      |
| **Kubernetes Client**        | client-go                        | v0.34.2                  | Official Kubernetes Go client for API interactions                                                          |
| **Kubernetes API**           | k8s.io/api                       | v0.34.2                  | Kubernetes API types and definitions                                                                        |
| **Kubernetes Machinery**     | k8s.io/apimachinery              | v0.34.2                  | Generic building blocks for Kubernetes APIs (schema, runtime, etc.)                                         |
| **Testing Framework**        | Ginkgo                           | v2.27.2                  | BDD-style testing framework for Go                                                                          |
| **Testing Assertions**       | Gomega                           | v1.38.2                  | Matcher library for expressive test assertions                                                              |
| **Monitoring Integration**   | Prometheus Operator APIs         | v0.87.0                  | Integration with Prometheus for ServiceMonitor/PodMonitor CRDs                                              |
| **Metrics Client**           | prometheus/client_golang         | v1.23.2                  | Prometheus metrics collection and exposition                                                                |
| **Cryptography**             | golang.org/x/crypto              | v0.42.0                  | TLS certificate generation and cryptographic operations                                                     |
| **Logging**                  | zap (via controller-runtime)     | v1.27.0                  | High-performance structured logging                                                                         |
| **Tracing**                  | OpenTelemetry                    | v1.34.0                  | Distributed tracing with OTLP gRPC exporter                                                                 |
| **HTTP Instrumentation**     | otelhttp                         | v0.56.0                  | Automatic HTTP client tracing                                                                               |
| **Build Tool**               | Make                             | N/A                      | Build automation and developer workflow orchestration                                                       |
| **Container Base (Builder)** | golang:1.25-alpine               | Latest                   | Lightweight Alpine Linux with Go for building                                                               |
| **Container Base (Runtime)** | gcr.io/distroless/static:nonroot | Latest                   | Minimal, secure container image with no shell or package manager                                            |

## Architecture Pattern

**Kubernetes Operator Pattern (Reconciliation-Based)**

The operator follows the standard Kubernetes operator pattern with:

- **Custom Resource Definitions (CRDs)**: 27 CRDs for declarative resource management

  - Wazuh Core: WazuhCluster, WazuhManager, WazuhWorker
  - Wazuh Config: WazuhRule, WazuhDecoder, WazuhCertificate, WazuhFilebeat
  - Wazuh Backup: WazuhBackup, WazuhRestore
  - OpenSearch Core: OpenSearchIndexer, OpenSearchDashboard
  - OpenSearch Security: OpenSearchUser, OpenSearchRole, OpenSearchRoleMapping, OpenSearchActionGroup, OpenSearchTenant, OpenSearchAuthConfig
  - OpenSearch Index: OpenSearchIndex, OpenSearchIndexTemplate, OpenSearchComponentTemplate, OpenSearchPolicy, OpenSearchSnapshotPolicy
  - OpenSearch Backup: OpenSearchSnapshotRepository, OpenSearchSnapshot, OpenSearchRestore

- **Controllers**: Reconciliation controllers that watch CRDs and manage Kubernetes resources

  - Main reconciler: WazuhCluster controller orchestrates all components
  - Specialized controllers for each CRD type
  - Certificate controller for TLS management
  - OpenSearch security config synchronization

- **Reconciliation Loops**:

  - Observe desired state (CRD specs)
  - Compare with actual state (running resources)
  - Take actions to converge to desired state
  - Requeue for continuous reconciliation

- **Resource Builders**: Generate Kubernetes resources (StatefulSets, Services, ConfigMaps, Secrets, etc.)

- **Status Reporting**: Rich status conditions on CRs for observability

## Key Dependencies

### Core Kubernetes

- `k8s.io/api`: Core Kubernetes API types
- `k8s.io/apimachinery`: API machinery and generic types
- `k8s.io/client-go`: Kubernetes API client with informers and caching
- `sigs.k8s.io/controller-runtime`: Controller framework with manager, reconciler, caching

### Monitoring & Observability

- `prometheus-operator/prometheus-operator/pkg/apis/monitoring`: ServiceMonitor/PodMonitor CRDs
- `prometheus/client_golang`: Prometheus metrics exposition
- `go.uber.org/zap`: Structured logging
- `go.opentelemetry.io/otel`: OpenTelemetry SDK for distributed tracing
- `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc`: OTLP gRPC exporter
- `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp`: HTTP transport instrumentation

### Security & Crypto

- `golang.org/x/crypto`: TLS certificate generation (RSA, ECDSA keys)
- X.509 certificate management for inter-component communication

### Testing

- `github.com/onsi/ginkgo/v2`: BDD testing framework
- `github.com/onsi/gomega`: Assertion matchers
- Kubernetes envtest for integration testing

## Build & Deployment

### Build Process

```makefile
make manifests  # Generate CRDs and RBAC
make generate   # Generate DeepCopy methods
make build      # Build operator binary
make test       # Run unit tests
```

### Container Build

- **Multi-stage Docker build**:
  - Stage 1: golang:1.25-alpine for building (with go mod caching)
  - Stage 2: distroless/static:nonroot for runtime (minimal attack surface)
- **Binary optimizations**: CGO disabled, stripped symbols (-ldflags="-s -w"), trimmed paths

### Deployment

- **kubectl**: Direct manifest deployment
- **Helm**: Operator chart + Cluster chart
  - Operator chart: Deploys the operator itself
  - Cluster chart: Deploys WazuhCluster CRs
- **OCI Registry**: Charts published to ghcr.io

## Development Tools

- **controller-gen**: Code and manifest generation (v0.17.0)
- **golangci-lint**: Linting and static analysis (.golangci.yml)
- **Make**: Build automation with targets for development, testing, deployment
- **Docker**: Container image building and local testing

## API Group

- **Group**: `resources.wazuh.com`
- **Version**: `v1` (storage version), `v1alpha1` (served for backward compatibility)
- **Short Names**: Defined for all CRDs (e.g., `wc`, `wmgr`, `osuser`, `osrole`)

## Target Environment

- **Kubernetes Version**: 1.24+
- **Minimum Resources**: 16GB+ RAM recommended
- **Storage**: Dynamic PersistentVolume provisioning required
- **Networking**: ClusterIP services, optional Ingress support

## Architecture Style

**Layered Kubernetes Operator Architecture**:

1. **API Layer** (`api/v1/`): CRD type definitions (v1 storage version)
2. **Controller Layer** (`internal/controller/`, `controllers/`): Reconciliation logic
3. **Business Logic Layer** (`internal/`):
   - `opensearch/`: OpenSearch config and reconcilers
   - `wazuh/`: Wazuh config and reconcilers
   - `certificates/`: TLS certificate management
   - `metrics/`: Custom metrics collection
   - `telemetry/`: OpenTelemetry tracing
   - `shared/`: Cross-cutting concerns
4. **Resource Builder Layer** (`pkg/resources/`): Kubernetes resource generation
5. **Client Layer** (`pkg/client/`): K8s and OpenSearch API clients
6. **Validation Layer** (`pkg/validation/`): CRD validation logic

## Configuration Management

- **Environment Variables**: Passed via Deployment spec
- **ConfigMaps**: For Wazuh/OpenSearch configuration files
- **Secrets**: For credentials (auto-generated by operator)
- **CRDs**: Declarative configuration via Custom Resources

## OpenTelemetry Configuration

The operator supports optional OpenTelemetry distributed tracing, configured via environment variables:

| Variable                      | Default          | Description                                                                    |
| ----------------------------- | ---------------- | ------------------------------------------------------------------------------ |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (disabled)       | OTLP gRPC endpoint (e.g., `localhost:4317`). Tracing is disabled when not set. |
| `OTEL_EXPORTER_OTLP_INSECURE` | `false`          | Use insecure connection (no TLS)                                               |
| `OTEL_SERVICE_NAME`           | `wazuh-operator` | Service name in traces                                                         |
| `OTEL_SERVICE_VERSION`        | `0.1.0`          | Service version in traces                                                      |

### Instrumented Components

- **Wazuh API calls**: HTTP requests to Wazuh Manager API
- **OpenSearch API calls**: HTTP requests to OpenSearch REST API
- **OpenSearch HTTP adapter**: HTTP requests via OpenSearch adapter

All HTTP clients automatically propagate trace context and record spans for external API calls.
