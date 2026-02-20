# Source Tree Analysis

## Project Structure

```text
wazuh-operator/
├── api/v1/                                        # CRD Type Definitions - v1 Storage Version (32 files)
│   ├── wazuhcluster_types.go                      # Main orchestrating CRD
│   ├── wazuhmanager_types.go                      # Manager component CRD
│   ├── wazuhworker_types.go                       # Worker component CRD
│   ├── opensearchindexer_types.go                 # Indexer component CRD
│   ├── opensearchdashboard_types.go               # Dashboard component CRD
│   ├── wazuhrule_types.go                         # Rule management CRD
│   ├── wazuhdecoder_types.go                      # Decoder management CRD
│   ├── wazuhcertificate_types.go                  # Certificate management CRD
│   ├── wazuhfilebeat_types.go                     # Filebeat config CRD
│   ├── wazuhbackup_types.go                       # Wazuh backup CRD
│   ├── wazuhrestore_types.go                      # Wazuh restore CRD
│   ├── opensearchuser_types.go                    # OpenSearch user CRD
│   ├── opensearchrole_types.go                    # OpenSearch role CRD
│   ├── opensearchrolemapping_types.go             # Role mapping CRD
│   ├── opensearchactiongroup_types.go             # Action group CRD
│   ├── opensearchtenant_types.go                  # Tenant CRD
│   ├── opensearchindex_types.go                   # Index CRD
│   ├── opensearchindextemplate_types.go           # Index template CRD
│   ├── opensearchcomponenttemplate_types.go       # Component template CRD
│   ├── opensearchpolicy_types.go                  # ISM policy CRD
│   ├── opensearchsnapshotpolicy_types.go          # Snapshot policy CRD
│   ├── opensearchsnapshotrepository_types.go      # Snapshot repo CRD
│   ├── opensearchsnapshot_types.go                # Manual snapshot CRD
│   ├── opensearchrestore_types.go                 # OpenSearch restore CRD
│   ├── opensearchauthconfig_types.go              # Auth config CRD
│   ├── nodepool_types.go                          # NodePool for advanced indexer topology
│   ├── common_types.go                            # Common shared types
│   ├── shared_types.go                            # Shared specifications
│   ├── groupversion_info.go                       # API group registration
│   ├── wazuhcluster_webhook.go                    # Webhook handlers
│   └── zz_generated.deepcopy.go                   # Generated DeepCopy methods
│
├── internal/                                      # Internal Implementation
│   ├── wazuh/                                     # Wazuh-specific logic
│   │   ├── reconciler/                            # Wazuh reconcilers
│   │   │   ├── cluster_reconciler.go              # Manager master+worker orchestration (main WazuhCluster path)
│   │   │   ├── manager_reconciler.go              # Standalone WazuhManager CRD reconciliation
│   │   │   ├── worker_reconciler.go               # Standalone WazuhWorker CRD + drain operations
│   │   │   ├── rule_reconciler.go                 # Rule deployment
│   │   │   ├── decoder_reconciler.go              # Decoder deployment
│   │   │   ├── filebeat_reconciler.go             # Filebeat config
│   │   │   ├── backup_reconciler.go               # Backup job management
│   │   │   └── restore_reconciler.go              # Restore job management
│   │   ├── config/                                # Wazuh configuration generation
│   │   │   └── wazuh_config_builder.go            # ossec.conf generation
│   │   ├── builder/                               # Wazuh resource builders
│   │   │   ├── statefulsets/                      # StatefulSet builders (manager, worker)
│   │   │   ├── services/                          # Service builders
│   │   │   ├── configmaps/                        # ConfigMap builders
│   │   │   ├── jobs/                              # Job builders (backup/restore)
│   │   │   └── pvc/                               # PVC builders
│   │   ├── drain/                                 # Drain strategy for safe scale-down
│   │   │   ├── drain.go                           # ManagerDrainer coordinator
│   │   │   ├── rollback.go                        # Rollback manager
│   │   │   └── retry.go                           # Retry manager
│   │   ├── health/                                # Wazuh health checks
│   │   └── validation/                            # Wazuh-specific validation
│   │
│   ├── opensearch/                                # OpenSearch-specific logic
│   │   ├── reconciler/                            # OpenSearch reconcilers
│   │   │   ├── indexer_reconciler.go              # Indexer StatefulSet management
│   │   │   ├── dashboard_reconciler.go            # Dashboard Deployment management
│   │   │   ├── user_reconciler.go                 # User API reconciler
│   │   │   ├── role_reconciler.go                 # Role API reconciler
│   │   │   ├── role_mapping_reconciler.go         # RoleMapping API reconciler
│   │   │   ├── action_group_reconciler.go         # ActionGroup API reconciler
│   │   │   ├── tenant_reconciler.go               # Tenant API reconciler
│   │   │   ├── authconfig_reconciler.go           # Auth config reconciler
│   │   │   ├── index_reconciler.go                # Index API reconciler
│   │   │   ├── template_reconciler.go             # IndexTemplate API reconciler
│   │   │   ├── component_template_reconciler.go   # ComponentTemplate API reconciler
│   │   │   ├── policy_reconciler.go               # ISM policy API reconciler
│   │   │   ├── snapshot_policy_reconciler.go      # Snapshot policy reconciler
│   │   │   ├── snapshot_repository_reconciler.go  # Repo API reconciler
│   │   │   ├── manual_snapshot_reconciler.go      # Manual snapshot trigger
│   │   │   └── restore_reconciler.go              # Restore API reconciler
│   │   ├── api/                                   # OpenSearch REST API clients
│   │   │   ├── security_api.go                    # Security plugin API client
│   │   │   ├── users_api.go                       # Users API wrapper
│   │   │   ├── roles_api.go                       # Roles API wrapper
│   │   │   ├── index_api.go                       # Index API wrapper
│   │   │   ├── templates_api.go                   # Templates API wrapper
│   │   │   ├── ism_api.go                         # ISM API wrapper
│   │   │   └── snapshot_api.go                    # Snapshot API wrapper
│   │   ├── config/                                # OpenSearch configuration generation
│   │   │   ├── security_config.go                 # Security plugin config
│   │   │   ├── auth_ldap.go                       # LDAP auth config
│   │   │   ├── auth_oidc.go                       # OIDC auth config
│   │   │   ├── auth_saml.go                       # SAML auth config
│   │   │   └── auth_config.go                     # Auth domain config
│   │   ├── security_config/                       # Security config structures
│   │   │   ├── users.go                           # Internal users struct
│   │   │   ├── roles.go                           # Roles struct
│   │   │   ├── role_mappings.go                   # Role mappings struct
│   │   │   ├── action_groups.go                   # Action groups struct
│   │   │   ├── tenants.go                         # Tenants struct
│   │   │   └── reconciler_bindings.go             # Security config reconciler
│   │   ├── security/                              # Security synchronization
│   │   │   └── synchronizer.go                    # Sync security config to cluster
│   │   ├── builder/                               # OpenSearch resource builders
│   │   │   ├── statefulsets/                      # StatefulSet builders (indexer)
│   │   │   ├── deployments/                       # Deployment builders (dashboard)
│   │   │   ├── services/                          # Service builders
│   │   │   ├── configmaps/                        # ConfigMap builders
│   │   │   ├── jobs/                              # Init job builders
│   │   │   └── pvc/                               # PVC builders
│   │   └── validation/                            # OpenSearch-specific validation
│   │       └── ...                                # Validation logic
│   │
│   ├── certificates/                              # TLS Certificate Management (cross-cutting)
│   │   ├── reconciler/                            # Certificate reconciliation
│   │   │   ├── certificate_reconciler.go          # CertificateReconciler (TLS lifecycle management)
│   │   │   └── certificate_hotreload.go           # Cert reload without restart (Wazuh 4.9+)
│   │   ├── common/                                # Shared certificate utilities
│   │   ├── opensearch/                            # OpenSearch-specific cert generation
│   │   ├── wazuh/                                 # Wazuh-specific cert generation
│   │   └── sans/                                  # SAN (Subject Alternative Name) management
│   │
│   ├── networking/                                # Networking (cross-cutting, shared by opensearch+wazuh)
│   │   ├── reconciler/                            # Networking reconcilers
│   │   │   ├── gateway_reconciler.go              # GatewayReconciler (HTTPRoute, TCPRoute, UDPRoute)
│   │   │   └── ingress_reconciler.go              # IngressReconciler (networkingv1.Ingress)
│   │   └── builder/                               # Networking resource builders
│   │       ├── routes/                            # Gateway API route builders
│   │       │   ├── httproute_builder.go           # HTTPRoute builder
│   │       │   ├── tcproute_builder.go            # TCPRoute builder
│   │       │   └── udproute_builder.go            # UDPRoute builder
│   │       └── ingresses/                         # Ingress builders
│   │           └── ingress_builder.go             # Ingress builder (4 concrete builders)
│   │
│   ├── metrics/                                   # Prometheus Metrics
│   │   └── metrics.go                             # Custom operator metrics
│   │
│   ├── monitoring/                                # Monitoring Integration
│   │   └── servicemonitor.go                      # ServiceMonitor/PodMonitor reconciler
│   │
│   ├── shared/                                    # Shared Cross-Cutting Concerns
│   │   ├── affinity/                              # Anti-affinity builders (manager, indexer, dashboard)
│   │   ├── pdb/                                   # PodDisruptionBudget builders (manager, indexer, dashboard)
│   │   ├── drain/                                 # Drain state machine and detection (used by wazuh & opensearch)
│   │   ├── config/                                # Shared configuration utilities
│   │   ├── storage/                               # Storage utilities
│   │   └── patch/                                 # Change detection utilities
│   │       ├── hash.go                            # Spec hash computation (per-component SpecInput structs)
│   │       ├── detector.go                        # Detect resource changes
│   │       ├── types.go                           # Patch types
│   │       └── errors.go                          # Patch errors
│   │
│   ├── validation/                                # CRD Validation (moved from pkg/validation/)
│   │   ├── cluster_validation.go                  # WazuhCluster validation
│   │   ├── opensearch_validation.go               # OpenSearch CRD validation
│   │   ├── wazuh_validation.go                    # Wazuh CRD validation
│   │   └── password_validation.go                 # Password policy validation
│   │
│   ├── adapters/                                  # External system adapters
│   │   └── ...                                    # Adapter implementations
│   │
│   ├── telemetry/                                 # OpenTelemetry Tracing
│   │   ├── provider.go                            # TracerProvider initialization
│   │   ├── config.go                              # OTEL environment configuration
│   │   ├── http_transport.go                      # HTTP RoundTripper instrumentation
│   │   └── provider_test.go                       # Unit tests
│   │
│   └── utils/                                     # Internal Utilities
│       ├── k8s_objects.go                         # Kubernetes object helpers
│       ├── status_conditions.go                   # Status condition utilities
│       ├── merge.go                               # Deep merge utilities
│       └── hash.go                                # Hash computation
│
├── controllers/                                   # Kubernetes Controllers (25 files)
│   ├── wazuhcluster_controller.go                 # Main orchestrating controller
│   ├── wazuhmanager_controller.go                 # Manager component controller
│   ├── wazuhworker_controller.go                  # Worker component controller
│   ├── opensearchindexer_controller.go            # Indexer component controller
│   ├── opensearchdashboard_controller.go          # Dashboard component controller
│   ├── wazuhrule_controller.go                    # Rule controller
│   ├── wazuhdecoder_controller.go                 # Decoder controller
│   ├── wazuhcertificate_controller.go             # Certificate controller
│   ├── wazuhfilebeat_controller.go                # Filebeat controller
│   ├── wazuhbackup_controller.go                  # Backup controller
│   ├── wazuhrestore_controller.go                 # Restore controller
│   ├── opensearchuser_controller.go               # User controller
│   ├── opensearchrole_controller.go               # Role controller
│   ├── opensearchrolemapping_controller.go        # RoleMapping controller
│   ├── opensearchactiongroup_controller.go        # ActionGroup controller
│   ├── opensearchtenant_controller.go             # Tenant controller
│   ├── opensearchindex_controller.go              # Index controller
│   ├── opensearchindextemplate_controller.go      # IndexTemplate controller
│   ├── opensearchcomponenttemplate_controller.go  # ComponentTemplate controller
│   ├── opensearchpolicy_controller.go             # ISM policy controller
│   ├── opensearchsnapshotpolicy_controller.go     # Snapshot policy controller
│   ├── opensearchsnapshotrepository_controller.go # Snapshot repo controller
│   ├── opensearchsnapshot_controller.go           # Manual snapshot controller
│   ├── opensearchrestore_controller.go            # Restore controller
│   └── opensearchauthconfig_controller.go         # Auth config controller
│
├── pkg/                                           # Public Packages (stable API, importable externally)
│   ├── config/                                    # Operator configuration
│   │   └── config.go                              # Runtime configuration
│   │
│   ├── constants/                                 # Constants
│   │   ├── ports.go                               # Port definitions
│   │   ├── defaults.go                            # Default values (versions, images)
│   │   └── backup.go                              # Backup constants
│   │
│   ├── dns/                                       # DNS utilities
│   │   └── dns.go                                 # Cluster domain resolution
│   │
│   ├── logging/                                   # Logging configuration
│   │   └── logging.go                             # Structured logging setup
│   │
│   ├── version/                                   # Version Information
│   │   ├── version.go                             # Operator version
│   │   └── buildinfo.go                           # Build metadata
│   │
│   └── versions/                                  # Wazuh↔OpenSearch Version Mapping
│       └── versions.go                            # Version mapping, hot reload support detection
│
├── cmd/                                           # Application Entry Point
│   └── wazuh-operator/
│       └── main.go                                # Operator entry point (manager setup, controller registration)
│
├── config/                                        # Kubernetes Manifests
│   ├── crd/                                       # Generated CRD YAML
│   │   └── *.yaml                                 # 25 CRD manifests (generated by controller-gen)
│   ├── rbac/                                      # RBAC Configuration
│   │   ├── role.yaml                              # ClusterRole
│   │   ├── role_binding.yaml                      # ClusterRoleBinding
│   │   └── service_account.yaml                   # ServiceAccount
│   ├── samples/                                   # Example Custom Resources (v1 API)
│   │   ├── wazuh_v1_wazuhcluster_minimal.yaml
│   │   ├── wazuh_v1_wazuhcluster_tls.yaml
│   │   ├── wazuh_v1_wazuhcluster_monitoring.yaml
│   │   ├── wazuh_v1_rule.yaml
│   │   ├── wazuh_v1_decoder.yaml
│   │   ├── opensearch_v1_user.yaml
│   │   ├── opensearch_v1_role.yaml
│   │   ├── opensearch_v1_indextemplate.yaml
│   │   └── ...                                    # 20+ example resources
│   └── manager/
│       └── manager.yaml                           # Operator Deployment manifest
│
├── charts/                                        # Helm Charts
│   ├── wazuh-operator/                            # Operator Helm Chart
│   │   ├── Chart.yaml                             # Chart metadata
│   │   ├── values.yaml                            # Default values
│   │   └── templates/                             # K8s templates (Deployment, ServiceAccount, etc.)
│   └── wazuh-cluster/                             # WazuhCluster Helm Chart
│       ├── Chart.yaml                             # Chart metadata
│       ├── values.yaml                            # Default cluster config
│       └── templates/                             # WazuhCluster CR template
│
├── docs/                                          # Documentation
│   ├── usage/                                     # User Documentation
│   │   ├── getting-started/                       # Installation, quick start
│   │   ├── features/                              # Feature guides (TLS, monitoring, backup, etc.)
│   │   ├── examples/                              # Example configurations
│   │   ├── troubleshooting/                       # Common issues, debugging
│   │   └── CRD-REFERENCE.md                       # Complete API reference
│   └── dev/                                       # Developer Documentation
│       ├── architecture/                          # Operator design, reconciliation flow, certificates
│       ├── testing/                               # Testing guide, certificate scenarios
│       └── contributing/                          # Contributing guide, code style
│
├── test/                                          # Tests
│   ├── e2e/                                       # End-to-End Tests
│   │   ├── e2e_suite_test.go                      # E2E suite setup (Ginkgo)
│   │   └── e2e_test.go                            # E2E test cases
│   └── utils/                                     # Test Utilities
│       └── utils.go                               # Helper functions
│
├── hack/                                          # Build Scripts
│   └── boilerplate.go.txt                         # Copyright header template
│
├── bin/                                           # Compiled Binaries
│   ├── manager                                    # Operator binary (generated by make build)
│   └── controller-gen                             # Code generator (downloaded by make)
│
├── build/
│   ├── operator/
│   │   └── Dockerfile                             # Operator container image build
│   └── backup-tools/
│       └── Dockerfile                             # Backup-tools container image build
│
├── Makefile                                       # Build Automation
├── go.mod                                         # Go Module Definition
├── go.sum                                         # Go dependency checksums
└── README.md                                      # Project README
```

## Key Directories

### Critical Paths

- **`api/v1/`**: CRD type definitions (v1 storage version) - **READ FIRST** to understand data model
- **`cmd/wazuh-operator/main.go`**: Application entry point - shows operator initialization
- **`controllers/`**: Kubernetes controllers - main reconciliation logic
- **`internal/wazuh/`**: Wazuh-specific implementation (reconcilers, config, builders, drain)
- **`internal/opensearch/`**: OpenSearch-specific implementation (reconcilers, API clients, config)
- **`internal/certificates/`**: TLS certificate management (reconciler, generation, SANs)
- **`internal/networking/`**: Networking reconcilers and builders (Gateway API, Ingress)
- **`internal/shared/`**: Cross-cutting concerns (affinity, PDB, drain state machine, config, storage, patch)
- **`internal/validation/`**: CRD validation logic (cluster, opensearch, wazuh, password)
- **`internal/telemetry/`**: OpenTelemetry tracing (TracerProvider, HTTP transport wrapper)
- **`pkg/versions/`**: Wazuh↔OpenSearch version mapping (public stable API)

### Entry Points

1. **Operator Startup**: `cmd/wazuh-operator/main.go:main()`

   - Initializes controller-runtime manager
   - Registers all 25 controllers
   - Starts metrics server
   - Runs controller loops

2. **Main Reconciliation**: `controllers/wazuhcluster_controller.go:Reconcile()`

   - Entry point for WazuhCluster reconciliation
   - Delegates to helper reconcilers

3. **CRD Definitions**: `api/v1/*_types.go` (v1 storage version)
   - Defines all Custom Resource structures
   - Kubebuilder validation markers
   - `api/v1/` still served for backward compatibility

### Integration Points

**Kubernetes API Server**:

- Controllers watch CRs via informers
- Apply resources (StatefulSets, Services, ConfigMaps, Secrets)
- Update CR status conditions

**OpenSearch REST API**:

- `internal/opensearch/api/`: Direct HTTP calls to OpenSearch
- Security plugin API (`/_plugins/_security/api/`)
- Index management API
- Snapshot API

**Wazuh API**:

- REST calls to Wazuh Manager API (via internal adapters)
- Rule/decoder reload commands
- Agent management

**S3/MinIO**:

- Backup/restore via Jobs with S3 SDK
- Snapshot repository storage

## Shared Code Patterns

### Common Utilities (`internal/utils/`)

- `k8s_objects.go`: Object creation helpers, owner references
- `status_conditions.go`: Status condition management (Ready, Progressing, Degraded)
- `merge.go`: Deep merge for strategic updates
- `hash.go`: Spec/ConfigMap/Secret hash computation for change detection

### Version Mapping (`pkg/versions/`)

- `versions.go`: Wazuh↔OpenSearch version mapping, hot reload support detection, Prometheus exporter version mapping

### Configuration Builders

- `internal/wazuh/config/`: Generate `ossec.conf` from CRD specs
- `internal/opensearch/config/`: Generate `opensearch.yml`, security config

### Resource Builders

- `internal/wazuh/builder/`: StatefulSets, Services, ConfigMaps for Wazuh
- `internal/opensearch/builder/`: StatefulSets, Deployments, Services for OpenSearch

## Asset Locations

- **Container Images**: Built from `build/operator/Dockerfile` and `build/backup-tools/Dockerfile`, pushed to registry
- **Helm Charts**: Published to GHCR (`ghcr.io/maximewewer/charts/`)
- **CRD Manifests**: `config/crd/` (generated, applied to cluster)
- **RBAC Manifests**: `config/rbac/` (ClusterRole, ClusterRoleBinding, ServiceAccount)
