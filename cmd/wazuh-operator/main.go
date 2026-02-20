/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"k8s.io/client-go/kubernetes"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/controllers"
	"github.com/MaximeWewer/wazuh-operator/internal/health"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/monitoring"

	certreconciler "github.com/MaximeWewer/wazuh-operator/internal/certificates/reconciler"
	networkingreconciler "github.com/MaximeWewer/wazuh-operator/internal/networking/reconciler"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/security"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/config"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
	"github.com/MaximeWewer/wazuh-operator/pkg/logging"
	"github.com/MaximeWewer/wazuh-operator/pkg/version"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(wazuhv1.AddToScheme(scheme))

	// Register Prometheus Operator types
	utilruntime.Must(monitoringv1.AddToScheme(scheme))

	// Register Gateway API types (optional - only used if Gateway API CRDs are installed)
	_ = gatewayv1.Install(scheme)
	_ = gatewayv1alpha2.Install(scheme)
	// +kubebuilder:scaffold:scheme

	// Register operator metrics with Prometheus
	metrics.RegisterMetrics()

	// Set operator version info metric
	v := version.Get()
	metrics.SetOperatorInfo(v.Version, v.GitCommit, v.BuildDate)
}

//nolint:gocyclo // Main function has high cyclomatic complexity due to controller setup; splitting would reduce clarity
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var enableLeaderElection bool
	var leaderElectionID string
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&leaderElectionID, "leader-election-id", "wazuh-operator-leader",
		"The name of the resource that leader election will use for holding the leader lock.")
	var maxConcurrentReconciles int
	flag.Bool("non-blocking-rollouts", true,
		"Enable non-blocking rollouts for parallel certificate renewals.")
	flag.IntVar(&maxConcurrentReconciles, "max-concurrent-reconciles", 1,
		"The maximum number of concurrent Reconciles which can be run for the WazuhCluster controller.")
	flag.Parse()

	// Setup logging from environment variables (LOG_FORMAT, LOG_LEVEL)
	logConfig := logging.LoadFromEnv()
	logging.SetupLogger(logConfig)

	// Initialize cluster domain configuration
	// This must be done before any controllers or components use DNS functions
	if err := dns.Initialize(); err != nil {
		setupLog.Error(err, "failed to initialize cluster domain configuration")
		os.Exit(1)
	}
	setupLog.Info("cluster domain configured", "domain", dns.ClusterDomain())

	// Initialize runtime configuration (vm.max_map_count, etc.)
	if err := config.Initialize(); err != nil {
		setupLog.Error(err, "failed to initialize runtime configuration")
		os.Exit(1)
	}
	setupLog.Info("runtime configuration initialized", "vmMaxMapCount", config.VMMaxMapCount())

	// Check Gateway API configuration (basic flag - CRD availability checked after manager creation)
	gatewayAPIEnabled := config.IsGatewayAPIEnabled()
	if !gatewayAPIEnabled {
		setupLog.Info("Gateway API support is DISABLED - Gateway API routes will not be managed",
			"enableWith", "set GATEWAY_API_ENABLED=true or gatewayAPI.enabled=true in Helm values")
	}

	// Initialize OpenTelemetry tracing if configured
	otelConfig := telemetry.LoadFromEnv()
	if otelConfig.IsEnabled() {
		setupLog.Info("Initializing OpenTelemetry tracing", "endpoint", otelConfig.Endpoint)
		tp, err := telemetry.InitProvider(context.Background(), otelConfig)
		if err != nil {
			setupLog.Error(err, "failed to initialize OpenTelemetry provider")
		} else {
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := telemetry.Shutdown(shutdownCtx, tp); err != nil {
					setupLog.Error(err, "failed to shutdown OpenTelemetry provider")
				}
			}()
			setupLog.Info("OpenTelemetry tracing initialized successfully")
		}
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if webhookCertPath != "" {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	if metricsCertPath != "" {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	// Configure namespace-scoped watching if WATCH_NAMESPACES is set
	// This enables multi-namespace RBAC isolation
	var cacheOptions cache.Options
	watchNamespaces := os.Getenv("WATCH_NAMESPACES")
	if watchNamespaces != "" {
		namespaces := strings.Split(watchNamespaces, ",")
		for i := range namespaces {
			namespaces[i] = strings.TrimSpace(namespaces[i])
		}
		setupLog.Info("Watching specific namespaces", "namespaces", namespaces)
		cacheOptions = cache.Options{
			DefaultNamespaces: make(map[string]cache.Config),
		}
		for _, ns := range namespaces {
			cacheOptions.DefaultNamespaces[ns] = cache.Config{}
		}
	} else {
		setupLog.Info("Watching all namespaces (cluster-scoped)")
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsServerOptions,
		WebhookServer:                 webhookServer,
		HealthProbeBindAddress:        probeAddr,
		LeaderElection:                enableLeaderElection,
		LeaderElectionID:              leaderElectionID,
		LeaderElectionReleaseOnCancel: true, // Release leadership on graceful shutdown for faster failover
		Cache:                         cacheOptions,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1) //nolint:gocritic // exitAfterDefer: OTEL cleanup not critical for fatal init errors
	}

	// Check Gateway API CRD availability if enabled
	var gatewayAPIStatus config.GatewayAPIStatus
	if gatewayAPIEnabled {
		gatewayAPIStatus = config.CheckGatewayAPICRDs(context.Background(), mgr.GetClient())
		setupLog.Info("Gateway API support is ENABLED",
			"httpRouteAvailable", gatewayAPIStatus.HTTPRouteAvailable,
			"tcpRouteAvailable", gatewayAPIStatus.TCPRouteAvailable,
			"udpRouteAvailable", gatewayAPIStatus.UDPRouteAvailable,
			"message", gatewayAPIStatus.Message)
	}

	// Create reconcile watchdog for health checks
	reconcileWatchdog := health.NewWatchdog(5 * time.Minute)

	// Create shared OpenSearch client factory for all standalone controllers
	osClientFactory := security.NewOpenSearchClientFactory(mgr.GetClient())

	// Create SecurityAdmin executor for applying security config via securityadmin.sh
	k8sClientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create kubernetes clientset")
		os.Exit(1)
	}
	securityAdminExecutor := security.NewSecurityAdminExecutor(mgr.GetClient(), mgr.GetConfig(), k8sClientset)

	// Create CertificateReconciler with REST config for pod exec support
	certReconciler := certreconciler.NewCertificateReconciler(mgr.GetClient(), mgr.GetScheme()).
		WithRESTConfig(mgr.GetConfig())

	// Create shared rule and decoder reconcilers (used by both WazuhCluster and individual controllers)
	wazuhRuleRecorder := mgr.GetEventRecorderFor("wazuhrule-controller")
	ruleReconciler := wazuhreconciler.NewRuleReconciler(mgr.GetClient(), mgr.GetScheme(), wazuhRuleRecorder)
	wazuhDecoderRecorder := mgr.GetEventRecorderFor("wazuhdecoder-controller")
	decoderReconciler := wazuhreconciler.NewDecoderReconciler(mgr.GetClient(), mgr.GetScheme(), wazuhDecoderRecorder)

	// WazuhCluster Controller (main orchestration)
	wazuhClusterReconciler := &controllers.WazuhClusterReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("wazuhcluster-controller"),
		ClusterReconciler: wazuhreconciler.NewClusterReconciler(mgr.GetClient(), mgr.GetScheme()).
			WithRuleReconciler(ruleReconciler).
			WithDecoderReconciler(decoderReconciler),
		CertificateReconciler:   certReconciler,
		IndexerReconciler:       opensearchreconciler.NewIndexerReconciler(mgr.GetClient(), mgr.GetScheme()).WithClientFactory(osClientFactory).WithSecurityAdminExecutor(securityAdminExecutor),
		DashboardReconciler:     opensearchreconciler.NewDashboardReconciler(mgr.GetClient(), mgr.GetScheme()),
		WorkerReconciler:        wazuhreconciler.NewWorkerReconciler(mgr.GetClient(), mgr.GetScheme()),
		MonitoringReconciler:    monitoring.NewMonitoringReconciler(mgr.GetClient(), mgr.GetScheme()),
		GatewayReconciler:       networkingreconciler.NewGatewayReconciler(mgr.GetClient(), mgr.GetScheme()),
		IngressReconciler:       networkingreconciler.NewIngressReconciler(mgr.GetClient(), mgr.GetScheme()),
		NetworkPolicyReconciler: networkingreconciler.NewNetworkPolicyReconciler(mgr.GetClient(), mgr.GetScheme()),
		RollbackManager:         drain.NewRollbackManager(mgr.GetClient(), ctrl.Log.WithName("rollback-manager")),
		RetryManager:            drain.NewRetryManager(ctrl.Log.WithName("retry-manager")),
		GatewayAPIEnabled:       gatewayAPIEnabled,
		HTTPRouteAvailable:      gatewayAPIStatus.HTTPRouteAvailable,
		TCPRouteAvailable:       gatewayAPIStatus.TCPRouteAvailable,
		UDPRouteAvailable:       gatewayAPIStatus.UDPRouteAvailable,
		MaxConcurrentReconciles: maxConcurrentReconciles,
		Watchdog:                reconcileWatchdog,
	}
	if err := wazuhClusterReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhCluster")
		os.Exit(1)
	}

	// Wazuh Controllers (reuse shared rule/decoder reconcilers created above)
	if err := (&controllers.WazuhRuleReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		Recorder:       wazuhRuleRecorder,
		RuleReconciler: ruleReconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhRule")
		os.Exit(1)
	}
	if err := (&controllers.WazuhDecoderReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		Recorder:          wazuhDecoderRecorder,
		DecoderReconciler: decoderReconciler,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhDecoder")
		os.Exit(1)
	}
	if err := (&controllers.WazuhCertificateReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		CertificateReconciler: certreconciler.NewCertificateReconciler(mgr.GetClient(), mgr.GetScheme()).WithRESTConfig(mgr.GetConfig()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhCertificate")
		os.Exit(1)
	}
	if err := (&controllers.WazuhManagerReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		ManagerReconciler: wazuhreconciler.NewManagerReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhManager")
		os.Exit(1)
	}
	if err := (&controllers.WazuhWorkerReconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		WorkerReconciler: wazuhreconciler.NewWorkerReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhWorker")
		os.Exit(1)
	}
	if err := (&controllers.WazuhFilebeatReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Recorder:           mgr.GetEventRecorderFor("wazuhfilebeat-controller"),
		FilebeatReconciler: wazuhreconciler.NewFilebeatReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("wazuhfilebeat-controller")),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhFilebeat")
		os.Exit(1)
	}

	// OpenSearch Security Controllers
	if err := (&controllers.OpenSearchUserReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		UserReconciler: opensearchreconciler.NewUserReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchuser-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchUser")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchRoleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		RoleReconciler: opensearchreconciler.NewRoleReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchrole-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchRole")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchRoleMappingReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		RoleMappingReconciler: opensearchreconciler.NewRoleMappingReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchrolemapping-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchRoleMapping")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchActionGroupReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		ActionGroupReconciler: opensearchreconciler.NewActionGroupReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchactiongroup-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchActionGroup")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchTenantReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		TenantReconciler: opensearchreconciler.NewTenantReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchtenant-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchTenant")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchAuthConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		AuthConfigReconciler: opensearchreconciler.NewAuthConfigReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchauthconfig-controller")).
			WithSecurityAdminExecutor(securityAdminExecutor),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchAuthConfig")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		PolicyReconciler: opensearchreconciler.NewPolicyReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchismpolicy-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchISMPolicy")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchIndexTemplateReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		TemplateReconciler: opensearchreconciler.NewTemplateReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchindextemplate-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchIndexTemplate")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchComponentTemplateReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		ComponentTemplateReconciler: opensearchreconciler.NewComponentTemplateReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchcomponenttemplate-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchComponentTemplate")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchIndexReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		IndexReconciler: opensearchreconciler.NewIndexReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchindex-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchIndex")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchSnapshotPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		SnapshotPolicyReconciler: opensearchreconciler.NewSnapshotPolicyReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchsnapshotpolicy-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchSnapshotPolicy")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchSnapshotRepositoryReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		SnapshotRepositoryReconciler: opensearchreconciler.NewSnapshotRepositoryReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchsnapshotrepository-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchSnapshotRepository")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchSnapshotReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		ManualSnapshotReconciler: opensearchreconciler.NewManualSnapshotReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchsnapshot-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchSnapshot")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchRestoreReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		RestoreReconciler: opensearchreconciler.NewRestoreReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("opensearchrestore-controller")).
			WithClientFactory(osClientFactory),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchRestore")
		os.Exit(1)
	}

	// OpenSearch Infrastructure Controllers
	if err := (&controllers.OpenSearchIndexerReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		IndexerReconciler: opensearchreconciler.NewIndexerReconciler(mgr.GetClient(), mgr.GetScheme()).WithClientFactory(osClientFactory).WithSecurityAdminExecutor(securityAdminExecutor),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchIndexer")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchDashboardReconciler{
		Client:              mgr.GetClient(),
		Scheme:              mgr.GetScheme(),
		DashboardReconciler: opensearchreconciler.NewDashboardReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchDashboard")
		os.Exit(1)
	}

	// Backup/Restore Controllers
	if err := (&controllers.WazuhBackupReconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		BackupReconciler: wazuhreconciler.NewBackupReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("wazuhbackup-controller")),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhBackup")
		os.Exit(1)
	}
	if err := (&controllers.WazuhRestoreReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		RestoreReconciler: wazuhreconciler.NewWazuhRestoreReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetEventRecorderFor("wazuhrestore-controller")),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhRestore")
		os.Exit(1)
	}

	// Setup webhooks
	if os.Getenv("ENABLE_WEBHOOKS") != "false" {
		if err := wazuhv1.SetupWazuhClusterWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "WazuhCluster")
			os.Exit(1)
		}
		if err := wazuhv1.SetupOpenSearchAuthConfigWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "OpenSearchAuthConfig")
			os.Exit(1)
		}
		if err := wazuhv1.SetupOpenSearchIndexerWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "OpenSearchIndexer")
			os.Exit(1)
		}
	}

	// +kubebuilder:scaffold:builder

	// Liveness: simple ping (restart only if process is dead)
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}

	// Readiness: operator is fully functional
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("informer-sync", health.InformerSyncChecker(mgr)); err != nil {
		setupLog.Error(err, "unable to set up informer-sync ready check")
		os.Exit(1)
	}
	if enableLeaderElection {
		if err := mgr.AddReadyzCheck("leader-election", health.LeaderElectionChecker(mgr)); err != nil {
			setupLog.Error(err, "unable to set up leader-election ready check")
			os.Exit(1)
		}
	}
	if err := mgr.AddReadyzCheck("reconcile-watchdog", health.WatchdogChecker(reconcileWatchdog)); err != nil {
		setupLog.Error(err, "unable to set up reconcile-watchdog ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
