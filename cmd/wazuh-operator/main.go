/*
Copyright 2025.

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
	"crypto/tls"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/controllers"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/monitoring"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(wazuhv1alpha1.AddToScheme(scheme))

	// Register Prometheus Operator types
	utilruntime.Must(monitoringv1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme

	// Register operator metrics with Prometheus
	metrics.RegisterMetrics()
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var certTestMode bool
	var nonBlockingRollouts bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.BoolVar(&certTestMode, "cert-test-mode", false,
		"If set, enables short-lived certificates (5 min) for testing renewal. DO NOT USE IN PRODUCTION.")
	flag.BoolVar(&nonBlockingRollouts, "non-blocking-rollouts", true,
		"If set, certificate renewals will not block waiting for pod rollouts. Recommended for production.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

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

	if len(webhookCertPath) > 0 {
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
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		// Leader election is disabled - operator manages one cluster only
		LeaderElection: false,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create CertificateReconciler with test mode if enabled
	certReconciler := wazuhreconciler.NewCertificateReconciler(mgr.GetClient(), mgr.GetScheme())
	if certTestMode {
		setupLog.Info("Certificate test mode ENABLED - certificates will have 5 minute validity")
		certReconciler.TestMode = true
	}

	// WazuhCluster Controller (main orchestration)
	wazuhClusterReconciler := &controllers.WazuhClusterReconciler{
		Client:                 mgr.GetClient(),
		Scheme:                 mgr.GetScheme(),
		ClusterReconciler:      wazuhreconciler.NewClusterReconciler(mgr.GetClient(), mgr.GetScheme()),
		CertificateReconciler:  certReconciler,
		IndexerReconciler:      opensearchreconciler.NewIndexerReconciler(mgr.GetClient(), mgr.GetScheme()),
		DashboardReconciler:    opensearchreconciler.NewDashboardReconciler(mgr.GetClient(), mgr.GetScheme()),
		WorkerReconciler:       wazuhreconciler.NewWorkerReconciler(mgr.GetClient(), mgr.GetScheme()),
		MonitoringReconciler:   monitoring.NewMonitoringReconciler(mgr.GetClient(), mgr.GetScheme()),
		RollbackManager:        drain.NewRollbackManager(mgr.GetClient(), ctrl.Log.WithName("rollback-manager")),
		RetryManager:           drain.NewRetryManager(ctrl.Log.WithName("retry-manager")),
		CertTestMode:           certTestMode,
		UseNonBlockingRollouts: nonBlockingRollouts,
	}
	if nonBlockingRollouts {
		setupLog.Info("Non-blocking certificate rollouts ENABLED")
	}
	if err := wazuhClusterReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhCluster")
		os.Exit(1)
	}

	// Wazuh Controllers
	if err := (&controllers.WazuhRuleReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		RuleReconciler: wazuhreconciler.NewRuleReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhRule")
		os.Exit(1)
	}
	if err := (&controllers.WazuhDecoderReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		DecoderReconciler: wazuhreconciler.NewDecoderReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhDecoder")
		os.Exit(1)
	}
	if err := (&controllers.WazuhCertificateReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		CertificateReconciler: wazuhreconciler.NewCertificateReconciler(mgr.GetClient(), mgr.GetScheme()),
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
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		UserReconciler: opensearchreconciler.NewUserReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchUser")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchRoleReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		RoleReconciler: opensearchreconciler.NewRoleReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchRole")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchRoleMappingReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		RoleMappingReconciler: opensearchreconciler.NewRoleMappingReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchRoleMapping")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchActionGroupReconciler{
		Client:                mgr.GetClient(),
		Scheme:                mgr.GetScheme(),
		ActionGroupReconciler: opensearchreconciler.NewActionGroupReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchActionGroup")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchTenantReconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		TenantReconciler: opensearchreconciler.NewTenantReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchTenant")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchPolicyReconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		PolicyReconciler: opensearchreconciler.NewPolicyReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchISMPolicy")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchIndexTemplateReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		TemplateReconciler: opensearchreconciler.NewTemplateReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchIndexTemplate")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchComponentTemplateReconciler{
		Client:                      mgr.GetClient(),
		Scheme:                      mgr.GetScheme(),
		ComponentTemplateReconciler: opensearchreconciler.NewComponentTemplateReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchComponentTemplate")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchIndexReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		IndexReconciler: opensearchreconciler.NewIndexReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchIndex")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchSnapshotPolicyReconciler{
		Client:                   mgr.GetClient(),
		Scheme:                   mgr.GetScheme(),
		SnapshotPolicyReconciler: opensearchreconciler.NewSnapshotPolicyReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchSnapshotPolicy")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchSnapshotRepositoryReconciler{
		Client:                       mgr.GetClient(),
		Scheme:                       mgr.GetScheme(),
		SnapshotRepositoryReconciler: opensearchreconciler.NewSnapshotRepositoryReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchSnapshotRepository")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchSnapshotReconciler{
		Client:                   mgr.GetClient(),
		Scheme:                   mgr.GetScheme(),
		ManualSnapshotReconciler: opensearchreconciler.NewManualSnapshotReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchSnapshot")
		os.Exit(1)
	}
	if err := (&controllers.OpenSearchRestoreReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		RestoreReconciler: opensearchreconciler.NewRestoreReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "OpenSearchRestore")
		os.Exit(1)
	}

	// OpenSearch Infrastructure Controllers
	if err := (&controllers.OpenSearchIndexerReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		IndexerReconciler: opensearchreconciler.NewIndexerReconciler(mgr.GetClient(), mgr.GetScheme()),
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
		BackupReconciler: wazuhreconciler.NewBackupReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhBackup")
		os.Exit(1)
	}
	if err := (&controllers.WazuhRestoreReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		RestoreReconciler: wazuhreconciler.NewWazuhRestoreReconciler(mgr.GetClient(), mgr.GetScheme()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WazuhRestore")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
