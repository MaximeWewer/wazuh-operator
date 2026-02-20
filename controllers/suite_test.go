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

package controllers

import (
	"context"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	certreconciler "github.com/MaximeWewer/wazuh-operator/internal/certificates/reconciler"
	"github.com/MaximeWewer/wazuh-operator/internal/monitoring"
	networkingreconciler "github.com/MaximeWewer/wazuh-operator/internal/networking/reconciler"
	opensearchreconciler "github.com/MaximeWewer/wazuh-operator/internal/opensearch/reconciler"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/drain"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

var (
	cfg        *rest.Config
	k8sClient  client.Client
	testEnv    *envtest.Environment
	reconciler *WazuhClusterReconciler
	ctx        context.Context
	cancel     context.CancelFunc
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("initializing DNS package for tests")
	// Initialize DNS package with default cluster domain for tests
	err := dns.InitializeWithDomain("cluster.local")
	Expect(err).NotTo(HaveOccurred())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	// Add WazuhCluster CRD scheme
	err = wazuhv1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// Add Gateway API types to scheme (optional - for GatewayAPI support)
	_ = gatewayv1.Install(scheme.Scheme)
	_ = gatewayv1alpha2.Install(scheme.Scheme)

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	// Initialize reconciler with ALL helper reconcilers (fixes nil pointer issues)
	testLogger := logf.Log.WithName("test")
	clusterReconciler := wazuhreconciler.NewClusterReconciler(k8sClient, scheme.Scheme)
	certificateReconciler := certreconciler.NewCertificateReconciler(k8sClient, scheme.Scheme)
	indexerReconciler := opensearchreconciler.NewIndexerReconciler(k8sClient, scheme.Scheme)
	dashboardReconciler := opensearchreconciler.NewDashboardReconciler(k8sClient, scheme.Scheme)
	workerReconciler := wazuhreconciler.NewWorkerReconciler(k8sClient, scheme.Scheme)
	monitoringReconciler := monitoring.NewMonitoringReconciler(k8sClient, scheme.Scheme)
	gatewayReconciler := networkingreconciler.NewGatewayReconciler(k8sClient, scheme.Scheme)

	// Initialize drain managers for safe scale-down operations
	rollbackManager := drain.NewRollbackManager(k8sClient, testLogger)
	retryManager := drain.NewRetryManager(testLogger)

	// Create a fake event recorder for tests with large buffer to prevent blocking
	// The reconciler emits many events during reconciliation, so we need a large buffer
	eventRecorder := record.NewFakeRecorder(10000)

	// Start a goroutine to drain events to prevent blocking
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-eventRecorder.Events:
				// Drain events to prevent blocking
			}
		}
	}()

	reconciler = &WazuhClusterReconciler{
		Client:                k8sClient,
		Scheme:                scheme.Scheme,
		Recorder:              eventRecorder,
		ClusterReconciler:     clusterReconciler,
		CertificateReconciler: certificateReconciler,
		IndexerReconciler:     indexerReconciler,
		DashboardReconciler:   dashboardReconciler,
		WorkerReconciler:      workerReconciler,
		MonitoringReconciler:  monitoringReconciler,
		GatewayReconciler:     gatewayReconciler,
		RollbackManager:       rollbackManager,
		RetryManager:          retryManager,
	}
})

var _ = AfterSuite(func() {
	cancel()
	By("resetting DNS package")
	dns.Reset()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
