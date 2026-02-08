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

// Package reconciler provides helper reconcilers for Wazuh components
package reconciler

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/hotreload"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
)

// CertificateReconciler handles reconciliation of TLS certificates
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// EventRecorder is used to emit Kubernetes events for certificate operations
	EventRecorder record.EventRecorder
	// PropagationTimeout is the timeout for waiting for kubelet to sync certificates
	// Defaults to 120 seconds if not set. Use a shorter value for unit tests.
	PropagationTimeout time.Duration
	// RESTConfig is the Kubernetes REST client configuration (needed for pod exec)
	RESTConfig *rest.Config
	// Clientset is the Kubernetes clientset (needed for pod exec)
	Clientset kubernetes.Interface
	// HotReloader handles OpenSearch certificate hot reload operations
	HotReloader *hotreload.HotReloader
}

// NewCertificateReconciler creates a new CertificateReconciler
func NewCertificateReconciler(c client.Client, scheme *runtime.Scheme) *CertificateReconciler {
	return &CertificateReconciler{
		Client:      c,
		Scheme:      scheme,
		HotReloader: hotreload.NewHotReloader(c),
	}
}

// WithEventRecorder sets the EventRecorder for the reconciler
func (r *CertificateReconciler) WithEventRecorder(recorder record.EventRecorder) *CertificateReconciler {
	r.EventRecorder = recorder
	r.HotReloader.WithEventRecorder(recorder)
	return r
}

// WithPropagationTimeout sets the timeout for waiting for kubelet to sync certificates
// Use a short value (e.g., 1*time.Second) for unit tests
func (r *CertificateReconciler) WithPropagationTimeout(timeout time.Duration) *CertificateReconciler {
	r.PropagationTimeout = timeout
	r.HotReloader.WithPropagationTimeout(timeout)
	return r
}

// WithRESTConfig sets the Kubernetes REST configuration for pod exec operations
func (r *CertificateReconciler) WithRESTConfig(config *rest.Config) *CertificateReconciler {
	r.RESTConfig = config
	if config != nil {
		clientset, err := kubernetes.NewForConfig(config)
		if err == nil {
			r.Clientset = clientset
		}
	}
	r.HotReloader.WithRESTConfig(config)
	return r
}

// getCertOptions builds CertificateOptions from the WazuhCluster CRD spec
// It reads TLS configuration from cluster.Spec.TLS.CertConfig if available
func (r *CertificateReconciler) getCertOptions(cluster *wazuhv1.WazuhCluster) *certificates.CertificateOptions {
	opts := certificates.DefaultCertificateOptions()

	// Read configuration from CRD if available
	if cluster.Spec.TLS != nil && cluster.Spec.TLS.CertConfig != nil {
		cfg := cluster.Spec.TLS.CertConfig

		// Set node cert validity from CRD
		if cfg.Validity != "" {
			if d, err := certificates.ParseCertDuration(cfg.Validity); err == nil {
				opts.NodeValidity = d
			}
		}

		// Set node cert renewal threshold from CRD
		if cfg.RenewalThreshold != "" {
			if d, err := certificates.ParseCertDuration(cfg.RenewalThreshold); err == nil {
				opts.RenewalThreshold = d
			}
		}

		// Set CA validity from CRD
		if cfg.CAValidity != "" {
			if d, err := certificates.ParseCertDuration(cfg.CAValidity); err == nil {
				opts.CAValidity = d
			}
		}

		// Set CA renewal threshold from CRD
		if cfg.CARenewalThreshold != "" {
			if d, err := certificates.ParseCertDuration(cfg.CARenewalThreshold); err == nil {
				opts.CARenewalThreshold = d
			}
		}

		// Set admin cert validity from CRD
		if cfg.AdminValidity != "" {
			if d, err := certificates.ParseCertDuration(cfg.AdminValidity); err == nil {
				opts.AdminValidity = d
			}
		}

		// Set admin cert renewal threshold from CRD
		if cfg.AdminRenewalThreshold != "" {
			if d, err := certificates.ParseCertDuration(cfg.AdminRenewalThreshold); err == nil {
				opts.AdminRenewalThreshold = d
			}
		}

		// Set dashboard cert validity from CRD
		if cfg.DashboardValidity != "" {
			if d, err := certificates.ParseCertDuration(cfg.DashboardValidity); err == nil {
				opts.DashboardValidity = d
			}
		}

		// Set dashboard cert renewal threshold from CRD
		if cfg.DashboardRenewalThreshold != "" {
			if d, err := certificates.ParseCertDuration(cfg.DashboardRenewalThreshold); err == nil {
				opts.DashboardRenewalThreshold = d
			}
		}

		// Set filebeat cert validity from CRD
		if cfg.FilebeatValidity != "" {
			if d, err := certificates.ParseCertDuration(cfg.FilebeatValidity); err == nil {
				opts.FilebeatValidity = d
			}
		}

		// Set filebeat cert renewal threshold from CRD
		if cfg.FilebeatRenewalThreshold != "" {
			if d, err := certificates.ParseCertDuration(cfg.FilebeatRenewalThreshold); err == nil {
				opts.FilebeatRenewalThreshold = d
			}
		}

		// Set certificate subject fields from CRD
		if cfg.Country != "" {
			opts.Country = cfg.Country
		}
		if cfg.State != "" {
			opts.State = cfg.State
		}
		if cfg.Locality != "" {
			opts.Locality = cfg.Locality
		}
		if cfg.Organization != "" {
			opts.Organization = cfg.Organization
		}
		if cfg.OrganizationalUnit != "" {
			opts.OrganizationalUnit = cfg.OrganizationalUnit
		}
		// Note: CommonName is not configurable - it's auto-generated per certificate type

		// Set key algorithm from CRD
		if cfg.KeyAlgorithm != "" {
			opts.KeyAlgorithm = certificates.KeyAlgorithm(cfg.KeyAlgorithm)
		}

		// Set ECDSA curve from CRD
		if cfg.ECDSACurve != "" {
			opts.ECDSACurve = certificates.ECDSACurve(cfg.ECDSACurve)
		}
	}

	return opts
}

// Reconcile reconciles certificates for the Wazuh cluster
func (r *CertificateReconciler) Reconcile(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	_, err := r.ReconcileWithHashes(ctx, cluster)
	return err
}

// ReconcileWithHashes reconciles certificates for the Wazuh cluster and returns certificate hashes
// The hashes can be used as pod annotations to trigger pod restarts when certificates are renewed
func (r *CertificateReconciler) ReconcileWithHashes(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*CertHashResult, error) {
	log := logf.FromContext(ctx)

	// Dispatch to custom certs reconciler if configured
	if cluster.Spec.TLS != nil && cluster.Spec.TLS.CustomCerts != nil {
		return r.reconcileCustomCerts(ctx, cluster)
	}

	// Get certificate options from CRD configuration
	certOpts := r.getCertOptions(cluster)
	log.V(1).Info("Using certificate options",
		"nodeValidity", certificates.FormatCertDuration(certOpts.GetNodeValidity()),
		"renewalThreshold", certificates.FormatCertDuration(certOpts.GetRenewalThreshold()))

	// Reconcile CA certificate
	caReconcileResult, err := r.reconcileCA(ctx, cluster, certOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile CA: %w", err)
	}

	caResult := caReconcileResult.CAResult
	caRenewed := caReconcileResult.Renewed

	// If CA renewal is pending (waiting for maintenance window), skip child cert reconciliation
	// and return early with the pending status
	if caReconcileResult.RenewalPending {
		log.Info("CA renewal pending - waiting for maintenance window",
			"nextWindow", caReconcileResult.NextMaintenanceWindow)
		result := &CertHashResult{
			CARenewalPending:     true,
			CARenewalScheduledAt: caReconcileResult.NextMaintenanceWindow,
		}
		// Still collect hashes from existing secrets
		existingResult, _ := r.collectCertHashes(ctx, cluster)
		if existingResult != nil {
			result.DashboardCertHash = existingResult.DashboardCertHash
			result.IndexerCertHash = existingResult.IndexerCertHash
			result.ManagerMasterCertHash = existingResult.ManagerMasterCertHash
			result.ManagerWorkerCertHash = existingResult.ManagerWorkerCertHash
			result.FilebeatCertHash = existingResult.FilebeatCertHash
			result.AdminCertHash = existingResult.AdminCertHash
			result.CACertHash = existingResult.CACertHash
		}
		return result, nil
	}

	// Reconcile Manager certificates
	if err := r.reconcileManagerCerts(ctx, cluster, caResult, certOpts); err != nil {
		return nil, fmt.Errorf("failed to reconcile manager certificates: %w", err)
	}

	// Reconcile Indexer certificates
	indexerCertsRenewed, err := r.reconcileIndexerCerts(ctx, cluster, caResult, certOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile indexer certificates: %w", err)
	}

	// Reconcile Dashboard certificates
	if err := r.reconcileDashboardCerts(ctx, cluster, caResult, certOpts); err != nil {
		return nil, fmt.Errorf("failed to reconcile dashboard certificates: %w", err)
	}

	// Reconcile Filebeat certificates
	if err := r.reconcileFilebeatCerts(ctx, cluster, caResult, certOpts); err != nil {
		return nil, fmt.Errorf("failed to reconcile filebeat certificates: %w", err)
	}

	// Reconcile Admin certificate
	if err := r.reconcileAdminCerts(ctx, cluster, caResult, certOpts); err != nil {
		return nil, fmt.Errorf("failed to reconcile admin certificates: %w", err)
	}

	// Collect certificate hashes from secrets
	result, err := r.collectCertHashes(ctx, cluster)
	if err != nil {
		log.Error(err, "Failed to collect certificate hashes, pods may not restart on cert renewal")
		// Don't fail the reconciliation if we can't collect hashes
	}

	// Set CARenewed flag so the controller knows to restart the indexer
	if result != nil {
		result.CARenewed = caRenewed
		result.IndexerCertsRenewed = indexerCertsRenewed

		if caRenewed {
			log.Info("CA was renewed - indexer will need to restart to reload trust store")
		}

		// If indexer certs were renewed but CA was NOT renewed, trigger hot reload
		// Hot reload only works for node cert renewal, not CA renewal
		if indexerCertsRenewed && !caRenewed {
			log.Info("Indexer certificates renewed - triggering hot reload")
			hotReloadResult := r.TriggerCertificateHotReload(ctx, cluster)
			if hotReloadResult.Error != nil {
				log.Error(hotReloadResult.Error, "Hot reload failed, indexer may need restart")
				result.HotReloadError = hotReloadResult.Error
			} else if hotReloadResult.APICallMade {
				log.Info("Hot reload API call successful - indexer does not need restart")
				result.HotReloadTriggered = true
			} else if hotReloadResult.Supported && !hotReloadResult.RequiresAPICall {
				log.Info("Hot reload is automatic for this version - indexer does not need restart")
				result.HotReloadTriggered = true
			}
		}
	}

	// Log hashes for debugging
	if result != nil {
		log.Info("Certificate hashes collected",
			"dashboardHash", utils.ShortHash(result.DashboardCertHash),
			"indexerHash", utils.ShortHash(result.IndexerCertHash),
			"masterHash", utils.ShortHash(result.ManagerMasterCertHash),
			"workerHash", utils.ShortHash(result.ManagerWorkerCertHash),
			"caRenewed", caRenewed)
	}

	// Record certificate expiry metrics
	r.recordCertificateExpiryMetrics(ctx, cluster)

	log.Info("Certificate reconciliation completed")
	return result, nil
}
