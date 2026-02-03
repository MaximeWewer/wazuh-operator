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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
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
}

// Certificate event reasons
const (
	// EventReasonCertificateRenewing is emitted when a certificate renewal starts
	EventReasonCertificateRenewing = "CertificateRenewing"
	// EventReasonCertificateRenewed is emitted when a certificate is successfully renewed
	EventReasonCertificateRenewed = "CertificateRenewed"
	// EventReasonCertificateRenewalFailed is emitted when a certificate renewal fails
	EventReasonCertificateRenewalFailed = "CertificateRenewalFailed"
	// EventReasonCertificateCreated is emitted when a new certificate is created
	EventReasonCertificateCreated = "CertificateCreated"
	// EventReasonCertificateDomainMismatch is emitted when a certificate has SANs with wrong cluster domain
	EventReasonCertificateDomainMismatch = "CertificateDomainMismatch"
)

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
		if cfg.CommonName != "" {
			opts.CommonName = cfg.CommonName
		}

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

// NewCertificateReconciler creates a new CertificateReconciler
func NewCertificateReconciler(c client.Client, scheme *runtime.Scheme) *CertificateReconciler {
	return &CertificateReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithEventRecorder sets the EventRecorder for the reconciler
func (r *CertificateReconciler) WithEventRecorder(recorder record.EventRecorder) *CertificateReconciler {
	r.EventRecorder = recorder
	return r
}

// WithPropagationTimeout sets the timeout for waiting for kubelet to sync certificates
// Use a short value (e.g., 1*time.Second) for unit tests
func (r *CertificateReconciler) WithPropagationTimeout(timeout time.Duration) *CertificateReconciler {
	r.PropagationTimeout = timeout
	return r
}

// emitCertificateRenewingEvent emits an event when certificate renewal starts
func (r *CertificateReconciler) emitCertificateRenewingEvent(cluster *wazuhv1.WazuhCluster, certName string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, EventReasonCertificateRenewing,
			"Starting renewal of certificate: %s", certName)
	}
}

// emitCertificateRenewedEvent emits an event when certificate renewal succeeds
func (r *CertificateReconciler) emitCertificateRenewedEvent(cluster *wazuhv1.WazuhCluster, certName string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, EventReasonCertificateRenewed,
			"Successfully renewed certificate: %s", certName)
	}
}

// emitCertificateRenewalFailedEvent emits an event when certificate renewal fails
func (r *CertificateReconciler) emitCertificateRenewalFailedEvent(cluster *wazuhv1.WazuhCluster, certName string, err error) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, EventReasonCertificateRenewalFailed,
			"Failed to renew certificate %s: %v", certName, err)
	}
}

// emitCertificateCreatedEvent emits an event when a new certificate is created
func (r *CertificateReconciler) emitCertificateCreatedEvent(cluster *wazuhv1.WazuhCluster, certName string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeNormal, EventReasonCertificateCreated,
			"Created new certificate: %s", certName)
	}
}

// emitCertificateDomainMismatchEvent emits a warning event when a certificate has SANs with wrong cluster domain
func (r *CertificateReconciler) emitCertificateDomainMismatchEvent(cluster *wazuhv1.WazuhCluster, certName, expectedDomain string) {
	if r.EventRecorder != nil {
		r.EventRecorder.Eventf(cluster, corev1.EventTypeWarning, EventReasonCertificateDomainMismatch,
			"Certificate %s has SANs with wrong cluster domain (expected: %s), triggering regeneration", certName, expectedDomain)
	}
}

// CertHashResult contains the certificate hashes for each component
// These hashes can be used as pod annotations to trigger restarts on cert renewal
type CertHashResult struct {
	// DashboardCertHash is the hash of the dashboard certificate secret
	DashboardCertHash string
	// IndexerCertHash is the hash of the indexer certificate secret
	IndexerCertHash string
	// ManagerMasterCertHash is the hash of the manager master certificate secret
	ManagerMasterCertHash string
	// ManagerWorkerCertHash is the hash of the manager worker certificate secret
	ManagerWorkerCertHash string
	// FilebeatCertHash is the hash of the filebeat certificate secret
	FilebeatCertHash string
	// AdminCertHash is the hash of the admin certificate secret
	AdminCertHash string
	// CACertHash is the hash of the CA certificate secret
	CACertHash string
	// CARenewed indicates if the CA certificate was renewed during this reconciliation
	// When true, the indexer must be restarted to reload the trust store
	// (OpenSearch's hot reload only works for node certs, not CA)
	CARenewed bool
	// IndexerCertsRenewed indicates if indexer node certificates were renewed
	// When true and CARenewed is false, hot reload API can be used instead of restart
	IndexerCertsRenewed bool
	// HotReloadTriggered indicates if hot reload API was successfully called
	// When true, the indexer does not need to be restarted for node cert renewal
	HotReloadTriggered bool
	// HotReloadError contains any error from the hot reload attempt
	HotReloadError error
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

	// Get certificate options from CRD configuration
	certOpts := r.getCertOptions(cluster)
	log.V(1).Info("Using certificate options",
		"nodeValidity", certificates.FormatCertDuration(certOpts.GetNodeValidity()),
		"renewalThreshold", certificates.FormatCertDuration(certOpts.GetRenewalThreshold()))

	// Reconcile CA certificate
	caResult, caRenewed, err := r.reconcileCA(ctx, cluster, certOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile CA: %w", err)
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

// collectCertHashes collects the certificate hashes from secrets
func (r *CertificateReconciler) collectCertHashes(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*CertHashResult, error) {
	result := &CertHashResult{}

	// Helper to get secret hash
	getSecretHash := func(secretName string) (string, error) {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
			if errors.IsNotFound(err) {
				return "", nil
			}
			return "", err
		}
		return utils.ShortHash(utils.HashSecretData(secret.Data)), nil
	}

	var err error

	// CA hash
	result.CACertHash, err = getSecretHash(cluster.Name + "-ca")
	if err != nil {
		return result, fmt.Errorf("failed to get CA secret hash: %w", err)
	}

	// Dashboard hash
	result.DashboardCertHash, err = getSecretHash(constants.DashboardCertsName(cluster.Name))
	if err != nil {
		return result, fmt.Errorf("failed to get dashboard secret hash: %w", err)
	}

	// Indexer hash
	result.IndexerCertHash, err = getSecretHash(constants.IndexerCertsName(cluster.Name))
	if err != nil {
		return result, fmt.Errorf("failed to get indexer secret hash: %w", err)
	}

	// Manager master hash
	result.ManagerMasterCertHash, err = getSecretHash(constants.ManagerMasterCertsName(cluster.Name))
	if err != nil {
		return result, fmt.Errorf("failed to get manager master secret hash: %w", err)
	}

	// Manager worker hash
	result.ManagerWorkerCertHash, err = getSecretHash(constants.ManagerWorkerCertsName(cluster.Name))
	if err != nil {
		return result, fmt.Errorf("failed to get manager worker secret hash: %w", err)
	}

	// Filebeat hash
	result.FilebeatCertHash, err = getSecretHash(constants.FilebeatCertsName(cluster.Name))
	if err != nil {
		return result, fmt.Errorf("failed to get filebeat secret hash: %w", err)
	}

	// Admin hash
	result.AdminCertHash, err = getSecretHash(constants.AdminCertsName(cluster.Name))
	if err != nil {
		return result, fmt.Errorf("failed to get admin secret hash: %w", err)
	}

	return result, nil
}

// recordCertificateExpiryMetrics records the expiry time of all certificates as Prometheus metrics
func (r *CertificateReconciler) recordCertificateExpiryMetrics(ctx context.Context, cluster *wazuhv1.WazuhCluster) {
	log := logf.FromContext(ctx)

	// Helper to get certificate expiry from secret
	getCertExpiry := func(secretName, certKey string) int64 {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
			return 0
		}
		certPEM, ok := secret.Data[certKey]
		if !ok {
			return 0
		}
		expiry, err := certificates.GetCertificateExpiry(certPEM)
		if err != nil {
			log.V(1).Info("Failed to get certificate expiry", "secret", secretName, "error", err)
			return 0
		}
		return expiry.Unix()
	}

	// Record CA certificate expiry
	if expiry := getCertExpiry(cluster.Name+"-ca", constants.SecretKeyCACert); expiry > 0 {
		metrics.SetWazuhCertificateExpiry(cluster.Name, cluster.Namespace, "ca", expiry)
	}

	// Record Indexer certificate expiry
	if expiry := getCertExpiry(constants.IndexerCertsName(cluster.Name), constants.SecretKeyNodeCert); expiry > 0 {
		metrics.SetWazuhCertificateExpiry(cluster.Name, cluster.Namespace, "indexer", expiry)
	}

	// Record Dashboard certificate expiry
	if expiry := getCertExpiry(constants.DashboardCertsName(cluster.Name), constants.SecretKeyNodeCert); expiry > 0 {
		metrics.SetWazuhCertificateExpiry(cluster.Name, cluster.Namespace, "dashboard", expiry)
	}

	// Record Manager master certificate expiry
	if expiry := getCertExpiry(constants.ManagerMasterCertsName(cluster.Name), constants.SecretKeyNodeCert); expiry > 0 {
		metrics.SetWazuhCertificateExpiry(cluster.Name, cluster.Namespace, "manager-master", expiry)
	}

	// Record Manager worker certificate expiry
	if expiry := getCertExpiry(constants.ManagerWorkerCertsName(cluster.Name), constants.SecretKeyNodeCert); expiry > 0 {
		metrics.SetWazuhCertificateExpiry(cluster.Name, cluster.Namespace, "manager-worker", expiry)
	}

	// Record Admin certificate expiry
	if expiry := getCertExpiry(constants.AdminCertsName(cluster.Name), constants.SecretKeyAdminCert); expiry > 0 {
		metrics.SetWazuhCertificateExpiry(cluster.Name, cluster.Namespace, "admin", expiry)
	}
}

// reconcileCA reconciles the CA certificate
// Returns the CA result, whether the CA was renewed, and any error
func (r *CertificateReconciler) reconcileCA(ctx context.Context, cluster *wazuhv1.WazuhCluster, certOpts *certificates.CertificateOptions) (*certificates.CAResult, bool, error) {
	log := logf.FromContext(ctx)
	secretName := cluster.Name + "-ca"
	caRenewed := false

	// Check if CA secret exists
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)
	if err == nil {
		// Parse existing CA
		caResult, err := certificates.ParseCA(found.Data[constants.SecretKeyCACert], found.Data[constants.SecretKeyCAKey])
		if err != nil {
			log.Error(err, "Failed to parse existing CA, regenerating")
		} else {
			// Check if CA needs renewal using options from CRD
			needsRenewal := certOpts.ShouldRenewCA(caResult)
			if needsRenewal {
				log.Info("CA certificate needs renewal", "name", secretName, "daysUntilExpiry", caResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetCARenewalThreshold()))
				// If CA needs renewal, regenerate it
				// This will trigger regeneration of all dependent certificates
				r.emitCertificateRenewingEvent(cluster, secretName)
				log.Info("Regenerating CA certificate", "name", secretName)
				caRenewed = true
				// Fall through to regenerate CA
			} else {
				// CA is valid and doesn't need renewal
				return caResult, false, nil
			}
		}
	}

	if err != nil && !errors.IsNotFound(err) {
		return nil, false, fmt.Errorf("failed to get CA secret: %w", err)
	}

	// Generate new CA using options from CRD
	log.Info("Generating new CA certificate", "name", secretName, "validity", certificates.FormatCertDuration(certOpts.GetCAValidity()),
		"country", certOpts.Country, "state", certOpts.State, "locality", certOpts.Locality,
		"organization", certOpts.Organization, "organizationalUnit", certOpts.OrganizationalUnit)
	caConfig := certificates.DefaultCAConfig(cluster.Name + "-ca")
	// Apply subject fields from CRD configuration
	caConfig.Country = certOpts.Country
	caConfig.State = certOpts.State
	caConfig.Locality = certOpts.Locality
	caConfig.Organization = certOpts.Organization
	caConfig.OrganizationalUnit = certOpts.OrganizationalUnit
	caConfig.Validity = certOpts.GetCAValidity()
	caConfig.KeyAlgorithm = certOpts.KeyAlgorithm
	caConfig.ECDSACurve = certOpts.ECDSACurve

	caResult, err := certificates.GenerateCA(caConfig)
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate CA: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				constants.LabelName:         "wazuh-ca",
				constants.LabelInstance:     cluster.Name,
				constants.LabelComponent:    "certificates",
				constants.LabelPartOf:       constants.AppName,
				constants.LabelManagedBy:    constants.OperatorName,
				constants.LabelWazuhCluster: cluster.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyCAKey:   caResult.PrivateKeyPEM,
			constants.SecretKeyTLSCert: caResult.CertificatePEM,
			constants.SecretKeyTLSKey:  caResult.PrivateKeyPEM,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
		return nil, false, fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Use CreateOrUpdate to handle both creation and renewal
	isRenewal := found.Name != ""
	if isRenewal {
		// Update existing secret
		found.Data = secret.Data
		found.Labels = secret.Labels
		if err := r.Update(ctx, found); err != nil {
			r.emitCertificateRenewalFailedEvent(cluster, secretName, err)
			return nil, false, fmt.Errorf("failed to update CA secret: %w", err)
		}
		r.emitCertificateRenewedEvent(cluster, secretName)
		log.Info("CA certificate renewed successfully", "name", secretName)
		caRenewed = true
	} else {
		// Create new secret
		if err := r.Create(ctx, secret); err != nil {
			r.emitCertificateRenewalFailedEvent(cluster, secretName, err)
			return nil, false, fmt.Errorf("failed to create CA secret: %w", err)
		}
		r.emitCertificateCreatedEvent(cluster, secretName)
	}

	return caResult, caRenewed, nil
}

// reconcileManagerCerts reconciles manager node certificates
func (r *CertificateReconciler) reconcileManagerCerts(ctx context.Context, cluster *wazuhv1.WazuhCluster, caResult *certificates.CAResult, certOpts *certificates.CertificateOptions) error {
	log := logf.FromContext(ctx)

	// Generate SANs for manager nodes
	// Handle nil Manager spec (Workers is a value type, not pointer)
	var workerReplicas int32
	if cluster.Spec.Manager != nil {
		workerReplicas = cluster.Spec.Manager.Workers.GetReplicas()
	}
	sans := certificates.GenerateManagerNodeSANs(cluster.Name, cluster.Namespace, workerReplicas)

	// Master certificate
	masterSecretName := constants.ManagerMasterCertsName(cluster.Name)
	if err := r.reconcileNodeCert(ctx, cluster, masterSecretName, constants.CertComponentManagerMaster, sans, caResult, certOpts); err != nil {
		return fmt.Errorf("failed to reconcile master certificate: %w", err)
	}

	// Worker certificate
	workerSecretName := constants.ManagerWorkerCertsName(cluster.Name)
	if err := r.reconcileNodeCert(ctx, cluster, workerSecretName, constants.CertComponentManagerWorker, sans, caResult, certOpts); err != nil {
		return fmt.Errorf("failed to reconcile worker certificate: %w", err)
	}

	log.V(1).Info("Manager certificates reconciled")
	return nil
}

// reconcileIndexerCerts reconciles indexer certificates
// Returns whether the certificates were renewed (true) or already valid (false)
func (r *CertificateReconciler) reconcileIndexerCerts(ctx context.Context, cluster *wazuhv1.WazuhCluster, caResult *certificates.CAResult, certOpts *certificates.CertificateOptions) (bool, error) {
	replicas := int32(1)
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Replicas > 0 {
		replicas = cluster.Spec.Indexer.Replicas
	}
	sans := certificates.GenerateIndexerNodeSANs(cluster.Name, cluster.Namespace, replicas)

	secretName := constants.IndexerCertsName(cluster.Name)
	return r.reconcileNodeCertWithRenewalStatus(ctx, cluster, secretName, constants.CertComponentIndexer, sans, caResult, certOpts)
}

// reconcileDashboardCerts reconciles dashboard certificates
func (r *CertificateReconciler) reconcileDashboardCerts(ctx context.Context, cluster *wazuhv1.WazuhCluster, caResult *certificates.CAResult, certOpts *certificates.CertificateOptions) error {
	log := logf.FromContext(ctx)
	secretName := constants.DashboardCertsName(cluster.Name)

	// Check if secret exists
	found := &corev1.Secret{}
	getErr := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)
	secretExists := getErr == nil

	if secretExists {
		// Check if certificate needs renewal using options from CRD
		certResult, parseErr := certificates.ParseDashboardCert(found.Data[constants.SecretKeyTLSCert], found.Data[constants.SecretKeyTLSKey])
		if parseErr == nil {
			// Check for cluster domain mismatch
			if certificates.RequiresDomainRegeneration(certResult.Certificate, secretName, cluster.Namespace, log) {
				log.Info("Dashboard certificate has domain mismatch, regenerating",
					"name", secretName,
					"expectedDomain", dns.ClusterDomain())
				r.emitCertificateDomainMismatchEvent(cluster, secretName, dns.ClusterDomain())
				// Fall through to regenerate certificate
			} else {
				needsRenewal := certOpts.ShouldRenewDashboard(certResult)
				if needsRenewal {
					log.Info("Dashboard certificate needs renewal", "name", secretName, "daysUntilExpiry", certResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetRenewalThreshold()))
					// Emit event before starting renewal
					r.emitCertificateRenewingEvent(cluster, secretName)
				}
				if !needsRenewal {
					return nil
				}
			}
		}
		if parseErr != nil {
			log.Info("Failed to parse dashboard certificate, regenerating", "error", parseErr.Error())
		}
	} else if !errors.IsNotFound(getErr) {
		return fmt.Errorf("failed to get dashboard secret: %w", getErr)
	}

	// Generate new dashboard certificate using options from CRD
	log.Info("Generating new dashboard certificate", "name", secretName, "validity", certificates.FormatCertDuration(certOpts.GetNodeValidity()))
	dashboardConfig := certificates.DefaultDashboardCertConfig()
	dashboardConfig.CommonName = cluster.Name + "-dashboard"
	dashboardConfig.DNSNames = certificates.GenerateDashboardSANs(cluster.Name, cluster.Namespace)
	// Apply subject fields from CRD configuration
	dashboardConfig.Country = certOpts.Country
	dashboardConfig.State = certOpts.State
	dashboardConfig.Locality = certOpts.Locality
	dashboardConfig.Organization = certOpts.Organization
	dashboardConfig.OrganizationalUnit = certOpts.OrganizationalUnit
	dashboardConfig.Validity = certOpts.GetNodeValidity()
	dashboardConfig.KeyAlgorithm = certOpts.KeyAlgorithm
	dashboardConfig.ECDSACurve = certOpts.ECDSACurve

	certResult, err := certificates.GenerateDashboardCert(dashboardConfig, caResult)
	if err != nil {
		return fmt.Errorf("failed to generate dashboard certificate: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				constants.LabelName:         "wazuh-dashboard",
				constants.LabelInstance:     cluster.Name,
				constants.LabelComponent:    "dashboard",
				constants.LabelPartOf:       constants.AppName,
				constants.LabelManagedBy:    constants.OperatorName,
				constants.LabelWazuhCluster: cluster.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyTLSCert: certResult.CertificatePEM,
			constants.SecretKeyTLSKey:  certResult.PrivateKeyPEM,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	if !secretExists {
		if err := r.Create(ctx, secret); err != nil {
			r.emitCertificateRenewalFailedEvent(cluster, secretName, err)
			return fmt.Errorf("failed to create dashboard secret: %w", err)
		}
		r.emitCertificateCreatedEvent(cluster, secretName)
	} else {
		secret.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, secret); err != nil {
			r.emitCertificateRenewalFailedEvent(cluster, secretName, err)
			return fmt.Errorf("failed to update dashboard secret: %w", err)
		}
		r.emitCertificateRenewedEvent(cluster, secretName)
	}

	return nil
}

// reconcileFilebeatCerts reconciles filebeat certificates
func (r *CertificateReconciler) reconcileFilebeatCerts(ctx context.Context, cluster *wazuhv1.WazuhCluster, caResult *certificates.CAResult, certOpts *certificates.CertificateOptions) error {
	log := logf.FromContext(ctx)
	secretName := constants.FilebeatCertsName(cluster.Name)

	// Check if secret exists
	found := &corev1.Secret{}
	getErr := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)
	secretExists := getErr == nil

	if secretExists {
		// Check if certificate needs renewal using options from CRD
		certResult, parseErr := certificates.ParseFilebeatCert(found.Data[constants.SecretKeyTLSCert], found.Data[constants.SecretKeyTLSKey])
		if parseErr == nil {
			// Check for cluster domain mismatch
			if certificates.RequiresDomainRegeneration(certResult.Certificate, secretName, cluster.Namespace, log) {
				log.Info("Filebeat certificate has domain mismatch, regenerating",
					"name", secretName,
					"expectedDomain", dns.ClusterDomain())
				r.emitCertificateDomainMismatchEvent(cluster, secretName, dns.ClusterDomain())
				// Fall through to regenerate certificate
			} else {
				needsRenewal := certOpts.ShouldRenewFilebeat(certResult)
				if needsRenewal {
					log.Info("Filebeat certificate needs renewal", "name", secretName, "daysUntilExpiry", certResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetRenewalThreshold()))
					// Emit event before starting renewal
					r.emitCertificateRenewingEvent(cluster, secretName)
				}
				if !needsRenewal {
					return nil
				}
			}
		}
		if parseErr != nil {
			log.Info("Failed to parse filebeat certificate, regenerating", "error", parseErr.Error())
		}
	} else if !errors.IsNotFound(getErr) {
		return fmt.Errorf("failed to get filebeat secret: %w", getErr)
	}

	// Generate new filebeat certificate using options from CRD
	log.Info("Generating new filebeat certificate", "name", secretName, "validity", certificates.FormatCertDuration(certOpts.GetNodeValidity()))
	var workerReplicas int32
	if cluster.Spec.Manager != nil {
		workerReplicas = cluster.Spec.Manager.Workers.GetReplicas()
	}

	filebeatConfig := certificates.DefaultFilebeatCertConfig()
	filebeatConfig.CommonName = cluster.Name + "-filebeat"
	filebeatConfig.DNSNames = certificates.GenerateFilebeatSANs(cluster.Name, cluster.Namespace, workerReplicas)
	// Apply subject fields from CRD configuration
	filebeatConfig.Country = certOpts.Country
	filebeatConfig.State = certOpts.State
	filebeatConfig.Locality = certOpts.Locality
	filebeatConfig.Organization = certOpts.Organization
	filebeatConfig.OrganizationalUnit = certOpts.OrganizationalUnit
	filebeatConfig.Validity = certOpts.GetNodeValidity()
	filebeatConfig.KeyAlgorithm = certOpts.KeyAlgorithm
	filebeatConfig.ECDSACurve = certOpts.ECDSACurve

	certResult, err := certificates.GenerateFilebeatCert(filebeatConfig, caResult)
	if err != nil {
		return fmt.Errorf("failed to generate filebeat certificate: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				constants.LabelName:         "wazuh-filebeat",
				constants.LabelInstance:     cluster.Name,
				constants.LabelComponent:    "filebeat",
				constants.LabelPartOf:       constants.AppName,
				constants.LabelManagedBy:    constants.OperatorName,
				constants.LabelWazuhCluster: cluster.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyTLSCert: certResult.CertificatePEM,
			constants.SecretKeyTLSKey:  certResult.PrivateKeyPEM,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	if !secretExists {
		if err := r.Create(ctx, secret); err != nil {
			r.emitCertificateRenewalFailedEvent(cluster, secretName, err)
			return fmt.Errorf("failed to create filebeat secret: %w", err)
		}
		r.emitCertificateCreatedEvent(cluster, secretName)
	} else {
		secret.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, secret); err != nil {
			r.emitCertificateRenewalFailedEvent(cluster, secretName, err)
			return fmt.Errorf("failed to update filebeat secret: %w", err)
		}
		r.emitCertificateRenewedEvent(cluster, secretName)
	}

	return nil
}

// reconcileAdminCerts reconciles admin certificates
func (r *CertificateReconciler) reconcileAdminCerts(ctx context.Context, cluster *wazuhv1.WazuhCluster, caResult *certificates.CAResult, certOpts *certificates.CertificateOptions) error {
	log := logf.FromContext(ctx)
	secretName := constants.AdminCertsName(cluster.Name)

	// Check if secret exists
	found := &corev1.Secret{}
	getErr := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)
	secretExists := getErr == nil

	if secretExists {
		// Check if certificate needs renewal using options from CRD
		certResult, parseErr := certificates.ParseAdminCert(found.Data[constants.SecretKeyTLSCert], found.Data[constants.SecretKeyTLSKey])
		if parseErr == nil {
			// Check for cluster domain mismatch (admin certs typically don't have K8s FQDNs, but check anyway)
			if certificates.RequiresDomainRegeneration(certResult.Certificate, secretName, cluster.Namespace, log) {
				log.Info("Admin certificate has domain mismatch, regenerating",
					"name", secretName,
					"expectedDomain", dns.ClusterDomain())
				r.emitCertificateDomainMismatchEvent(cluster, secretName, dns.ClusterDomain())
				// Fall through to regenerate certificate
			} else {
				needsRenewal := certOpts.ShouldRenewAdmin(certResult)
				if needsRenewal {
					log.Info("Admin certificate needs renewal", "name", secretName, "daysUntilExpiry", certResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetRenewalThreshold()))
					// Emit event before starting renewal
					r.emitCertificateRenewingEvent(cluster, secretName)
				}
				if !needsRenewal {
					return nil
				}
			}
		}
		if parseErr != nil {
			log.Info("Failed to parse admin certificate, regenerating", "error", parseErr.Error())
		}
	} else if !errors.IsNotFound(getErr) {
		return fmt.Errorf("failed to get admin secret: %w", getErr)
	}

	// Generate new admin certificate using options from CRD
	log.Info("Generating new admin certificate", "name", secretName, "validity", certificates.FormatCertDuration(certOpts.GetNodeValidity()))
	adminConfig := certificates.DefaultAdminCertConfig()
	// Apply subject fields from CRD configuration
	adminConfig.Country = certOpts.Country
	adminConfig.State = certOpts.State
	adminConfig.Locality = certOpts.Locality
	adminConfig.Organization = certOpts.Organization
	adminConfig.OrganizationalUnit = certOpts.OrganizationalUnit
	adminConfig.Validity = certOpts.GetNodeValidity()
	adminConfig.KeyAlgorithm = certOpts.KeyAlgorithm
	adminConfig.ECDSACurve = certOpts.ECDSACurve

	certResult, err := certificates.GenerateAdminCert(adminConfig, caResult)
	if err != nil {
		return fmt.Errorf("failed to generate admin certificate: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				constants.LabelName:         "wazuh-admin",
				constants.LabelInstance:     cluster.Name,
				constants.LabelComponent:    "certificates",
				constants.LabelPartOf:       constants.AppName,
				constants.LabelManagedBy:    constants.OperatorName,
				constants.LabelWazuhCluster: cluster.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyTLSCert: certResult.CertificatePEM,
			constants.SecretKeyTLSKey:  certResult.PrivateKeyPEM,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	if !secretExists {
		if err := r.Create(ctx, secret); err != nil {
			r.emitCertificateRenewalFailedEvent(cluster, secretName, err)
			return fmt.Errorf("failed to create admin secret: %w", err)
		}
		r.emitCertificateCreatedEvent(cluster, secretName)
	} else {
		secret.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, secret); err != nil {
			r.emitCertificateRenewalFailedEvent(cluster, secretName, err)
			return fmt.Errorf("failed to update admin secret: %w", err)
		}
		r.emitCertificateRenewedEvent(cluster, secretName)
	}

	return nil
}

// ReconcileStandalone reconciles a standalone WazuhCertificate resource
func (r *CertificateReconciler) ReconcileStandalone(ctx context.Context, cert *wazuhv1.WazuhCertificate) error {
	log := logf.FromContext(ctx)

	// Get or create CA for signing
	caResult, err := r.getOrCreateStandaloneCA(ctx, cert)
	if err != nil {
		return fmt.Errorf("failed to get/create CA: %w", err)
	}

	// Generate SANs based on spec
	sans := r.generateSANs(cert)

	// Generate certificate based on type
	var certData map[string][]byte
	switch cert.Spec.Type {
	case wazuhv1.CertificateTypeCA:
		certData = map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyCAKey:   caResult.PrivateKeyPEM,
			constants.SecretKeyTLSCert: caResult.CertificatePEM,
			constants.SecretKeyTLSKey:  caResult.PrivateKeyPEM,
		}
	case wazuhv1.CertificateTypeNode, wazuhv1.CertificateTypeIndexer:
		commonName := cert.Name
		if cert.Spec.DistinguishedName != nil && cert.Spec.DistinguishedName.CommonName != "" {
			commonName = cert.Spec.DistinguishedName.CommonName
		}
		nodeConfig := certificates.DefaultNodeCertConfig(commonName)
		nodeConfig.DNSNames = sans
		if cert.Spec.Validity != "" {
			if d, err := certificates.ParseCertDuration(cert.Spec.Validity); err == nil {
				nodeConfig.Validity = d
			}
		}
		// Apply subject fields from standalone certificate spec
		if cert.Spec.DistinguishedName != nil {
			if cert.Spec.DistinguishedName.Country != "" {
				nodeConfig.Country = cert.Spec.DistinguishedName.Country
			}
			if cert.Spec.DistinguishedName.State != "" {
				nodeConfig.State = cert.Spec.DistinguishedName.State
			}
			if cert.Spec.DistinguishedName.Locality != "" {
				nodeConfig.Locality = cert.Spec.DistinguishedName.Locality
			}
			if cert.Spec.DistinguishedName.Organization != "" {
				nodeConfig.Organization = cert.Spec.DistinguishedName.Organization
			}
			if cert.Spec.DistinguishedName.OrganizationalUnit != "" {
				nodeConfig.OrganizationalUnit = cert.Spec.DistinguishedName.OrganizationalUnit
			}
		}
		// Apply key algorithm from standalone certificate spec
		if cert.Spec.KeyConfig != nil {
			if cert.Spec.KeyConfig.Algorithm != "" {
				nodeConfig.KeyAlgorithm = certificates.KeyAlgorithm(cert.Spec.KeyConfig.Algorithm)
			}
			if cert.Spec.KeyConfig.Curve != "" {
				nodeConfig.ECDSACurve = certificates.ECDSACurve(cert.Spec.KeyConfig.Curve)
			}
		}
		nodeCert, err := certificates.GenerateNodeCert(nodeConfig, caResult)
		if err != nil {
			return fmt.Errorf("failed to generate node certificate: %w", err)
		}
		certData = map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyTLSCert: nodeCert.CertificatePEM,
			constants.SecretKeyTLSKey:  nodeCert.PrivateKeyPEM,
		}
	case wazuhv1.CertificateTypeAdmin:
		adminConfig := certificates.DefaultAdminCertConfig()
		if cert.Spec.Validity != "" {
			if d, err := certificates.ParseCertDuration(cert.Spec.Validity); err == nil {
				adminConfig.Validity = d
			}
		}
		// Apply subject fields from standalone certificate spec
		if cert.Spec.DistinguishedName != nil {
			if cert.Spec.DistinguishedName.Country != "" {
				adminConfig.Country = cert.Spec.DistinguishedName.Country
			}
			if cert.Spec.DistinguishedName.State != "" {
				adminConfig.State = cert.Spec.DistinguishedName.State
			}
			if cert.Spec.DistinguishedName.Locality != "" {
				adminConfig.Locality = cert.Spec.DistinguishedName.Locality
			}
			if cert.Spec.DistinguishedName.Organization != "" {
				adminConfig.Organization = cert.Spec.DistinguishedName.Organization
			}
			if cert.Spec.DistinguishedName.OrganizationalUnit != "" {
				adminConfig.OrganizationalUnit = cert.Spec.DistinguishedName.OrganizationalUnit
			}
		}
		// Apply key algorithm from standalone certificate spec
		if cert.Spec.KeyConfig != nil {
			if cert.Spec.KeyConfig.Algorithm != "" {
				adminConfig.KeyAlgorithm = certificates.KeyAlgorithm(cert.Spec.KeyConfig.Algorithm)
			}
			if cert.Spec.KeyConfig.Curve != "" {
				adminConfig.ECDSACurve = certificates.ECDSACurve(cert.Spec.KeyConfig.Curve)
			}
		}
		adminCert, err := certificates.GenerateAdminCert(adminConfig, caResult)
		if err != nil {
			return fmt.Errorf("failed to generate admin certificate: %w", err)
		}
		certData = map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyTLSCert: adminCert.CertificatePEM,
			constants.SecretKeyTLSKey:  adminCert.PrivateKeyPEM,
		}
	case wazuhv1.CertificateTypeFilebeat:
		commonName := cert.Name
		if cert.Spec.DistinguishedName != nil && cert.Spec.DistinguishedName.CommonName != "" {
			commonName = cert.Spec.DistinguishedName.CommonName
		}
		filebeatConfig := certificates.DefaultFilebeatCertConfig()
		filebeatConfig.CommonName = commonName
		filebeatConfig.DNSNames = sans
		if cert.Spec.Validity != "" {
			if d, err := certificates.ParseCertDuration(cert.Spec.Validity); err == nil {
				filebeatConfig.Validity = d
			}
		}
		// Apply subject fields from standalone certificate spec
		if cert.Spec.DistinguishedName != nil {
			if cert.Spec.DistinguishedName.Country != "" {
				filebeatConfig.Country = cert.Spec.DistinguishedName.Country
			}
			if cert.Spec.DistinguishedName.State != "" {
				filebeatConfig.State = cert.Spec.DistinguishedName.State
			}
			if cert.Spec.DistinguishedName.Locality != "" {
				filebeatConfig.Locality = cert.Spec.DistinguishedName.Locality
			}
			if cert.Spec.DistinguishedName.Organization != "" {
				filebeatConfig.Organization = cert.Spec.DistinguishedName.Organization
			}
			if cert.Spec.DistinguishedName.OrganizationalUnit != "" {
				filebeatConfig.OrganizationalUnit = cert.Spec.DistinguishedName.OrganizationalUnit
			}
		}
		// Apply key algorithm from standalone certificate spec
		if cert.Spec.KeyConfig != nil {
			if cert.Spec.KeyConfig.Algorithm != "" {
				filebeatConfig.KeyAlgorithm = certificates.KeyAlgorithm(cert.Spec.KeyConfig.Algorithm)
			}
			if cert.Spec.KeyConfig.Curve != "" {
				filebeatConfig.ECDSACurve = certificates.ECDSACurve(cert.Spec.KeyConfig.Curve)
			}
		}
		filebeatCert, err := certificates.GenerateFilebeatCert(filebeatConfig, caResult)
		if err != nil {
			return fmt.Errorf("failed to generate filebeat certificate: %w", err)
		}
		certData = map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyTLSCert: filebeatCert.CertificatePEM,
			constants.SecretKeyTLSKey:  filebeatCert.PrivateKeyPEM,
		}
	case wazuhv1.CertificateTypeDashboard:
		commonName := cert.Name
		if cert.Spec.DistinguishedName != nil && cert.Spec.DistinguishedName.CommonName != "" {
			commonName = cert.Spec.DistinguishedName.CommonName
		}
		dashboardConfig := certificates.DefaultDashboardCertConfig()
		dashboardConfig.CommonName = commonName
		dashboardConfig.DNSNames = sans
		if cert.Spec.Validity != "" {
			if d, err := certificates.ParseCertDuration(cert.Spec.Validity); err == nil {
				dashboardConfig.Validity = d
			}
		}
		// Apply subject fields from standalone certificate spec
		if cert.Spec.DistinguishedName != nil {
			if cert.Spec.DistinguishedName.Country != "" {
				dashboardConfig.Country = cert.Spec.DistinguishedName.Country
			}
			if cert.Spec.DistinguishedName.State != "" {
				dashboardConfig.State = cert.Spec.DistinguishedName.State
			}
			if cert.Spec.DistinguishedName.Locality != "" {
				dashboardConfig.Locality = cert.Spec.DistinguishedName.Locality
			}
			if cert.Spec.DistinguishedName.Organization != "" {
				dashboardConfig.Organization = cert.Spec.DistinguishedName.Organization
			}
			if cert.Spec.DistinguishedName.OrganizationalUnit != "" {
				dashboardConfig.OrganizationalUnit = cert.Spec.DistinguishedName.OrganizationalUnit
			}
		}
		// Apply key algorithm from standalone certificate spec
		if cert.Spec.KeyConfig != nil {
			if cert.Spec.KeyConfig.Algorithm != "" {
				dashboardConfig.KeyAlgorithm = certificates.KeyAlgorithm(cert.Spec.KeyConfig.Algorithm)
			}
			if cert.Spec.KeyConfig.Curve != "" {
				dashboardConfig.ECDSACurve = certificates.ECDSACurve(cert.Spec.KeyConfig.Curve)
			}
		}
		dashboardCert, err := certificates.GenerateDashboardCert(dashboardConfig, caResult)
		if err != nil {
			return fmt.Errorf("failed to generate dashboard certificate: %w", err)
		}
		certData = map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyTLSCert: dashboardCert.CertificatePEM,
			constants.SecretKeyTLSKey:  dashboardCert.PrivateKeyPEM,
		}
	default:
		return fmt.Errorf("unsupported certificate type: %s", cert.Spec.Type)
	}

	// Create or update the secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cert.Spec.SecretName,
			Namespace: cert.Namespace,
			Labels: map[string]string{
				constants.LabelName:      "wazuh-certificate",
				constants.LabelInstance:  cert.Name,
				constants.LabelComponent: string(cert.Spec.Type),
				constants.LabelPartOf:    constants.AppName,
				constants.LabelManagedBy: constants.OperatorName,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: certData,
	}

	if err := controllerutil.SetControllerReference(cert, secret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Check if secret exists
	found := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating certificate secret", "name", secret.Name)
		if err := r.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	} else {
		secret.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, secret); err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}
	}

	log.Info("Standalone certificate reconciliation completed", "name", cert.Name)
	return nil
}

// getOrCreateStandaloneCA gets or creates a CA for standalone certificate generation
func (r *CertificateReconciler) getOrCreateStandaloneCA(ctx context.Context, cert *wazuhv1.WazuhCertificate) (*certificates.CAResult, error) {
	// If this is a CA certificate, generate a new one
	if cert.Spec.Type == wazuhv1.CertificateTypeCA {
		caConfig := certificates.DefaultCAConfig(cert.Name)
		if cert.Spec.DistinguishedName != nil {
			if cert.Spec.DistinguishedName.Organization != "" {
				caConfig.Organization = cert.Spec.DistinguishedName.Organization
			}
		}
		if cert.Spec.Validity != "" {
			if d, err := certificates.ParseCertDuration(cert.Spec.Validity); err == nil {
				caConfig.Validity = d
			}
		}
		// Apply key algorithm from standalone certificate spec
		if cert.Spec.KeyConfig != nil {
			if cert.Spec.KeyConfig.Algorithm != "" {
				caConfig.KeyAlgorithm = certificates.KeyAlgorithm(cert.Spec.KeyConfig.Algorithm)
			}
			if cert.Spec.KeyConfig.Curve != "" {
				caConfig.ECDSACurve = certificates.ECDSACurve(cert.Spec.KeyConfig.Curve)
			}
		}
		return certificates.GenerateCA(caConfig)
	}

	// For other types, try to find existing CA from cluster reference
	caSecretName := cert.Spec.ClusterRef + "-ca"
	caSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: caSecretName, Namespace: cert.Namespace}, caSecret); err != nil {
		if errors.IsNotFound(err) {
			// Generate a new CA if none exists
			caConfig := certificates.DefaultCAConfig(cert.Spec.ClusterRef + "-ca")
			// Apply key algorithm from standalone certificate spec
			if cert.Spec.KeyConfig != nil {
				if cert.Spec.KeyConfig.Algorithm != "" {
					caConfig.KeyAlgorithm = certificates.KeyAlgorithm(cert.Spec.KeyConfig.Algorithm)
				}
				if cert.Spec.KeyConfig.Curve != "" {
					caConfig.ECDSACurve = certificates.ECDSACurve(cert.Spec.KeyConfig.Curve)
				}
			}
			return certificates.GenerateCA(caConfig)
		}
		return nil, fmt.Errorf("failed to get CA secret: %w", err)
	}

	// Parse existing CA
	return certificates.ParseCA(caSecret.Data[constants.SecretKeyCACert], caSecret.Data[constants.SecretKeyCAKey])
}

// generateSANs generates Subject Alternative Names based on certificate spec
func (r *CertificateReconciler) generateSANs(cert *wazuhv1.WazuhCertificate) []string {
	var sans []string

	// Add explicit SANs from spec
	if len(cert.Spec.SANs) > 0 {
		sans = append(sans, cert.Spec.SANs...)
	}

	// Auto-generate SANs if enabled
	if cert.Spec.AutoGenerateSANs != nil && cert.Spec.AutoGenerateSANs.Enabled {
		namespace := cert.Spec.AutoGenerateSANs.Namespace
		if namespace == "" {
			namespace = cert.Namespace
		}
		clusterName := cert.Spec.ClusterRef

		switch cert.Spec.Type {
		case wazuhv1.CertificateTypeIndexer, wazuhv1.CertificateTypeNode:
			replicas := cert.Spec.AutoGenerateSANs.IndexerReplicas
			if replicas == 0 {
				replicas = 3
			}
			sans = append(sans, certificates.GenerateIndexerNodeSANs(clusterName, namespace, replicas)...)
		case wazuhv1.CertificateTypeDashboard:
			sans = append(sans, certificates.GenerateDashboardSANs(clusterName, namespace)...)
		case wazuhv1.CertificateTypeFilebeat:
			sans = append(sans, certificates.GenerateFilebeatSANs(clusterName, namespace, 0)...)
		case wazuhv1.CertificateTypeAdmin:
			sans = append(sans, "localhost")
		}

		// Add additional custom SANs
		if len(cert.Spec.AutoGenerateSANs.AdditionalSANs) > 0 {
			sans = append(sans, cert.Spec.AutoGenerateSANs.AdditionalSANs...)
		}
	}

	// Ensure localhost is always included for admin certs
	if cert.Spec.Type == wazuhv1.CertificateTypeAdmin && len(sans) == 0 {
		sans = []string{"localhost"}
	}

	return sans
}

// reconcileNodeCert reconciles a node certificate
func (r *CertificateReconciler) reconcileNodeCert(ctx context.Context, cluster *wazuhv1.WazuhCluster, secretName, componentName string, sans []string, caResult *certificates.CAResult, certOpts *certificates.CertificateOptions) error {
	_, err := r.reconcileNodeCertWithRenewalStatus(ctx, cluster, secretName, componentName, sans, caResult, certOpts)
	return err
}

// reconcileNodeCertWithRenewalStatus reconciles a node certificate and returns whether it was renewed
func (r *CertificateReconciler) reconcileNodeCertWithRenewalStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster, secretName, componentName string, sans []string, caResult *certificates.CAResult, certOpts *certificates.CertificateOptions) (bool, error) {
	log := logf.FromContext(ctx)

	// Check if secret exists
	found := &corev1.Secret{}
	getErr := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)
	secretExists := getErr == nil

	if secretExists {
		// Check if certificate needs renewal using options from CRD
		certResult, parseErr := certificates.ParseNodeCert(found.Data[constants.SecretKeyTLSCert], found.Data[constants.SecretKeyTLSKey])
		if parseErr == nil {
			// Check for cluster domain mismatch (e.g., after operator upgrade with new domain)
			if certificates.RequiresDomainRegeneration(certResult.Certificate, secretName, cluster.Namespace, log) {
				log.Info("Node certificate has domain mismatch, regenerating",
					"name", secretName,
					"component", componentName,
					"expectedDomain", dns.ClusterDomain())
				r.emitCertificateDomainMismatchEvent(cluster, secretName, dns.ClusterDomain())
				// Fall through to regenerate certificate
			} else {
				// Check if certificate needs renewal due to expiry
				needsRenewal := certOpts.ShouldRenewNode(certResult)
				if needsRenewal {
					log.Info("Node certificate needs renewal", "name", secretName, "component", componentName, "daysUntilExpiry", certResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetRenewalThreshold()))
				}
				if !needsRenewal {
					return false, nil // Certificate is still valid, no renewal
				}
			}
		}
		if parseErr != nil {
			log.Info("Failed to parse node certificate, regenerating", "error", parseErr.Error())
		}
	} else if !errors.IsNotFound(getErr) {
		return false, fmt.Errorf("failed to get node secret: %w", getErr)
	}

	// Generate new node certificate using options from CRD
	log.Info("Generating new node certificate", "name", secretName, "component", componentName, "validity", certificates.FormatCertDuration(certOpts.GetNodeValidity()))
	nodeConfig := certificates.DefaultNodeCertConfig(cluster.Name + "-" + componentName)
	nodeConfig.DNSNames = sans
	// Apply subject fields from CRD configuration
	nodeConfig.Country = certOpts.Country
	nodeConfig.State = certOpts.State
	nodeConfig.Locality = certOpts.Locality
	nodeConfig.Organization = certOpts.Organization
	nodeConfig.OrganizationalUnit = certOpts.OrganizationalUnit
	nodeConfig.Validity = certOpts.GetNodeValidity()
	nodeConfig.KeyAlgorithm = certOpts.KeyAlgorithm
	nodeConfig.ECDSACurve = certOpts.ECDSACurve

	certResult, err := certificates.GenerateNodeCert(nodeConfig, caResult)
	if err != nil {
		return false, fmt.Errorf("failed to generate node certificate: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels: map[string]string{
				constants.LabelName:         fmt.Sprintf("wazuh-%s", componentName),
				constants.LabelInstance:     cluster.Name,
				constants.LabelComponent:    componentName,
				constants.LabelPartOf:       constants.AppName,
				constants.LabelManagedBy:    constants.OperatorName,
				constants.LabelWazuhCluster: cluster.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.SecretKeyCACert:  caResult.CertificatePEM,
			constants.SecretKeyTLSCert: certResult.CertificatePEM,
			constants.SecretKeyTLSKey:  certResult.PrivateKeyPEM,
		},
	}

	if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
		return false, fmt.Errorf("failed to set controller reference: %w", err)
	}

	if !secretExists {
		if err := r.Create(ctx, secret); err != nil {
			return false, fmt.Errorf("failed to create node secret: %w", err)
		}
		return false, nil // Certificate was created (not renewed)
	}

	// Secret exists, update it (this is a renewal)
	secret.SetResourceVersion(found.GetResourceVersion())
	if err := r.Update(ctx, secret); err != nil {
		return false, fmt.Errorf("failed to update node secret: %w", err)
	}

	return true, nil // Certificate was renewed
}
