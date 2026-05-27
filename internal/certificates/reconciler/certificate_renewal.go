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

package reconciler

import (
	"context"
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	certcommon "github.com/MaximeWewer/wazuh-operator/internal/certificates/common"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

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
			// Record certificate expiry metric
			secondsUntilExpiry := time.Until(certResult.Certificate.NotAfter).Seconds()
			metrics.SetCertificateExpiry(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, constants.CertTypeDashboard, secondsUntilExpiry)

			// Record certificate info metric
			metrics.SetCertificateInfo(cluster.Name, cluster.Namespace, constants.CertComponentDashboard,
				certResult.Certificate.SerialNumber.String(), certResult.Certificate.Issuer.CommonName)

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
					log.Info("Dashboard certificate needs renewal", "name", secretName, "daysUntilExpiry", certResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetDashboardRenewalThreshold()))
					// Emit event before starting renewal
					r.emitTypedCertRenewingEvent(cluster, CertEventTypeDashboard, secretName)
				}
				if !needsRenewal {
					return nil
				}
			}
		}
		if parseErr != nil {
			log.Info("Failed to parse dashboard certificate, regenerating", "error", parseErr.Error())
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "parse_error")
		}
	} else if !errors.IsNotFound(getErr) {
		return fmt.Errorf("failed to get dashboard secret: %w", getErr)
	}

	// Generate new dashboard certificate using options from CRD
	renewalStart := time.Now()
	log.Info("Generating new dashboard certificate", "name", secretName, "validity", certificates.FormatCertDuration(certOpts.GetDashboardValidity()))
	dashboardConfig := certificates.DefaultDashboardCertConfig()
	dashboardConfig.CommonName = cluster.Name + "-dashboard"
	dashboardConfig.DNSNames = certificates.GenerateDashboardSANs(cluster.Name, cluster.Namespace)
	// Apply subject fields from CRD configuration
	dashboardConfig.Country = certOpts.Country
	dashboardConfig.State = certOpts.State
	dashboardConfig.Locality = certOpts.Locality
	dashboardConfig.Organization = certOpts.Organization
	dashboardConfig.OrganizationalUnit = certOpts.OrganizationalUnit
	dashboardConfig.Validity = certOpts.GetDashboardValidity()
	dashboardConfig.KeyAlgorithm = certOpts.KeyAlgorithm
	dashboardConfig.ECDSACurve = certOpts.ECDSACurve

	certResult, err := certificates.GenerateDashboardCert(dashboardConfig, caResult)
	if err != nil {
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "failure", duration)
		metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "generation_error")
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
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "failure", duration)
		metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "controller_reference_error")
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	if !secretExists {
		if err := r.Create(ctx, secret); err != nil {
			duration := time.Since(renewalStart).Seconds()
			metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "failure", duration)
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "create_error")
			r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeDashboard, secretName, err)
			return fmt.Errorf("failed to create dashboard secret: %w", err)
		}
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "success", duration)
		r.emitTypedCertCreatedEvent(cluster, CertEventTypeDashboard, secretName)
	} else {
		secret.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, secret); err != nil {
			duration := time.Since(renewalStart).Seconds()
			metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "failure", duration)
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "update_error")
			r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeDashboard, secretName, err)
			return fmt.Errorf("failed to update dashboard secret: %w", err)
		}
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentDashboard, "success", duration)
		r.emitTypedCertRenewedEvent(cluster, CertEventTypeDashboard, secretName)
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
			// Record certificate expiry metric
			secondsUntilExpiry := time.Until(certResult.Certificate.NotAfter).Seconds()
			metrics.SetCertificateExpiry(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, constants.CertTypeFilebeat, secondsUntilExpiry)

			// Record certificate info metric
			metrics.SetCertificateInfo(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat,
				certResult.Certificate.SerialNumber.String(), certResult.Certificate.Issuer.CommonName)

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
					log.Info("Filebeat certificate needs renewal", "name", secretName, "daysUntilExpiry", certResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetFilebeatRenewalThreshold()))
					// Emit event before starting renewal
					r.emitTypedCertRenewingEvent(cluster, CertEventTypeFilebeat, secretName)
				}
				if !needsRenewal {
					return nil
				}
			}
		}
		if parseErr != nil {
			log.Info("Failed to parse filebeat certificate, regenerating", "error", parseErr.Error())
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "parse_error")
		}
	} else if !errors.IsNotFound(getErr) {
		return fmt.Errorf("failed to get filebeat secret: %w", getErr)
	}

	// Generate new filebeat certificate using options from CRD
	renewalStart := time.Now()
	log.Info("Generating new filebeat certificate", "name", secretName, "validity", certificates.FormatCertDuration(certOpts.GetFilebeatValidity()))
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
	filebeatConfig.Validity = certOpts.GetFilebeatValidity()
	filebeatConfig.KeyAlgorithm = certOpts.KeyAlgorithm
	filebeatConfig.ECDSACurve = certOpts.ECDSACurve

	certResult, err := certificates.GenerateFilebeatCert(filebeatConfig, caResult)
	if err != nil {
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "failure", duration)
		metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "generation_error")
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
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "failure", duration)
		metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "controller_reference_error")
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	if !secretExists {
		if err := r.Create(ctx, secret); err != nil {
			duration := time.Since(renewalStart).Seconds()
			metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "failure", duration)
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "create_error")
			r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeFilebeat, secretName, err)
			return fmt.Errorf("failed to create filebeat secret: %w", err)
		}
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "success", duration)
		r.emitTypedCertCreatedEvent(cluster, CertEventTypeFilebeat, secretName)
	} else {
		secret.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, secret); err != nil {
			duration := time.Since(renewalStart).Seconds()
			metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "failure", duration)
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "update_error")
			r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeFilebeat, secretName, err)
			return fmt.Errorf("failed to update filebeat secret: %w", err)
		}
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentFilebeat, "success", duration)
		r.emitTypedCertRenewedEvent(cluster, CertEventTypeFilebeat, secretName)
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
			// Record certificate expiry metric
			secondsUntilExpiry := time.Until(certResult.Certificate.NotAfter).Seconds()
			metrics.SetCertificateExpiry(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, constants.CertTypeAdmin, secondsUntilExpiry)

			// Record certificate info metric
			metrics.SetCertificateInfo(cluster.Name, cluster.Namespace, constants.CertComponentAdmin,
				certResult.Certificate.SerialNumber.String(), certResult.Certificate.Issuer.CommonName)

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
					log.Info("Admin certificate needs renewal", "name", secretName, "daysUntilExpiry", certResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetAdminRenewalThreshold()))
					// Emit event before starting renewal
					r.emitTypedCertRenewingEvent(cluster, CertEventTypeAdmin, secretName)
				}
				if !needsRenewal {
					// Migrate existing admin key to PKCS#8 to guarantee securityadmin.sh compatibility.
					convertedKey, convErr := certcommon.ConvertPrivateKeyPEMToPKCS8(found.Data[constants.SecretKeyTLSKey])
					if convErr != nil {
						log.V(1).Info("Failed to convert existing admin key to PKCS#8", "secret", secretName, "error", convErr.Error())
					} else if string(found.Data[constants.SecretKeyTLSKey]) != string(convertedKey) {
						found.Data[constants.SecretKeyTLSKey] = convertedKey
						if err := r.Update(ctx, found); err != nil {
							return fmt.Errorf("failed to migrate admin key to PKCS#8 in secret %s: %w", secretName, err)
						}
						log.Info("Migrated admin key to PKCS#8 format", "secret", secretName)
					}
					return nil
				}
			}
		}
		if parseErr != nil {
			log.Info("Failed to parse admin certificate, regenerating", "error", parseErr.Error())
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "parse_error")
		}
	} else if !errors.IsNotFound(getErr) {
		return fmt.Errorf("failed to get admin secret: %w", getErr)
	}

	// Generate new admin certificate using options from CRD
	renewalStart := time.Now()
	log.Info("Generating new admin certificate", "name", secretName, "validity", certificates.FormatCertDuration(certOpts.GetAdminValidity()))
	adminConfig := certificates.DefaultAdminCertConfig()
	// Apply subject fields from CRD configuration
	adminConfig.Country = certOpts.Country
	adminConfig.State = certOpts.State
	adminConfig.Locality = certOpts.Locality
	adminConfig.Organization = certOpts.Organization
	adminConfig.OrganizationalUnit = certOpts.OrganizationalUnit
	adminConfig.Validity = certOpts.GetAdminValidity()
	adminConfig.KeyAlgorithm = certOpts.KeyAlgorithm
	adminConfig.ECDSACurve = certOpts.ECDSACurve

	certResult, err := certificates.GenerateAdminCert(adminConfig, caResult)
	if err != nil {
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "failure", duration)
		metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "generation_error")
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
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "failure", duration)
		metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "controller_reference_error")
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	if !secretExists {
		if err := r.Create(ctx, secret); err != nil {
			duration := time.Since(renewalStart).Seconds()
			metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "failure", duration)
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "create_error")
			r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeAdmin, secretName, err)
			return fmt.Errorf("failed to create admin secret: %w", err)
		}
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "success", duration)
		r.emitTypedCertCreatedEvent(cluster, CertEventTypeAdmin, secretName)
	} else {
		secret.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, secret); err != nil {
			duration := time.Since(renewalStart).Seconds()
			metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "failure", duration)
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "update_error")
			r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeAdmin, secretName, err)
			return fmt.Errorf("failed to update admin secret: %w", err)
		}
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, constants.CertComponentAdmin, "success", duration)
		r.emitTypedCertRenewedEvent(cluster, CertEventTypeAdmin, secretName)
	}

	return nil
}

// reconcileNodeCert reconciles a node certificate
func (r *CertificateReconciler) reconcileNodeCert(ctx context.Context, cluster *wazuhv1.WazuhCluster, secretName, componentName string, sans []string, caResult *certificates.CAResult, certOpts *certificates.CertificateOptions) error {
	_, err := r.reconcileNodeCertWithRenewalStatus(ctx, cluster, secretName, componentName, sans, caResult, certOpts)
	return err
}

// reconcileNodeCertWithRenewalStatus reconciles a node certificate and returns whether it was renewed
func (r *CertificateReconciler) reconcileNodeCertWithRenewalStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster, secretName, componentName string, sans []string, caResult *certificates.CAResult, certOpts *certificates.CertificateOptions) (bool, error) {
	log := logf.FromContext(ctx)

	// Manager certs (the API served on 55000) need a 127.0.0.1 IP SAN so in-pod
	// sidecars (e.g. the Wazuh exporter) can verify TLS over the loopback.
	isManagerCert := componentName == constants.CertComponentManagerMaster ||
		componentName == constants.CertComponentManagerWorker

	// Check if secret exists
	found := &corev1.Secret{}
	getErr := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, found)
	secretExists := getErr == nil

	if secretExists {
		// Check if certificate needs renewal using options from CRD
		certResult, parseErr := certificates.ParseNodeCert(found.Data[constants.SecretKeyTLSCert], found.Data[constants.SecretKeyTLSKey])
		if parseErr == nil {
			// Record certificate expiry metric
			secondsUntilExpiry := time.Until(certResult.Certificate.NotAfter).Seconds()
			metrics.SetCertificateExpiry(cluster.Name, cluster.Namespace, componentName, constants.CertTypeNode, secondsUntilExpiry)

			// Record certificate info metric
			metrics.SetCertificateInfo(cluster.Name, cluster.Namespace, componentName,
				certResult.Certificate.SerialNumber.String(), certResult.Certificate.Issuer.CommonName)

			// Manager certs must carry the 127.0.0.1 IP SAN; older certs predate it.
			missingLoopbackIP := isManagerCert && !hasLoopbackIPSAN(certResult.Certificate.IPAddresses)

			// Check for cluster domain mismatch (e.g., after operator upgrade with new domain)
			if certificates.RequiresDomainRegeneration(certResult.Certificate, secretName, cluster.Namespace, log) {
				log.Info("Node certificate has domain mismatch, regenerating",
					"name", secretName,
					"component", componentName,
					"expectedDomain", dns.ClusterDomain())
				r.emitCertificateDomainMismatchEvent(cluster, secretName, dns.ClusterDomain())
				// Fall through to regenerate certificate
			} else if missingLoopbackIP {
				log.Info("Node certificate missing required 127.0.0.1 IP SAN, regenerating",
					"name", secretName, "component", componentName)
				// Fall through to regenerate certificate
			} else {
				// Check if certificate needs renewal due to expiry
				needsRenewal := certOpts.ShouldRenewNode(certResult)
				if needsRenewal {
					log.Info("Node certificate needs renewal", "name", secretName, "component", componentName, "daysUntilExpiry", certResult.DaysUntilExpiry(), "renewalThreshold", certificates.FormatCertDuration(certOpts.GetRenewalThreshold()))
					r.emitTypedCertRenewingEvent(cluster, CertEventTypeNode, secretName)
				}
				if !needsRenewal {
					return false, nil // Certificate is still valid, no renewal
				}
			}
		}
		if parseErr != nil {
			log.Info("Failed to parse node certificate, regenerating", "error", parseErr.Error())
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, componentName, "parse_error")
		}
	} else if !errors.IsNotFound(getErr) {
		return false, fmt.Errorf("failed to get node secret: %w", getErr)
	}

	// Generate new node certificate using options from CRD
	renewalStart := time.Now()
	log.Info("Generating new node certificate", "name", secretName, "component", componentName, "validity", certificates.FormatCertDuration(certOpts.GetNodeValidity()))
	nodeConfig := certificates.DefaultNodeCertConfig(cluster.Name + "-" + componentName)
	nodeConfig.DNSNames = sans
	// IPv4 loopback SAN so in-pod sidecars (e.g. the Wazuh exporter) can verify
	// TLS when reaching the manager API over 127.0.0.1.
	if isManagerCert {
		nodeConfig.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
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
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, componentName, "failure", duration)
		metrics.RecordCertificateError(cluster.Name, cluster.Namespace, componentName, "generation_error")
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
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, componentName, "failure", duration)
		metrics.RecordCertificateError(cluster.Name, cluster.Namespace, componentName, "controller_reference_error")
		return false, fmt.Errorf("failed to set controller reference: %w", err)
	}

	if !secretExists {
		if err := r.Create(ctx, secret); err != nil {
			duration := time.Since(renewalStart).Seconds()
			metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, componentName, "failure", duration)
			metrics.RecordCertificateError(cluster.Name, cluster.Namespace, componentName, "create_error")
			r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeNode, secretName, err)
			return false, fmt.Errorf("failed to create node secret: %w", err)
		}
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, componentName, "success", duration)
		r.emitTypedCertCreatedEvent(cluster, CertEventTypeNode, secretName)
		return false, nil // Certificate was created (not renewed)
	}

	// Secret exists, update it (this is a renewal)
	secret.SetResourceVersion(found.GetResourceVersion())
	if err := r.Update(ctx, secret); err != nil {
		duration := time.Since(renewalStart).Seconds()
		metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, componentName, "failure", duration)
		metrics.RecordCertificateError(cluster.Name, cluster.Namespace, componentName, "update_error")
		r.emitTypedCertRenewalFailedEvent(cluster, CertEventTypeNode, secretName, err)
		return false, fmt.Errorf("failed to update node secret: %w", err)
	}
	duration := time.Since(renewalStart).Seconds()
	metrics.RecordCertificateRenewal(cluster.Name, cluster.Namespace, componentName, "success", duration)
	r.emitTypedCertRenewedEvent(cluster, CertEventTypeNode, secretName)

	return true, nil // Certificate was renewed
}

// hasLoopbackIPSAN reports whether the cert IP SANs include the IPv4 loopback.
func hasLoopbackIPSAN(ips []net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			return true
		}
	}
	return false
}
