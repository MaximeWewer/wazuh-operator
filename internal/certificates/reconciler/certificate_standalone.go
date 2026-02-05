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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

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
