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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// customCertExpiryWarningThreshold is the threshold for emitting certificate expiry warnings
const customCertExpiryWarningThreshold = 30 * 24 * time.Hour // 30 days

// reconcileCustomCerts handles custom (BYO) certificate reconciliation.
// It reads user-provided secrets and copies them into the operator's internal
// secret format expected by the builders.
func (r *CertificateReconciler) reconcileCustomCerts(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*CertHashResult, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling custom certificates (BYO certs mode)")

	customCerts := cluster.Spec.TLS.CustomCerts

	// Read CA certificate - required
	caData, err := r.readSecretFromRef(ctx, cluster.Namespace, customCerts.CASecretRef)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA secret: %w", err)
	}

	// Warn if CA cert is expiring soon
	if certPEM, ok := caData[customCerts.CASecretRef.Key]; ok {
		r.warnIfCertExpiringSoon(ctx, cluster, certPEM, "CA")
	}

	// Build CA secret data in operator format
	caSecretData := map[string][]byte{
		constants.SecretKeyCACert: caData[customCerts.CASecretRef.Key],
	}

	// Create/update CA secret
	caSecretName := cluster.Name + "-ca"
	if err := r.ensureCustomCertSecret(ctx, cluster, caSecretName, caSecretData); err != nil {
		return nil, fmt.Errorf("failed to ensure CA secret: %w", err)
	}

	// Read and copy node certificates (indexer, manager, dashboard)
	if customCerts.NodeSecretRef != nil {
		nodeData, err := r.readSecretFromRef(ctx, cluster.Namespace, customCerts.NodeSecretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to read node certificate secret: %w", err)
		}

		// The node secret should contain all node certificates
		// Copy to each component's cert secret with CA included
		if err := r.copyNodeCertsToComponents(ctx, cluster, nodeData, customCerts.NodeSecretRef.Key, caData[customCerts.CASecretRef.Key]); err != nil {
			return nil, fmt.Errorf("failed to copy node certificates: %w", err)
		}
	}

	// Read and copy admin certificates
	if customCerts.AdminSecretRef != nil {
		adminData, err := r.readSecretFromRef(ctx, cluster.Namespace, customCerts.AdminSecretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to read admin certificate secret: %w", err)
		}

		adminSecretData := map[string][]byte{
			constants.SecretKeyRootCA: caData[customCerts.CASecretRef.Key],
		}
		// Copy all keys from the user secret
		for k, v := range adminData {
			adminSecretData[k] = v
		}

		if err := r.ensureCustomCertSecret(ctx, cluster, constants.AdminCertsName(cluster.Name), adminSecretData); err != nil {
			return nil, fmt.Errorf("failed to ensure admin certs secret: %w", err)
		}

		// Warn if admin cert is expiring
		if certPEM, ok := adminData[customCerts.AdminSecretRef.Key]; ok {
			r.warnIfCertExpiringSoon(ctx, cluster, certPEM, "admin")
		}
	}

	// Read and copy filebeat certificates
	if customCerts.FilebeatSecretRef != nil {
		filebeatData, err := r.readSecretFromRef(ctx, cluster.Namespace, customCerts.FilebeatSecretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to read filebeat certificate secret: %w", err)
		}

		filebeatSecretData := map[string][]byte{
			constants.SecretKeyRootCA: caData[customCerts.CASecretRef.Key],
		}
		for k, v := range filebeatData {
			filebeatSecretData[k] = v
		}

		if err := r.ensureCustomCertSecret(ctx, cluster, constants.FilebeatCertsName(cluster.Name), filebeatSecretData); err != nil {
			return nil, fmt.Errorf("failed to ensure filebeat certs secret: %w", err)
		}

		if certPEM, ok := filebeatData[customCerts.FilebeatSecretRef.Key]; ok {
			r.warnIfCertExpiringSoon(ctx, cluster, certPEM, "filebeat")
		}
	}

	// Collect hashes from the resulting secrets
	result, err := r.collectCertHashes(ctx, cluster)
	if err != nil {
		log.Error(err, "Failed to collect certificate hashes for custom certs")
	}

	log.Info("Custom certificate reconciliation completed")
	return result, nil
}

// copyNodeCertsToComponents copies node certificate data to all component cert secrets.
// The user provides a single node cert secret; the operator replicates it to
// indexer, manager-master, manager-worker, and dashboard cert secrets.
func (r *CertificateReconciler) copyNodeCertsToComponents(ctx context.Context, cluster *wazuhv1.WazuhCluster, nodeData map[string][]byte, certKey string, caCert []byte) error {
	// Warn if node cert is expiring
	if certPEM, ok := nodeData[certKey]; ok {
		r.warnIfCertExpiringSoon(ctx, cluster, certPEM, "node")
	}

	// Build base secret data with CA
	baseData := map[string][]byte{
		constants.SecretKeyRootCA: caCert,
	}
	// Copy all keys from the user secret
	for k, v := range nodeData {
		baseData[k] = v
	}

	// Component cert secrets to populate
	componentSecrets := []string{
		constants.IndexerCertsName(cluster.Name),
		constants.ManagerMasterCertsName(cluster.Name),
		constants.ManagerWorkerCertsName(cluster.Name),
		constants.DashboardCertsName(cluster.Name),
	}

	for _, secretName := range componentSecrets {
		// Make a copy of baseData for each secret
		secretData := make(map[string][]byte, len(baseData))
		for k, v := range baseData {
			secretData[k] = v
		}

		if err := r.ensureCustomCertSecret(ctx, cluster, secretName, secretData); err != nil {
			return fmt.Errorf("failed to ensure secret %s: %w", secretName, err)
		}
	}

	return nil
}

// readSecretFromRef reads a Kubernetes Secret referenced by a SecretKeySelector.
// Returns the full secret data map.
func (r *CertificateReconciler) readSecretFromRef(ctx context.Context, namespace string, ref *corev1.SecretKeySelector) (map[string][]byte, error) {
	if ref == nil {
		return nil, fmt.Errorf("secret reference is nil")
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      ref.Name,
		Namespace: namespace,
	}, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("secret %s not found in namespace %s", ref.Name, namespace)
		}
		return nil, fmt.Errorf("failed to get secret %s: %w", ref.Name, err)
	}

	// Verify the referenced key exists
	if ref.Key != "" {
		if _, ok := secret.Data[ref.Key]; !ok {
			return nil, fmt.Errorf("key %q not found in secret %s", ref.Key, ref.Name)
		}
	}

	return secret.Data, nil
}

// warnIfCertExpiringSoon parses a PEM-encoded certificate and emits a warning
// event if it expires within the warning threshold.
func (r *CertificateReconciler) warnIfCertExpiringSoon(ctx context.Context, cluster *wazuhv1.WazuhCluster, certPEM []byte, componentName string) {
	log := logf.FromContext(ctx)

	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.V(1).Info("Failed to decode PEM block for expiry check", "component", componentName)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.V(1).Info("Failed to parse certificate for expiry check", "component", componentName, "error", err)
		return
	}

	timeUntilExpiry := time.Until(cert.NotAfter)
	if timeUntilExpiry < customCertExpiryWarningThreshold {
		days := int(timeUntilExpiry.Hours() / 24)
		msg := fmt.Sprintf("Custom %s certificate expires in %d days (NotAfter: %s). Consider rotating your certificates.",
			componentName, days, cert.NotAfter.Format(time.RFC3339))

		if r.EventRecorder != nil {
			r.EventRecorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonCertificateExpiring, msg)
		}
		log.Info("Custom certificate expiring soon", "component", componentName, "expiresIn", timeUntilExpiry.String(), "notAfter", cert.NotAfter)
	}
}

// ensureCustomCertSecret creates or updates an operator-managed secret with custom certificate data.
func (r *CertificateReconciler) ensureCustomCertSecret(ctx context.Context, cluster *wazuhv1.WazuhCluster, secretName string, data map[string][]byte) error {
	log := logf.FromContext(ctx)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: cluster.Namespace,
			Labels:    constants.CommonLabels(cluster.Name, "certificates", cluster.Spec.Version),
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}

	// Set owner reference
	if err := controllerutil.SetControllerReference(cluster, secret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Check if secret exists
	existing := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, existing)
	if errors.IsNotFound(err) {
		log.Info("Creating custom cert secret", "secret", secretName)
		return r.Create(ctx, secret)
	}
	if err != nil {
		return fmt.Errorf("failed to get existing secret %s: %w", secretName, err)
	}

	// Skip update if data and labels haven't changed
	if byteMapEqual(existing.Data, data) && stringMapEqual(existing.Labels, secret.Labels) {
		return nil
	}

	// Update existing secret data
	existing.Data = data
	existing.Labels = secret.Labels
	log.V(1).Info("Updating custom cert secret", "secret", secretName)
	return r.Update(ctx, existing)
}
