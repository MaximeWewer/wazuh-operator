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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

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
	// CARenewalPending indicates CA needs renewal but is waiting for maintenance window
	CARenewalPending bool
	// CARenewalScheduledAt is when the next maintenance window starts (if CARenewalPending)
	CARenewalScheduledAt time.Time
	// IndexerCertsRenewed indicates if indexer node certificates were renewed
	// When true and CARenewed is false, hot reload API can be used instead of restart
	IndexerCertsRenewed bool
	// HotReloadTriggered indicates if hot reload API was successfully called
	// When true, the indexer does not need to be restarted for node cert renewal
	HotReloadTriggered bool
	// HotReloadError contains any error from the hot reload attempt
	HotReloadError error
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
