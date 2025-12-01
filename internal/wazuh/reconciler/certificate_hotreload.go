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

package reconciler

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// HotReloadResult contains the result of a hot reload operation
type HotReloadResult struct {
	// Supported indicates if hot reload is supported for this version
	Supported bool
	// RequiresAPICall indicates if API call is needed (OpenSearch 2.13-2.18)
	RequiresAPICall bool
	// APICallMade indicates if an API call was made
	APICallMade bool
	// Error contains any error that occurred
	Error error
}

// ShouldTriggerHotReload determines if hot reload should be triggered based on cluster config
func (r *CertificateReconciler) ShouldTriggerHotReload(cluster *wazuhv1alpha1.WazuhCluster) bool {
	// Check if TLS is enabled
	if cluster.Spec.TLS == nil {
		return false
	}
	if cluster.Spec.TLS.Enabled != nil && !*cluster.Spec.TLS.Enabled {
		return false
	}

	// Check if hot reload is configured
	if cluster.Spec.TLS.HotReload == nil {
		// Default: hot reload is enabled
		return true
	}

	return cluster.Spec.TLS.HotReload.Enabled
}

// ShouldForceAPIReload determines if API reload should be forced
func (r *CertificateReconciler) ShouldForceAPIReload(cluster *wazuhv1alpha1.WazuhCluster) bool {
	if cluster.Spec.TLS == nil || cluster.Spec.TLS.HotReload == nil {
		return false
	}
	return cluster.Spec.TLS.HotReload.ForceAPIReload
}

// TriggerCertificateHotReload triggers the appropriate hot reload mechanism based on version
// For OpenSearch 2.13-2.18.x: Calls the reload certificates API
// For OpenSearch 2.19+: Hot reload happens automatically via file watching
func (r *CertificateReconciler) TriggerCertificateHotReload(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) *HotReloadResult {
	log := logf.FromContext(ctx)
	result := &HotReloadResult{}

	// Check if hot reload is enabled
	if !r.ShouldTriggerHotReload(cluster) {
		log.V(1).Info("Hot reload is disabled for this cluster")
		result.Supported = false
		return result
	}

	// Get hot reload support level for this Wazuh version
	support, err := utils.GetHotReloadSupportForWazuh(cluster.Spec.Version)
	if err != nil {
		log.Error(err, "Failed to determine hot reload support for version", "version", cluster.Spec.Version)
		result.Error = err
		return result
	}

	switch support {
	case utils.HotReloadNotSupported:
		log.Info("Hot reload not supported for this Wazuh version",
			"version", cluster.Spec.Version,
			"minRequired", utils.MinWazuhVersionForHotReload.String())
		result.Supported = false
		return result

	case utils.HotReloadAutomatic:
		result.Supported = true
		result.RequiresAPICall = false
		// Check if force API reload is configured
		if r.ShouldForceAPIReload(cluster) {
			log.Info("Hot reload is automatic but forceAPIReload is enabled, calling API",
				"version", cluster.Spec.Version)
			result.RequiresAPICall = true
			result.Error = r.callReloadCertificatesAPI(ctx, cluster)
			result.APICallMade = true
		} else {
			log.Info("Hot reload is automatic for this version, no API call needed",
				"version", cluster.Spec.Version)
		}
		return result

	case utils.HotReloadWithAPICall:
		result.Supported = true
		result.RequiresAPICall = true
		log.Info("Hot reload requires API call for this version",
			"version", cluster.Spec.Version)
		result.Error = r.callReloadCertificatesAPI(ctx, cluster)
		result.APICallMade = true
		return result

	default:
		result.Error = fmt.Errorf("unknown hot reload support level: %d", support)
		return result
	}
}

// callReloadCertificatesAPI calls the OpenSearch API to reload certificates
// The certificate reload API requires admin certificate authentication (mTLS),
// not username/password authentication
func (r *CertificateReconciler) callReloadCertificatesAPI(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get CA certificate for TLS verification
	caCert, err := r.getCACertificate(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Get admin certificate for mTLS authentication
	// The reload API requires admin cert, not username/password
	adminCert, adminKey, err := r.getAdminCertificate(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to get admin certificate: %w", err)
	}

	// Build indexer URL
	indexerURL := fmt.Sprintf("https://%s-indexer.%s.svc:%d",
		cluster.Name, cluster.Namespace, constants.PortIndexerREST)

	// Create OpenSearch client with mTLS authentication
	client, err := api.NewClient(api.ClientConfig{
		BaseURL:    indexerURL,
		CACert:     caCert,
		ClientCert: adminCert,
		ClientKey:  adminKey,
		Insecure:   false, // Use CA cert for verification
	})
	if err != nil {
		return fmt.Errorf("failed to create OpenSearch client: %w", err)
	}

	// Call reload certificates API
	log.Info("Calling OpenSearch API to reload certificates", "url", indexerURL)
	if err := client.ReloadAllCertificates(ctx); err != nil {
		return fmt.Errorf("API call to reload certificates failed: %w", err)
	}

	log.Info("Successfully reloaded certificates via API")
	return nil
}

// AdminCredentials holds admin username and password
type AdminCredentials struct {
	Username string
	Password string
}

// getAdminCredentials retrieves admin credentials from the indexer credentials secret
func (r *CertificateReconciler) getAdminCredentials(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*AdminCredentials, error) {
	secretName := cluster.Name + "-indexer-credentials"
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials secret %s: %w", secretName, err)
	}

	username := string(secret.Data[constants.SecretKeyAdminUsername])
	password := string(secret.Data[constants.SecretKeyAdminPassword])

	if username == "" {
		username = constants.DefaultOpenSearchAdminUsername
	}
	if password == "" {
		return nil, fmt.Errorf("admin password not found in secret %s", secretName)
	}

	return &AdminCredentials{
		Username: username,
		Password: password,
	}, nil
}

// getCACertificate retrieves the CA certificate for TLS verification
func (r *CertificateReconciler) getCACertificate(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) ([]byte, error) {
	secretName := cluster.Name + "-ca"
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA secret %s: %w", secretName, err)
	}

	caCert, ok := secret.Data[constants.SecretKeyCACert]
	if !ok {
		return nil, fmt.Errorf("ca.crt not found in secret %s", secretName)
	}

	return caCert, nil
}

// getAdminCertificate retrieves the admin certificate and key for mTLS authentication
// Required for OpenSearch security API calls like certificate reload
func (r *CertificateReconciler) getAdminCertificate(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (cert []byte, key []byte, err error) {
	secretName := cluster.Name + "-admin-certs"
	secret := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}, secret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get admin cert secret %s: %w", secretName, err)
	}

	cert, ok := secret.Data[constants.SecretKeyTLSCert]
	if !ok {
		return nil, nil, fmt.Errorf("tls.crt not found in secret %s", secretName)
	}

	key, ok = secret.Data[constants.SecretKeyTLSKey]
	if !ok {
		return nil, nil, fmt.Errorf("tls.key not found in secret %s", secretName)
	}

	return cert, key, nil
}

// GetHotReloadConfigString returns the OpenSearch configuration string for hot reload
// This should be added to opensearch.yml when hot reload is enabled
func GetHotReloadConfigString(cluster *wazuhv1alpha1.WazuhCluster) string {
	// Check if hot reload is enabled
	if cluster.Spec.TLS == nil {
		return ""
	}
	if cluster.Spec.TLS.Enabled != nil && !*cluster.Spec.TLS.Enabled {
		return ""
	}
	if cluster.Spec.TLS.HotReload != nil && !cluster.Spec.TLS.HotReload.Enabled {
		return ""
	}

	// Check version support
	if !utils.SupportsHotReload(cluster.Spec.Version) {
		return ""
	}

	// Return the hot reload configuration
	// This enables the security plugin to reload certificates without restart
	return "plugins.security.ssl_cert_reload_enabled: true"
}

// IsHotReloadEnabled returns true if hot reload is enabled for the cluster
func IsHotReloadEnabled(cluster *wazuhv1alpha1.WazuhCluster) bool {
	if cluster.Spec.TLS == nil {
		return false
	}
	if cluster.Spec.TLS.Enabled != nil && !*cluster.Spec.TLS.Enabled {
		return false
	}
	if cluster.Spec.TLS.HotReload == nil {
		// Default: enabled if TLS is enabled
		return true
	}
	return cluster.Spec.TLS.HotReload.Enabled
}
