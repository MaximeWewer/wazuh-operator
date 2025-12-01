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

package security

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// OpenSearchClientFactory creates OpenSearch clients from cluster references
type OpenSearchClientFactory struct {
	k8sClient client.Client
}

// NewOpenSearchClientFactory creates a new OpenSearchClientFactory
func NewOpenSearchClientFactory(k8sClient client.Client) *OpenSearchClientFactory {
	return &OpenSearchClientFactory{
		k8sClient: k8sClient,
	}
}

// GetClient returns an authenticated OpenSearch client for a cluster by reference
func (f *OpenSearchClientFactory) GetClient(ctx context.Context, clusterRef types.NamespacedName) (*api.Client, error) {
	// Get the WazuhCluster
	var cluster wazuhv1alpha1.WazuhCluster
	if err := f.k8sClient.Get(ctx, clusterRef, &cluster); err != nil {
		return nil, fmt.Errorf("failed to get WazuhCluster %s: %w", clusterRef, err)
	}

	return f.GetClientForCluster(ctx, &cluster)
}

// GetClientForCluster returns an authenticated OpenSearch client using cluster object directly
func (f *OpenSearchClientFactory) GetClientForCluster(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*api.Client, error) {
	// Get credentials from secret
	username, password, err := f.getCredentials(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	// Get CA certificate from secret
	caCert, err := f.getCACertificate(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Build the service URL
	baseURL := f.buildServiceURL(cluster)

	// Create the client
	config := api.ClientConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		CACert:   caCert,
		Insecure: false, // Always verify TLS in production
	}

	return api.NewClient(config)
}

// getCredentials retrieves admin credentials from the indexer-credentials secret
func (f *OpenSearchClientFactory) getCredentials(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (username, password string, err error) {
	secretName := fmt.Sprintf("%s-indexer-credentials", cluster.Name)
	secretKey := types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}

	var secret corev1.Secret
	if err := f.k8sClient.Get(ctx, secretKey, &secret); err != nil {
		return "", "", fmt.Errorf("failed to get credentials secret %s: %w", secretName, err)
	}

	usernameBytes, ok := secret.Data[constants.SecretKeyAdminUsername]
	if !ok {
		return "", "", fmt.Errorf("%s not found in secret %s", constants.SecretKeyAdminUsername, secretName)
	}

	passwordBytes, ok := secret.Data[constants.SecretKeyAdminPassword]
	if !ok {
		return "", "", fmt.Errorf("%s not found in secret %s", constants.SecretKeyAdminPassword, secretName)
	}

	return string(usernameBytes), string(passwordBytes), nil
}

// getCACertificate retrieves the CA certificate from the indexer-certs secret
func (f *OpenSearchClientFactory) getCACertificate(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) ([]byte, error) {
	secretName := fmt.Sprintf("%s-indexer-certs", cluster.Name)
	secretKey := types.NamespacedName{
		Name:      secretName,
		Namespace: cluster.Namespace,
	}

	var secret corev1.Secret
	if err := f.k8sClient.Get(ctx, secretKey, &secret); err != nil {
		return nil, fmt.Errorf("failed to get certs secret %s: %w", secretName, err)
	}

	caCert, ok := secret.Data[constants.SecretKeyCACert]
	if !ok {
		return nil, fmt.Errorf("ca.crt not found in secret %s", secretName)
	}

	return caCert, nil
}

// buildServiceURL builds the internal service URL for the indexer
func (f *OpenSearchClientFactory) buildServiceURL(cluster *wazuhv1alpha1.WazuhCluster) string {
	// Format: https://{cluster-name}-indexer.{namespace}.svc.cluster.local:9200
	return fmt.Sprintf("https://%s-indexer.%s.svc.cluster.local:%d",
		cluster.Name,
		cluster.Namespace,
		constants.PortIndexerREST,
	)
}

// GetClientWithCustomCredentials creates a client with specific credentials (for testing specific users)
func (f *OpenSearchClientFactory) GetClientWithCustomCredentials(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, username, password string) (*api.Client, error) {
	// Get CA certificate from secret
	caCert, err := f.getCACertificate(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Build the service URL
	baseURL := f.buildServiceURL(cluster)

	// Create the client
	config := api.ClientConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		CACert:   caCert,
		Insecure: false,
	}

	return api.NewClient(config)
}
