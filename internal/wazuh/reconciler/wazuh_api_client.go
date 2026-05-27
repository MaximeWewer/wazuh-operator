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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

// buildWazuhAPIClient builds a Wazuh Manager API client for the given cluster.
// Shared by the RBAC reconcilers; mirrors AgentGroupReconciler.buildAPIClient.
func buildWazuhAPIClient(ctx context.Context, c client.Client, cluster *wazuhv1.WazuhCluster) (*adapters.WazuhAPIAdapter, error) {
	masterServiceName := cluster.Name + "-manager-master"
	baseURL := fmt.Sprintf("https://%s:%d",
		dns.ServiceFQDN(masterServiceName, cluster.Namespace), constants.PortManagerAPI)

	username, password, err := getWazuhAPICredentials(ctx, c, cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to get Wazuh API credentials: %w", err)
	}

	return adapters.NewWazuhAPIAdapter(adapters.WazuhAPIConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		Insecure: true,
	}), nil
}

// getWazuhAPICredentials resolves the Wazuh API credentials for the cluster,
// preferring an explicit Manager.APICredentials secret and falling back to the
// operator-managed default API credentials secret.
func getWazuhAPICredentials(ctx context.Context, c client.Client, cluster *wazuhv1.WazuhCluster) (string, string, error) {
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.APICredentials != nil {
		secretName := cluster.Spec.Manager.APICredentials.GetSecretName()
		if secretName != "" {
			secret := &corev1.Secret{}
			if err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
				return "", "", fmt.Errorf("failed to get API credentials secret: %w", err)
			}
			usernameKey := cluster.Spec.Manager.APICredentials.UsernameKey
			if usernameKey == "" {
				usernameKey = "username"
			}
			passwordKey := cluster.Spec.Manager.APICredentials.PasswordKey
			if passwordKey == "" {
				passwordKey = "password"
			}
			return string(secret.Data[usernameKey]), string(secret.Data[passwordKey]), nil
		}
	}

	defaultSecretName := constants.APICredentialsName(cluster.Name)
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: defaultSecretName, Namespace: cluster.Namespace}, secret); err != nil {
		if errors.IsNotFound(err) {
			return constants.DefaultWazuhAPIUsername, "wazuh", nil
		}
		return "", "", fmt.Errorf("failed to get default API credentials secret: %w", err)
	}

	return string(secret.Data[constants.SecretKeyAPIUsername]), string(secret.Data[constants.SecretKeyAPIPassword]), nil
}
