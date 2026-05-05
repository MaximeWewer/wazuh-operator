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

package config

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// Secret map keys used across dashboard and indexer auth builders.
const (
	AuthSecretKeyOIDCClientSecret    = "oidc_client_secret"
	AuthSecretKeyOIDCCookiePassword  = "oidc_cookie_password"
	AuthSecretKeySAMLExchangeKey     = "saml_exchange_key"
	AuthSecretKeyLDAPBindPassword    = "ldap_bind_password"
)

// ResolveAuthSecrets resolves all secret references declared by an OpenSearchAuthConfig
// into plaintext values keyed by the constants above. Secrets are looked up in the
// OpenSearchAuthConfig's own namespace.
func ResolveAuthSecrets(ctx context.Context, cli client.Client, authConfig *wazuhv1.OpenSearchAuthConfig) (map[string]string, error) {
	secrets := make(map[string]string)
	if authConfig == nil {
		return secrets, nil
	}
	ns := authConfig.Namespace

	if authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.ClientSecretRef != nil {
		v, err := getSecretValue(ctx, cli, ns, authConfig.Spec.OIDC.ClientSecretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve OIDC client secret: %w", err)
		}
		secrets[AuthSecretKeyOIDCClientSecret] = v
	}

	if authConfig.Spec.OIDC != nil && authConfig.Spec.OIDC.Dashboard != nil &&
		authConfig.Spec.OIDC.Dashboard.CookiePasswordRef != nil {
		v, err := getSecretValue(ctx, cli, ns, authConfig.Spec.OIDC.Dashboard.CookiePasswordRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve OIDC cookie password: %w", err)
		}
		secrets[AuthSecretKeyOIDCCookiePassword] = v
	}

	if authConfig.Spec.SAML != nil && authConfig.Spec.SAML.ExchangeKeyRef != nil {
		v, err := getSecretValue(ctx, cli, ns, authConfig.Spec.SAML.ExchangeKeyRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve SAML exchange key: %w", err)
		}
		secrets[AuthSecretKeySAMLExchangeKey] = v
	}

	if authConfig.Spec.LDAP != nil && authConfig.Spec.LDAP.Authentication.BindPasswordRef != nil {
		v, err := getSecretValue(ctx, cli, ns, authConfig.Spec.LDAP.Authentication.BindPasswordRef)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve LDAP bind password: %w", err)
		}
		secrets[AuthSecretKeyLDAPBindPassword] = v
	}

	return secrets, nil
}

// FindAuthConfigForCluster returns the first OpenSearchAuthConfig (across all
// namespaces) whose spec.clusterRefs targets the given cluster. Returns (nil, nil)
// when none is found so callers can fall back to defaults.
func FindAuthConfigForCluster(ctx context.Context, cli client.Client, clusterName, clusterNamespace string) (*wazuhv1.OpenSearchAuthConfig, error) {
	list := &wazuhv1.OpenSearchAuthConfigList{}
	if err := cli.List(ctx, list); err != nil {
		return nil, fmt.Errorf("failed to list OpenSearchAuthConfigs: %w", err)
	}
	for i := range list.Items {
		ac := &list.Items[i]
		for _, ref := range ac.Spec.ClusterRefs {
			if ref.Name == clusterName && ref.Namespace == clusterNamespace {
				return ac, nil
			}
		}
	}
	return nil, nil
}

func getSecretValue(ctx context.Context, cli client.Client, namespace string, ref *wazuhv1.SecretKeyRef) (string, error) {
	secret := &corev1.Secret{}
	if err := cli.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, secret); err != nil {
		return "", err
	}
	key := ref.Key
	if key == "" {
		key = "password"
	}
	v, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", key, ref.Name)
	}
	return string(v), nil
}
