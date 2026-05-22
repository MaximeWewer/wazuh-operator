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

package v1

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var opensearchauthconfiglog = logf.Log.WithName("opensearchauthconfig-webhook")

// SetupOpenSearchAuthConfigWebhookWithManager registers the webhook for OpenSearchAuthConfig in the manager.
func SetupOpenSearchAuthConfigWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &OpenSearchAuthConfig{}).
		WithValidator(&OpenSearchAuthConfigCustomValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-resources-wazuh-com-v1-opensearchauthconfig,mutating=false,failurePolicy=fail,sideEffects=None,groups=resources.wazuh.com,resources=opensearchauthconfigs,verbs=create;update,versions=v1,name=vopensearchauthconfig.kb.io,admissionReviewVersions=v1

// OpenSearchAuthConfigCustomValidator handles validation for OpenSearchAuthConfig
type OpenSearchAuthConfigCustomValidator struct{}

var _ admission.Validator[*OpenSearchAuthConfig] = &OpenSearchAuthConfigCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *OpenSearchAuthConfigCustomValidator) ValidateCreate(_ context.Context, authConfig *OpenSearchAuthConfig) (admission.Warnings, error) {
	opensearchauthconfiglog.Info("validate create", "name", authConfig.Name, "namespace", authConfig.Namespace)
	return v.validateOpenSearchAuthConfig(authConfig)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *OpenSearchAuthConfigCustomValidator) ValidateUpdate(_ context.Context, _, newAuthConfig *OpenSearchAuthConfig) (admission.Warnings, error) {
	opensearchauthconfiglog.Info("validate update", "name", newAuthConfig.Name, "namespace", newAuthConfig.Namespace)
	return v.validateOpenSearchAuthConfig(newAuthConfig)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *OpenSearchAuthConfigCustomValidator) ValidateDelete(_ context.Context, authConfig *OpenSearchAuthConfig) (admission.Warnings, error) {
	opensearchauthconfiglog.Info("validate delete", "name", authConfig.Name, "namespace", authConfig.Namespace)
	return nil, nil
}

// validateOpenSearchAuthConfig validates the OpenSearchAuthConfig spec
func (v *OpenSearchAuthConfigCustomValidator) validateOpenSearchAuthConfig(authConfig *OpenSearchAuthConfig) (admission.Warnings, error) {
	var allErrors []string
	var warnings admission.Warnings

	spec := &authConfig.Spec

	// Rule 1: At least one auth method must be enabled
	if !v.hasEnabledAuthMethod(spec) {
		allErrors = append(allErrors, "spec: at least one authentication method must be enabled (basicAuth, oidc, saml, ldap, or jwt)")
	}

	// Rule 2: OIDC enabled → connectURL and clientId required
	if spec.OIDC != nil && spec.OIDC.Enabled {
		if spec.OIDC.ConnectURL == "" {
			allErrors = append(allErrors, "spec.oidc.connectURL: is required when OIDC is enabled")
		}
		if spec.OIDC.ClientID == "" {
			allErrors = append(allErrors, "spec.oidc.clientId: is required when OIDC is enabled")
		}
	}

	// Rule 3: SAML enabled → idpEntityId, spEntityId, kibanaUrl required + idpMetadataUrl or idpMetadataFile
	if spec.SAML != nil && spec.SAML.Enabled {
		if spec.SAML.IdpEntityID == "" {
			allErrors = append(allErrors, "spec.saml.idpEntityId: is required when SAML is enabled")
		}
		if spec.SAML.SpEntityID == "" {
			allErrors = append(allErrors, "spec.saml.spEntityId: is required when SAML is enabled")
		}
		if spec.SAML.KibanaURL == "" {
			allErrors = append(allErrors, "spec.saml.kibanaUrl: is required when SAML is enabled")
		}
		if spec.SAML.IdpMetadataURL == "" && spec.SAML.IdpMetadataFile == "" {
			allErrors = append(allErrors, "spec.saml: either idpMetadataUrl or idpMetadataFile must be specified when SAML is enabled")
		}
	}

	// Rule 4: LDAP enabled → hosts non-empty + authentication.userBase required
	if spec.LDAP != nil && spec.LDAP.Enabled {
		if len(spec.LDAP.Hosts) == 0 {
			allErrors = append(allErrors, "spec.ldap.hosts: must not be empty when LDAP is enabled")
		}
		if spec.LDAP.Authentication.UserBase == "" {
			allErrors = append(allErrors, "spec.ldap.authentication.userBase: is required when LDAP is enabled")
		}
	}

	// Rule 5: JWT enabled → exactly one verification source (signingKeyRef or jwksUrl)
	if spec.JWT != nil && spec.JWT.Enabled {
		hasKey := spec.JWT.SigningKeyRef != nil
		hasJWKS := spec.JWT.JwksURL != ""
		if !hasKey && !hasJWKS {
			allErrors = append(allErrors, "spec.jwt: either signingKeyRef or jwksUrl is required when JWT is enabled")
		}
		if hasKey && hasJWKS {
			allErrors = append(allErrors, "spec.jwt: signingKeyRef and jwksUrl are mutually exclusive")
		}
	}

	// Rule 6: Warning if more than one auth domain has challenge=true
	challengeCount := v.countChallengeDomains(spec)
	if challengeCount > 1 {
		warnings = append(warnings, fmt.Sprintf("%d authentication domains have challenge=true; only one should issue challenges to avoid conflicts", challengeCount))
	}

	if len(allErrors) > 0 {
		return warnings, fmt.Errorf("validation failed: %v", allErrors)
	}

	return warnings, nil
}

// hasEnabledAuthMethod checks if at least one auth method is enabled
func (v *OpenSearchAuthConfigCustomValidator) hasEnabledAuthMethod(spec *OpenSearchAuthConfigSpec) bool {
	if spec.BasicAuth != nil && spec.BasicAuth.Enabled {
		return true
	}
	if spec.OIDC != nil && spec.OIDC.Enabled {
		return true
	}
	if spec.SAML != nil && spec.SAML.Enabled {
		return true
	}
	if spec.LDAP != nil && spec.LDAP.Enabled {
		return true
	}
	if spec.JWT != nil && spec.JWT.Enabled {
		return true
	}
	return false
}

// countChallengeDomains counts how many auth domains have challenge=true
func (v *OpenSearchAuthConfigCustomValidator) countChallengeDomains(spec *OpenSearchAuthConfigSpec) int {
	count := 0
	if spec.BasicAuth != nil && spec.BasicAuth.Enabled && spec.BasicAuth.Challenge {
		count++
	}
	if spec.OIDC != nil && spec.OIDC.Enabled && spec.OIDC.Challenge {
		count++
	}
	if spec.SAML != nil && spec.SAML.Enabled && spec.SAML.Challenge {
		count++
	}
	if spec.LDAP != nil && spec.LDAP.Enabled && spec.LDAP.Challenge {
		count++
	}
	if spec.JWT != nil && spec.JWT.Enabled && spec.JWT.Challenge {
		count++
	}
	return count
}
