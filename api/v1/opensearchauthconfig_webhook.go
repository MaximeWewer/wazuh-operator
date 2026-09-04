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
	var warnings admission.Warnings

	spec := &authConfig.Spec

	var allErrors []string
	// Rule 1: At least one auth method must be enabled
	if !v.hasEnabledAuthMethod(spec) {
		allErrors = append(allErrors, "spec: at least one authentication method must be enabled (basicAuth, oidc, saml, ldap, jwt, proxy, or kerberos)")
	}
	// Rules 2-7: per-backend requirements, each independent of the others.
	allErrors = append(allErrors, validateOIDCSpec(spec.OIDC)...)
	allErrors = append(allErrors, validateSAMLSpec(spec.SAML)...)
	allErrors = append(allErrors, validateLDAPSpec(spec.LDAP)...)
	allErrors = append(allErrors, validateJWTSpec(spec.JWT)...)
	allErrors = append(allErrors, validateProxySpec(spec.Proxy)...)
	allErrors = append(allErrors, validateKerberosSpec(spec.Kerberos)...)

	// Rule 8: Warning if more than one auth domain has challenge=true
	if challengeCount := v.countChallengeDomains(spec); challengeCount > 1 {
		warnings = append(warnings, fmt.Sprintf("%d authentication domains have challenge=true; only one should issue challenges to avoid conflicts", challengeCount))
	}

	if len(allErrors) > 0 {
		return warnings, fmt.Errorf("validation failed: %v", allErrors)
	}

	return warnings, nil
}

// validateOIDCSpec checks the OIDC backend: connectURL and clientId are required,
// and a trusted CA bundle is only honored when SSL is enabled.
func validateOIDCSpec(spec *OIDCAuthSpec) []string {
	if spec == nil || !spec.Enabled {
		return nil
	}
	var errs []string
	if spec.ConnectURL == "" {
		errs = append(errs, "spec.oidc.connectURL: is required when OIDC is enabled")
	}
	if spec.ClientID == "" {
		errs = append(errs, "spec.oidc.clientId: is required when OIDC is enabled")
	}
	if spec.IdpTLS != nil && spec.IdpTLS.TrustedCAsSecretRef != nil && !spec.IdpTLS.EnableSSL {
		errs = append(errs, "spec.oidc.idpTLS.trustedCAsSecretRef: requires enableSSL: true")
	}
	return errs
}

// validateSAMLSpec checks the SAML backend: entity IDs, the dashboard URL and a
// metadata source are required, and a trusted CA bundle needs SSL enabled.
func validateSAMLSpec(spec *SAMLAuthSpec) []string {
	if spec == nil || !spec.Enabled {
		return nil
	}
	var errs []string
	if spec.IdpEntityID == "" {
		errs = append(errs, "spec.saml.idpEntityId: is required when SAML is enabled")
	}
	if spec.SpEntityID == "" {
		errs = append(errs, "spec.saml.spEntityId: is required when SAML is enabled")
	}
	if spec.KibanaURL == "" {
		errs = append(errs, "spec.saml.kibanaUrl: is required when SAML is enabled")
	}
	if spec.IdpMetadataURL == "" && spec.IdpMetadataFile == "" {
		errs = append(errs, "spec.saml: either idpMetadataUrl or idpMetadataFile must be specified when SAML is enabled")
	}
	if spec.IdpTLS != nil && spec.IdpTLS.TrustedCAsSecretRef != nil && !spec.IdpTLS.EnableSSL {
		errs = append(errs, "spec.saml.idpTLS.trustedCAsSecretRef: requires enableSSL: true")
	}
	return errs
}

// validateLDAPSpec checks the LDAP backend: at least one host and a user base DN.
func validateLDAPSpec(spec *LDAPAuthSpec) []string {
	if spec == nil || !spec.Enabled {
		return nil
	}
	var errs []string
	if len(spec.Hosts) == 0 {
		errs = append(errs, "spec.ldap.hosts: must not be empty when LDAP is enabled")
	}
	if spec.Authentication.UserBase == "" {
		errs = append(errs, "spec.ldap.authentication.userBase: is required when LDAP is enabled")
	}
	return errs
}

// validateJWTSpec checks the JWT backend: exactly one verification source
// (a signing key or a JWKS URL).
func validateJWTSpec(spec *JWTAuthSpec) []string {
	if spec == nil || !spec.Enabled {
		return nil
	}
	var errs []string
	hasKey := spec.SigningKeyRef != nil
	hasJWKS := spec.JwksURL != ""
	if !hasKey && !hasJWKS {
		errs = append(errs, "spec.jwt: either signingKeyRef or jwksUrl is required when JWT is enabled")
	}
	if hasKey && hasJWKS {
		errs = append(errs, "spec.jwt: signingKeyRef and jwksUrl are mutually exclusive")
	}
	return errs
}

// validateProxySpec checks the proxy backend: without xff.internalProxies the
// security plugin ignores the proxy identity headers.
func validateProxySpec(spec *ProxyAuthSpec) []string {
	if spec == nil || !spec.Enabled {
		return nil
	}
	if spec.XFF.InternalProxies == "" {
		return []string{"spec.proxy.xff.internalProxies is required when proxy is enabled"}
	}
	return nil
}

// validateKerberosSpec checks the Kerberos backend: acceptor principal and keytab
// credentials are both required.
func validateKerberosSpec(spec *KerberosAuthSpec) []string {
	if spec == nil || !spec.Enabled {
		return nil
	}
	var errs []string
	if spec.AcceptorPrincipal == "" {
		errs = append(errs, "spec.kerberos.acceptorPrincipal: is required when Kerberos is enabled")
	}
	if spec.CredentialsSecret == "" {
		errs = append(errs, "spec.kerberos.credentialsSecret: is required when Kerberos is enabled")
	}
	return errs
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
	if spec.Proxy != nil && spec.Proxy.Enabled {
		return true
	}
	if spec.Kerberos != nil && spec.Kerberos.Enabled {
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
	if spec.Kerberos != nil && spec.Kerberos.Enabled && spec.Kerberos.Challenge {
		count++
	}
	return count
}
