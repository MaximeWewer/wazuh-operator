package config

import (
	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// buildJWTAuthDomain creates the jwt auth domain configuration for config.yml.
// Reference: https://docs.opensearch.org/latest/security/authentication-backends/jwt/
//
// JWKS-based validation is routed to the authenticator the target OpenSearch version
// supports. The native `jwt` authenticator only accepts `jwks_uri` from OpenSearch 3.3;
// on older versions JWKS validation must use the `openid` authenticator (where `jwks_uri`
// replaces `openid_connect_url`). A static `signing_key` always uses the `jwt`
// authenticator, which is valid on every version.
func (b *AuthConfigBuilder) buildJWTAuthDomain(spec *v1.JWTAuthSpec) AuthDomainConfig {
	config := make(map[string]any)

	usesJWKS := spec.JwksURL != ""

	// Default to the native jwt authenticator; route JWKS to openid on versions whose
	// jwt authenticator predates jwks_uri support.
	authType := "jwt"
	if usesJWKS && !b.openSearchSupportsJwtJwks() {
		authType = "openid"
	}

	// Static signing key (jwt authenticator only). Mutually exclusive with jwks_uri.
	if secret, ok := b.resolvedSecrets[AuthSecretKeyJWTSigningKey]; ok && secret != "" {
		config["signing_key"] = secret
	}
	if usesJWKS {
		config["jwks_uri"] = spec.JwksURL
	}

	if spec.JwtHeader != "" {
		config["jwt_header"] = spec.JwtHeader
	}
	if spec.JwtURLParameter != "" {
		config["jwt_url_parameter"] = spec.JwtURLParameter
	}
	if spec.SubjectKey != "" {
		config["subject_key"] = spec.SubjectKey
	}
	if spec.RolesKey != "" {
		config["roles_key"] = spec.RolesKey
	}
	if spec.RequiredAudience != "" {
		config["required_audience"] = spec.RequiredAudience
	}
	if spec.RequiredIssuer != "" {
		config["required_issuer"] = spec.RequiredIssuer
	}
	if spec.ClockSkewToleranceSeconds > 0 {
		config["jwt_clock_skew_tolerance_seconds"] = spec.ClockSkewToleranceSeconds
	}

	// The domain name is an arbitrary key; keep it stable as "jwt_auth_domain" (even when
	// the authenticator is openid) so it never collides with the dedicated OIDC block's
	// "openid_auth_domain".
	return AuthDomainConfig{
		Name:                "jwt_auth_domain",
		Order:               spec.Order,
		HTTPEnabled:         spec.HTTPEnabled,
		TransportEnabled:    spec.TransportEnabled,
		Challenge:           spec.Challenge,
		AuthenticatorType:   authType,
		AuthenticatorConfig: config,
		BackendType:         "noop",
		Description:         "Authenticate via JWT bearer token",
	}
}

// JWTConfigBuilder validates and builds the JWT authenticator config in
// isolation, mirroring the OIDC/SAML/LDAP standalone builders.
type JWTConfigBuilder struct {
	spec            *v1.JWTAuthSpec
	resolvedSecrets map[string]string
}

func NewJWTConfigBuilder(spec *v1.JWTAuthSpec) *JWTConfigBuilder {
	return &JWTConfigBuilder{
		spec:            spec,
		resolvedSecrets: make(map[string]string),
	}
}

func (b *JWTConfigBuilder) WithSigningKey(key string) *JWTConfigBuilder {
	b.resolvedSecrets["signing_key"] = key
	return b
}

func (b *JWTConfigBuilder) BuildAuthenticatorConfig() map[string]any {
	config := make(map[string]any)

	if key, ok := b.resolvedSecrets["signing_key"]; ok && key != "" {
		config["signing_key"] = key
	}
	if b.spec.JwksURL != "" {
		config["jwks_uri"] = b.spec.JwksURL
	}
	if b.spec.JwtHeader != "" {
		config["jwt_header"] = b.spec.JwtHeader
	}
	if b.spec.JwtURLParameter != "" {
		config["jwt_url_parameter"] = b.spec.JwtURLParameter
	}
	if b.spec.SubjectKey != "" {
		config["subject_key"] = b.spec.SubjectKey
	}
	if b.spec.RolesKey != "" {
		config["roles_key"] = b.spec.RolesKey
	}
	if b.spec.RequiredAudience != "" {
		config["required_audience"] = b.spec.RequiredAudience
	}
	if b.spec.RequiredIssuer != "" {
		config["required_issuer"] = b.spec.RequiredIssuer
	}
	if b.spec.ClockSkewToleranceSeconds > 0 {
		config["jwt_clock_skew_tolerance_seconds"] = b.spec.ClockSkewToleranceSeconds
	}

	return config
}

// HasSigningKey reports whether a signing key was resolved from a Secret.
func (b *JWTConfigBuilder) HasSigningKey() bool {
	key, ok := b.resolvedSecrets["signing_key"]
	return ok && key != ""
}

func (b *JWTConfigBuilder) IsEnabled() bool {
	return b.spec != nil && b.spec.Enabled &&
		(b.HasSigningKey() || b.spec.JwksURL != "")
}

func (b *JWTConfigBuilder) ValidateConfig() error {
	if b.spec == nil || !b.spec.Enabled {
		return nil
	}

	// Exactly one verification source is required.
	hasKey := b.spec.SigningKeyRef != nil || b.HasSigningKey()
	hasJWKS := b.spec.JwksURL != ""
	if !hasKey && !hasJWKS {
		return &ValidationError{
			Field:   "jwt",
			Message: "either signingKeyRef or jwksUrl is required when JWT is enabled",
		}
	}
	if hasKey && hasJWKS {
		return &ValidationError{
			Field:   "jwt",
			Message: "signingKeyRef and jwksUrl are mutually exclusive",
		}
	}

	return nil
}
