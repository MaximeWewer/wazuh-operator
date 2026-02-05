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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// OpenSearchAuthConfig CRD - Manages OpenSearch authentication configuration
// ============================================================================

// OpenSearchAuthConfigSpec defines the desired state of OpenSearchAuthConfig
type OpenSearchAuthConfigSpec struct {
	// ClusterRef references the WazuhCluster this auth config belongs to
	// +kubebuilder:validation:Required
	ClusterRef WazuhClusterReference `json:"clusterRef"`

	// BasicAuth configures HTTP Basic authentication against internal users database
	// +optional
	BasicAuth *BasicAuthSpec `json:"basicAuth,omitempty"`

	// OIDC configures OpenID Connect authentication
	// +optional
	OIDC *OIDCAuthSpec `json:"oidc,omitempty"`

	// SAML configures SAML 2.0 authentication
	// +optional
	SAML *SAMLAuthSpec `json:"saml,omitempty"`

	// LDAP configures LDAP/Active Directory authentication
	// +optional
	LDAP *LDAPAuthSpec `json:"ldap,omitempty"`
}

// ============================================================================
// Basic Auth Configuration (T002, T003)
// ============================================================================

// BasicAuthSpec configures HTTP Basic authentication
type BasicAuthSpec struct {
	// Enabled enables HTTP Basic authentication
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// Order determines the evaluation order of this auth domain
	// Lower numbers are evaluated first
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=0
	Order int `json:"order,omitempty"`

	// Challenge enables WWW-Authenticate challenge header
	// Only one auth domain should have challenge enabled when multiple are configured
	// +kubebuilder:default=true
	Challenge bool `json:"challenge,omitempty"`

	// HTTPEnabled enables authentication on HTTP layer
	// +kubebuilder:default=true
	HTTPEnabled bool `json:"httpEnabled,omitempty"`

	// TransportEnabled enables authentication on transport layer
	// +kubebuilder:default=true
	TransportEnabled bool `json:"transportEnabled,omitempty"`
}

// ============================================================================
// OIDC Configuration (T004)
// ============================================================================

// OIDCAuthSpec configures OpenID Connect authentication
type OIDCAuthSpec struct {
	// Enabled enables OIDC authentication
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Order determines the evaluation order of this auth domain
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=1
	Order int `json:"order,omitempty"`

	// Challenge enables authentication challenge
	// Should typically be false when multiple auth methods are enabled
	// +kubebuilder:default=false
	Challenge bool `json:"challenge,omitempty"`

	// HTTPEnabled enables authentication on HTTP layer
	// +kubebuilder:default=true
	HTTPEnabled bool `json:"httpEnabled,omitempty"`

	// ConnectURL is the OpenID Connect discovery endpoint URL
	// Example: https://keycloak.example.com/realms/wazuh/.well-known/openid-configuration
	// +kubebuilder:validation:Required
	ConnectURL string `json:"connectURL,omitempty"`

	// ClientID is the OAuth 2.0 client ID
	// +kubebuilder:validation:Required
	ClientID string `json:"clientId,omitempty"`

	// ClientSecretRef references a Secret containing the client secret
	// +optional
	ClientSecretRef *SecretKeyRef `json:"clientSecretRef,omitempty"`

	// SubjectKey is the JWT claim to use as the username
	// +kubebuilder:default="preferred_username"
	SubjectKey string `json:"subjectKey,omitempty"`

	// RolesKey is the JWT claim containing user roles
	// +kubebuilder:default="roles"
	RolesKey string `json:"rolesKey,omitempty"`

	// Scope is the OAuth 2.0 scope to request
	// +kubebuilder:default="openid profile email"
	Scope string `json:"scope,omitempty"`

	// LogoutURL is the URL to redirect after logout
	// +optional
	LogoutURL string `json:"logoutUrl,omitempty"`

	// Dashboard configures OIDC-specific dashboard settings
	// +optional
	Dashboard *OIDCDashboardSpec `json:"dashboard,omitempty"`
}

// OIDCDashboardSpec configures OIDC settings for OpenSearch Dashboard
type OIDCDashboardSpec struct {
	// RootURL is the base URL of the dashboard for OIDC callbacks
	// Example: https://dashboard.example.com
	// +optional
	RootURL string `json:"rootUrl,omitempty"`

	// LoginEndpoint is the custom login endpoint path
	// +kubebuilder:default="/auth/openid/login"
	LoginEndpoint string `json:"loginEndpoint,omitempty"`

	// LogoutEndpoint is the custom logout endpoint path
	// +kubebuilder:default="/auth/openid/logout"
	LogoutEndpoint string `json:"logoutEndpoint,omitempty"`

	// CookiePassword is the password for cookie encryption (auto-generated if not set)
	// +optional
	CookiePasswordRef *SecretKeyRef `json:"cookiePasswordRef,omitempty"`

	// AdditionalCookies defines extra cookies to set
	// +optional
	AdditionalCookies []string `json:"additionalCookies,omitempty"`

	// CookiePrefix is the prefix for OIDC cookies
	// +kubebuilder:default="security_authentication"
	CookiePrefix string `json:"cookiePrefix,omitempty"`
}

// ============================================================================
// SAML Configuration (T005)
// ============================================================================

// SAMLAuthSpec configures SAML 2.0 authentication
type SAMLAuthSpec struct {
	// Enabled enables SAML authentication
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Order determines the evaluation order of this auth domain
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=2
	Order int `json:"order,omitempty"`

	// Challenge enables authentication challenge
	// Should typically be false when multiple auth methods are enabled
	// +kubebuilder:default=false
	Challenge bool `json:"challenge,omitempty"`

	// HTTPEnabled enables authentication on HTTP layer
	// +kubebuilder:default=true
	HTTPEnabled bool `json:"httpEnabled,omitempty"`

	// IdpMetadataURL is the URL to fetch IdP metadata from
	// Either IdpMetadataURL or IdpMetadataFile must be specified
	// +optional
	IdpMetadataURL string `json:"idpMetadataUrl,omitempty"`

	// IdpMetadataFile is the path to IdP metadata XML file
	// Either IdpMetadataURL or IdpMetadataFile must be specified
	// +optional
	IdpMetadataFile string `json:"idpMetadataFile,omitempty"`

	// IdpEntityID is the entity ID of the Identity Provider
	// +kubebuilder:validation:Required
	IdpEntityID string `json:"idpEntityId,omitempty"`

	// SpEntityID is the entity ID of this Service Provider
	// Usually the Kibana/Dashboard URL
	// +kubebuilder:validation:Required
	SpEntityID string `json:"spEntityId,omitempty"`

	// KibanaURL is the base URL of OpenSearch Dashboard
	// Used for assertion consumer service URL
	// +kubebuilder:validation:Required
	KibanaURL string `json:"kibanaUrl,omitempty"`

	// SubjectKey is the SAML attribute to use as the username
	// +kubebuilder:default="NameID"
	SubjectKey string `json:"subjectKey,omitempty"`

	// RolesKey is the SAML attribute containing user roles
	// +optional
	RolesKey string `json:"rolesKey,omitempty"`

	// ExchangeKeyRef references a Secret containing the HMAC256 exchange key
	// Used for signing and encrypting SAML messages
	// +optional
	ExchangeKeyRef *SecretKeyRef `json:"exchangeKeyRef,omitempty"`

	// Dashboard configures SAML-specific dashboard settings
	// +optional
	Dashboard *SAMLDashboardSpec `json:"dashboard,omitempty"`
}

// SAMLDashboardSpec configures SAML settings for OpenSearch Dashboard
type SAMLDashboardSpec struct {
	// RequestedAuthnContextRef specifies the authentication context requirements
	// +optional
	RequestedAuthnContextRef string `json:"requestedAuthnContextRef,omitempty"`

	// XSRFAllowlist specifies URLs to exclude from XSRF protection
	// Typically includes the SAML ACS endpoint
	// +optional
	XSRFAllowlist []string `json:"xsrfAllowlist,omitempty"`
}

// ============================================================================
// LDAP Configuration (T006)
// ============================================================================

// LDAPAuthSpec configures LDAP/Active Directory authentication
type LDAPAuthSpec struct {
	// Enabled enables LDAP authentication
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Order determines the evaluation order of this auth domain
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=3
	Order int `json:"order,omitempty"`

	// Challenge enables authentication challenge
	// Should typically be false when multiple auth methods are enabled
	// +kubebuilder:default=false
	Challenge bool `json:"challenge,omitempty"`

	// HTTPEnabled enables authentication on HTTP layer
	// +kubebuilder:default=true
	HTTPEnabled bool `json:"httpEnabled,omitempty"`

	// TransportEnabled enables authentication on transport layer
	// +kubebuilder:default=false
	TransportEnabled bool `json:"transportEnabled,omitempty"`

	// Hosts is the list of LDAP server hostnames or IPs
	// +kubebuilder:validation:MinItems=1
	Hosts []string `json:"hosts,omitempty"`

	// Authentication configures LDAP authentication settings
	// +kubebuilder:validation:Required
	Authentication LDAPAuthenticationSpec `json:"authentication,omitempty"`

	// Authorization configures LDAP authorization/role mapping
	// +optional
	Authorization *LDAPAuthorizationSpec `json:"authorization,omitempty"`

	// TLS configures LDAP TLS/SSL settings
	// +optional
	TLS *LDAPTLSSpec `json:"tls,omitempty"`

	// ConnectionPool configures connection pooling
	// +optional
	ConnectionPool *LDAPConnectionPoolSpec `json:"connectionPool,omitempty"`
}

// LDAPAuthenticationSpec configures LDAP authentication
type LDAPAuthenticationSpec struct {
	// BindDN is the DN to bind for LDAP searches
	// Example: cn=admin,dc=example,dc=com
	// +optional
	BindDN string `json:"bindDn,omitempty"`

	// BindPasswordRef references a Secret containing the bind password
	// +optional
	BindPasswordRef *SecretKeyRef `json:"bindPasswordRef,omitempty"`

	// UserBase is the base DN for user searches
	// Example: ou=users,dc=example,dc=com
	// +kubebuilder:validation:Required
	UserBase string `json:"userBase,omitempty"`

	// UserSearch is the LDAP filter for finding users
	// Example: (uid={0}) or (sAMAccountName={0}) for AD
	// +kubebuilder:default="(uid={0})"
	UserSearch string `json:"userSearch,omitempty"`

	// UsernameAttribute is the attribute containing the username
	// +kubebuilder:default="uid"
	UsernameAttribute string `json:"usernameAttribute,omitempty"`
}

// LDAPAuthorizationSpec configures LDAP authorization/role mapping
type LDAPAuthorizationSpec struct {
	// Enabled enables LDAP authorization
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// RoleBase is the base DN for role searches
	// Example: ou=groups,dc=example,dc=com
	// +kubebuilder:validation:Required
	RoleBase string `json:"roleBase,omitempty"`

	// RoleSearch is the LDAP filter for finding roles
	// Example: (member={0}) or (memberUid={1})
	// +kubebuilder:default="(member={0})"
	RoleSearch string `json:"roleSearch,omitempty"`

	// UserRoleName is the user attribute for role membership
	// Example: memberOf (for AD)
	// +optional
	UserRoleName string `json:"userRoleName,omitempty"`

	// RoleName is the attribute containing the role name
	// +kubebuilder:default="cn"
	RoleName string `json:"roleName,omitempty"`

	// ResolveNestedRoles enables nested group resolution
	// +kubebuilder:default=false
	ResolveNestedRoles bool `json:"resolveNestedRoles,omitempty"`

	// SkipUsers disables user authorization (role-only mode)
	// +kubebuilder:default=false
	SkipUsers bool `json:"skipUsers,omitempty"`
}

// LDAPTLSSpec configures LDAP TLS/SSL settings
type LDAPTLSSpec struct {
	// EnableSSL enables LDAPS (port 636)
	// +kubebuilder:default=false
	EnableSSL bool `json:"enableSsl,omitempty"`

	// EnableStartTLS enables STARTTLS on standard port
	// +kubebuilder:default=false
	EnableStartTLS bool `json:"enableStartTls,omitempty"`

	// VerifyHostnames enables hostname verification
	// +kubebuilder:default=true
	VerifyHostnames bool `json:"verifyHostnames,omitempty"`

	// TrustAllCertificates disables certificate verification (insecure)
	// +kubebuilder:default=false
	TrustAllCertificates bool `json:"trustAllCertificates,omitempty"`

	// PemTrustedCAsFilepath is the path to trusted CA certificates
	// +optional
	PemTrustedCAsFilepath string `json:"pemTrustedCasFilepath,omitempty"`
}

// LDAPConnectionPoolSpec configures LDAP connection pooling
type LDAPConnectionPoolSpec struct {
	// MinSize is the minimum pool size
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=3
	MinSize int `json:"minSize,omitempty"`

	// MaxSize is the maximum pool size
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=10
	MaxSize int `json:"maxSize,omitempty"`
}

// ============================================================================
// Status
// ============================================================================

// OpenSearchAuthConfigStatus defines the observed state of OpenSearchAuthConfig
type OpenSearchAuthConfigStatus struct {
	// Phase is the current phase (Pending, Ready, Failed)
	// +optional
	Phase string `json:"phase,omitempty"`

	// Message provides additional information about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastSyncTime is when the auth config was last synced to OpenSearch
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ActiveAuthDomains lists the currently active authentication domains
	// +optional
	ActiveAuthDomains []string `json:"activeAuthDomains,omitempty"`

	// ConfigSynced indicates if the security config is in sync
	// +optional
	ConfigSynced bool `json:"configSynced,omitempty"`

	// DashboardConfigSynced indicates if the dashboard config is in sync
	// +optional
	DashboardConfigSynced bool `json:"dashboardConfigSynced,omitempty"`
}

// ============================================================================
// CRD Definition
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=osauthconfig;osauth
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Basic",type=boolean,JSONPath=`.spec.basicAuth.enabled`
// +kubebuilder:printcolumn:name="OIDC",type=boolean,JSONPath=`.spec.oidc.enabled`
// +kubebuilder:printcolumn:name="SAML",type=boolean,JSONPath=`.spec.saml.enabled`
// +kubebuilder:printcolumn:name="LDAP",type=boolean,JSONPath=`.spec.ldap.enabled`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OpenSearchAuthConfig is the Schema for the opensearchauthconfigs API
// It manages authentication configuration for OpenSearch clusters including
// basic auth, OIDC, SAML, and LDAP authentication methods.
type OpenSearchAuthConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenSearchAuthConfigSpec   `json:"spec,omitempty"`
	Status OpenSearchAuthConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenSearchAuthConfigList contains a list of OpenSearchAuthConfig
type OpenSearchAuthConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenSearchAuthConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenSearchAuthConfig{}, &OpenSearchAuthConfigList{})
}
