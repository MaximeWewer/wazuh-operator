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
	"testing"
)

func TestOpenSearchAuthConfigValidator_NoAuthEnabled(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			// No auth methods enabled
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err == nil {
		t.Error("expected error when no auth method is enabled, got nil")
	}
}

func TestOpenSearchAuthConfigValidator_BasicAuthOnly(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			BasicAuth: &BasicAuthSpec{
				Enabled: true,
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err != nil {
		t.Errorf("expected no error with basicAuth enabled, got: %v", err)
	}
}

func TestOpenSearchAuthConfigValidator_OIDCMissingConnectURL(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			OIDC: &OIDCAuthSpec{
				Enabled:  true,
				ClientID: "my-client",
				// ConnectURL missing
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err == nil {
		t.Error("expected error when OIDC connectURL is missing, got nil")
	}
}

func TestOpenSearchAuthConfigValidator_OIDCMissingClientID(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			OIDC: &OIDCAuthSpec{
				Enabled:    true,
				ConnectURL: "https://idp.example.com/.well-known/openid-configuration",
				// ClientID missing
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err == nil {
		t.Error("expected error when OIDC clientId is missing, got nil")
	}
}

func TestOpenSearchAuthConfigValidator_OIDCValid(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			OIDC: &OIDCAuthSpec{
				Enabled:    true,
				ConnectURL: "https://idp.example.com/.well-known/openid-configuration",
				ClientID:   "my-client",
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err != nil {
		t.Errorf("expected no error with valid OIDC config, got: %v", err)
	}
}

func TestOpenSearchAuthConfigValidator_SAMLMissingFields(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			SAML: &SAMLAuthSpec{
				Enabled: true,
				// All required fields missing
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err == nil {
		t.Error("expected error when SAML required fields are missing, got nil")
	}
}

func TestOpenSearchAuthConfigValidator_SAMLMissingMetadata(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			SAML: &SAMLAuthSpec{
				Enabled:     true,
				IdpEntityID: "https://idp.example.com",
				SpEntityID:  "https://dashboard.example.com",
				KibanaURL:   "https://dashboard.example.com",
				// Neither IdpMetadataURL nor IdpMetadataFile set
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err == nil {
		t.Error("expected error when SAML metadata source is missing, got nil")
	}
}

func TestOpenSearchAuthConfigValidator_SAMLValidWithURL(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			SAML: &SAMLAuthSpec{
				Enabled:        true,
				IdpEntityID:    "https://idp.example.com",
				SpEntityID:     "https://dashboard.example.com",
				KibanaURL:      "https://dashboard.example.com",
				IdpMetadataURL: "https://idp.example.com/metadata",
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err != nil {
		t.Errorf("expected no error with valid SAML config, got: %v", err)
	}
}

func TestOpenSearchAuthConfigValidator_SAMLValidWithFile(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			SAML: &SAMLAuthSpec{
				Enabled:         true,
				IdpEntityID:     "https://idp.example.com",
				SpEntityID:      "https://dashboard.example.com",
				KibanaURL:       "https://dashboard.example.com",
				IdpMetadataFile: "/path/to/metadata.xml",
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err != nil {
		t.Errorf("expected no error with valid SAML config (file), got: %v", err)
	}
}

func TestOpenSearchAuthConfigValidator_LDAPMissingHosts(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			LDAP: &LDAPAuthSpec{
				Enabled: true,
				// Hosts empty
				Authentication: LDAPAuthenticationSpec{
					UserBase: "ou=users,dc=example,dc=com",
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err == nil {
		t.Error("expected error when LDAP hosts is empty, got nil")
	}
}

func TestOpenSearchAuthConfigValidator_LDAPMissingUserBase(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			LDAP: &LDAPAuthSpec{
				Enabled:        true,
				Hosts:          []string{"ldap.example.com"},
				Authentication: LDAPAuthenticationSpec{
					// UserBase missing
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err == nil {
		t.Error("expected error when LDAP userBase is missing, got nil")
	}
}

func TestOpenSearchAuthConfigValidator_LDAPValid(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			LDAP: &LDAPAuthSpec{
				Enabled: true,
				Hosts:   []string{"ldap.example.com"},
				Authentication: LDAPAuthenticationSpec{
					UserBase: "ou=users,dc=example,dc=com",
				},
			},
		},
	}

	_, err := v.ValidateCreate(context.Background(), authConfig)
	if err != nil {
		t.Errorf("expected no error with valid LDAP config, got: %v", err)
	}
}

func TestOpenSearchAuthConfigValidator_MultipleChallengeWarning(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			BasicAuth: &BasicAuthSpec{
				Enabled:   true,
				Challenge: true,
			},
			OIDC: &OIDCAuthSpec{
				Enabled:    true,
				Challenge:  true,
				ConnectURL: "https://idp.example.com/.well-known/openid-configuration",
				ClientID:   "my-client",
			},
		},
	}

	warnings, err := v.ValidateCreate(context.Background(), authConfig)
	if err != nil {
		t.Errorf("expected no error with multiple challenge domains, got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("expected warning when multiple auth domains have challenge=true, got none")
	}
}

func TestOpenSearchAuthConfigValidator_SingleChallengeNoWarning(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			BasicAuth: &BasicAuthSpec{
				Enabled:   true,
				Challenge: true,
			},
			OIDC: &OIDCAuthSpec{
				Enabled:    true,
				Challenge:  false,
				ConnectURL: "https://idp.example.com/.well-known/openid-configuration",
				ClientID:   "my-client",
			},
		},
	}

	warnings, err := v.ValidateCreate(context.Background(), authConfig)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("expected no warnings with single challenge domain, got: %v", warnings)
	}
}

func TestOpenSearchAuthConfigValidator_DisabledAuthNotCounted(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	// Only BasicAuth enabled with challenge=true, OIDC disabled but with challenge=true
	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			BasicAuth: &BasicAuthSpec{
				Enabled:   true,
				Challenge: true,
			},
			OIDC: &OIDCAuthSpec{
				Enabled:   false, // disabled
				Challenge: true,
			},
		},
	}

	warnings, err := v.ValidateCreate(context.Background(), authConfig)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if len(warnings) > 0 {
		t.Errorf("expected no warnings (disabled auth should not count), got: %v", warnings)
	}
}

func TestOpenSearchAuthConfigValidator_ValidateUpdate(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	old := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			BasicAuth:  &BasicAuthSpec{Enabled: true},
		},
	}
	new := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
			BasicAuth:  &BasicAuthSpec{Enabled: true},
			OIDC: &OIDCAuthSpec{
				Enabled:    true,
				ConnectURL: "https://idp.example.com/.well-known/openid-configuration",
				ClientID:   "my-client",
			},
		},
	}

	_, err := v.ValidateUpdate(context.Background(), old, new)
	if err != nil {
		t.Errorf("expected no error on valid update, got: %v", err)
	}
}

func TestOpenSearchAuthConfigValidator_ValidateDelete(t *testing.T) {
	v := &OpenSearchAuthConfigCustomValidator{}

	authConfig := &OpenSearchAuthConfig{
		Spec: OpenSearchAuthConfigSpec{
			ClusterRef: WazuhClusterReference{Name: "test-cluster"},
		},
	}

	_, err := v.ValidateDelete(context.Background(), authConfig)
	if err != nil {
		t.Errorf("expected no error on delete, got: %v", err)
	}
}
