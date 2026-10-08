package config

import (
	"strings"
	"testing"

	"k8s.io/utils/ptr"

	v1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// TestValidateMultiAuthJWTSupported guards a dashboard crash reproduced on Wazuh 4.9:
// basicAuth + jwt renders auth.type ["basicauth", "jwt"], which OpenSearch Dashboards
// before 2.18 rejects at startup with "Unsupported authentication type: jwt".
func TestValidateMultiAuthJWTSupported(t *testing.T) {
	jwt := &v1.JWTAuthSpec{Enabled: true}
	basic := &v1.BasicAuthSpec{Enabled: ptr.To(true)}
	oidc := &v1.OIDCAuthSpec{Enabled: true}

	tests := []struct {
		name    string
		spec    v1.OpenSearchAuthConfigSpec
		version string
		wantErr bool
	}{
		{"basic+jwt on 4.9", v1.OpenSearchAuthConfigSpec{BasicAuth: basic, JWT: jwt}, "4.9.0", true},
		{"oidc+jwt on 4.11", v1.OpenSearchAuthConfigSpec{OIDC: oidc, JWT: jwt}, "4.11.2", true},
		{"basic+jwt on 4.12", v1.OpenSearchAuthConfigSpec{BasicAuth: basic, JWT: jwt}, "4.12.0", false},
		{"basic+jwt on 4.14", v1.OpenSearchAuthConfigSpec{BasicAuth: basic, JWT: jwt}, "4.14.0", false},
		{"jwt alone on 4.9", v1.OpenSearchAuthConfigSpec{JWT: jwt}, "4.9.0", false},
		{"basic+oidc on 4.9", v1.OpenSearchAuthConfigSpec{BasicAuth: basic, OIDC: oidc}, "4.9.0", false},
		{"unknown version", v1.OpenSearchAuthConfigSpec{BasicAuth: basic, JWT: jwt}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAuthConfigBuilder(&tt.spec).WithWazuhVersion(tt.version).ValidateMultiAuthJWTSupported()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateMultiAuthJWTSupported() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "Wazuh 4.12") {
				t.Errorf("error should point to the fix: %v", err)
			}
		})
	}
}
