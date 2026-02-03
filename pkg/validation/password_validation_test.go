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

package validation

import (
	"errors"
	"testing"
)

func TestValidateWazuhPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errCount int // expected number of validation errors
	}{
		{
			name:     "valid password with all requirements",
			password: "Wazuh.Secure.2026",
			wantErr:  false,
		},
		{
			name:     "valid password with different special char",
			password: "MyP@ssw0rd!",
			wantErr:  false,
		},
		{
			name:     "valid password with underscore",
			password: "Test_Pass123",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "Ab1.",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "missing lowercase",
			password: "ABCD1234.",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "missing uppercase",
			password: "abcd1234.",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "missing digit",
			password: "Abcdefgh.",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "missing special character",
			password: "Abcdefgh1",
			wantErr:  true,
			errCount: 1,
		},
		{
			name:     "default helm password - should fail",
			password: "CHANGE_ME_STRONG_PASSWORD_HERE",
			wantErr:  true,
			errCount: 2, // missing lowercase and special char
		},
		{
			name:     "only lowercase",
			password: "abcdefghij",
			wantErr:  true,
			errCount: 3, // missing uppercase, digit, special
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  true,
			errCount: 5, // all requirements fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWazuhPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWazuhPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				var pve *PasswordValidationError
				if errors.As(err, &pve) {
					if len(pve.Reasons) != tt.errCount {
						t.Errorf("ValidateWazuhPassword() got %d errors, want %d errors. Errors: %v",
							len(pve.Reasons), tt.errCount, pve.Reasons)
					}
				}
			}
		})
	}
}

func TestIsPasswordValidationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "password validation error",
			err:  &PasswordValidationError{Reasons: []string{"test"}},
			want: true,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPasswordValidationError(tt.err); got != tt.want {
				t.Errorf("IsPasswordValidationError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultWazuhPasswordPolicy(t *testing.T) {
	policy := DefaultWazuhPasswordPolicy()

	if policy.MinLength != 8 {
		t.Errorf("MinLength = %d, want 8", policy.MinLength)
	}
	if !policy.RequireLowercase {
		t.Error("RequireLowercase should be true")
	}
	if !policy.RequireUppercase {
		t.Error("RequireUppercase should be true")
	}
	if !policy.RequireDigit {
		t.Error("RequireDigit should be true")
	}
	if !policy.RequireSpecial {
		t.Error("RequireSpecial should be true")
	}
	if policy.SpecialChars == "" {
		t.Error("SpecialChars should not be empty")
	}
}

func TestFormatPasswordRequirements(t *testing.T) {
	requirements := FormatPasswordRequirements()

	if requirements == "" {
		t.Error("FormatPasswordRequirements() should return non-empty string")
	}

	// Check that it contains key information
	if !contains(requirements, "8") {
		t.Error("Requirements should mention minimum length of 8")
	}
	if !contains(requirements, "lowercase") {
		t.Error("Requirements should mention lowercase")
	}
	if !contains(requirements, "uppercase") {
		t.Error("Requirements should mention uppercase")
	}
	if !contains(requirements, "digit") {
		t.Error("Requirements should mention digit")
	}
	if !contains(requirements, "special") {
		t.Error("Requirements should mention special character")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
