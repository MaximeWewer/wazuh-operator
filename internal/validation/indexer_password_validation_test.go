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

func TestValidateIndexerPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "operator-generated alphanumeric", password: "aB3xY9zQkLm2", wantErr: false},
		{name: "common special characters are fine", password: "P@ssw0rd!#%-_.", wantErr: false},
		// "/" only breaks a sed using "/" as its delimiter; the upstream script's delimiter is
		// not guaranteed, so we must not reject passwords that may already work.
		{name: "slash is allowed", password: "pa/ss/w0rD!", wantErr: false},

		{name: "ampersand corrupts the sed replacement", password: "pa&ssw0rD!", wantErr: true},
		{name: "backslash is the sed escape", password: `pa\ssw0rD!`, wantErr: true},
		{name: "double quote breaks the YAML scalar", password: `pa"ssw0rD!`, wantErr: true},
		{name: "newline breaks line-oriented config", password: "pass\nw0rD!", wantErr: true},
		{name: "carriage return breaks line-oriented config", password: "pass\rw0rD!", wantErr: true},
		{name: "several unsafe characters at once", password: `a&b\c"d`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIndexerPassword(tt.password)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateIndexerPassword(%q) = nil, want an error", tt.password)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateIndexerPassword(%q) = %v, want nil", tt.password, err)
			}
			if tt.wantErr && err != nil && !IsPasswordValidationError(err) {
				t.Errorf("ValidateIndexerPassword(%q) returned %T, want *PasswordValidationError", tt.password, err)
			}
		})
	}
}

// Each unsafe character must be reported once, so the user sees every problem in one pass
// instead of fixing them one reconcile at a time.
func TestValidateIndexerPassword_ReportsEachUnsafeCharOnce(t *testing.T) {
	err := ValidateIndexerPassword(`a&&b\\c""d`)
	if err == nil {
		t.Fatal("expected an error")
	}
	var pve *PasswordValidationError
	if !IsPasswordValidationError(err) {
		t.Fatalf("got %T, want *PasswordValidationError", err)
	}
	pve = func() *PasswordValidationError {
		target := &PasswordValidationError{}
		_ = errors.As(err, &target)
		return target
	}()
	if len(pve.Reasons) != 3 {
		t.Errorf("got %d reasons %v, want 3 (one per distinct unsafe character)", len(pve.Reasons), pve.Reasons)
	}
}
