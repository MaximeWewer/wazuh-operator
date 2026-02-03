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
	"fmt"
	"strings"
	"unicode"
)

// WazuhPasswordPolicy defines the password complexity requirements for Wazuh API
// These requirements are enforced by Wazuh itself (Error 5007 - Insecure user password)
type WazuhPasswordPolicy struct {
	MinLength        int
	RequireLowercase bool
	RequireUppercase bool
	RequireDigit     bool
	RequireSpecial   bool
	SpecialChars     string // Allowed special characters
}

// DefaultWazuhPasswordPolicy returns the default Wazuh password policy
// Based on Wazuh's security requirements that cause Error 5007 when not met
func DefaultWazuhPasswordPolicy() WazuhPasswordPolicy {
	return WazuhPasswordPolicy{
		MinLength:        8,
		RequireLowercase: true,
		RequireUppercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
		SpecialChars:     ".*+?-_@#$%&!^()[]{}|:;<>,~/\\`\"'=",
	}
}

// PasswordValidationError represents a password validation failure with details
type PasswordValidationError struct {
	Reasons []string
}

func (e *PasswordValidationError) Error() string {
	return fmt.Sprintf("password does not meet Wazuh security requirements: %s", strings.Join(e.Reasons, "; "))
}

// ValidateWazuhPassword validates a password against Wazuh's password policy
// Returns nil if the password is valid, or a PasswordValidationError with details
func ValidateWazuhPassword(password string) error {
	return ValidateWazuhPasswordWithPolicy(password, DefaultWazuhPasswordPolicy())
}

// ValidateWazuhPasswordWithPolicy validates a password against a custom policy
func ValidateWazuhPasswordWithPolicy(password string, policy WazuhPasswordPolicy) error {
	var reasons []string

	// Check minimum length
	if len(password) < policy.MinLength {
		reasons = append(reasons, fmt.Sprintf("minimum length is %d characters (got %d)", policy.MinLength, len(password)))
	}

	// Check for required character types
	var hasLower, hasUpper, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsDigit(char):
			hasDigit = true
		case strings.ContainsRune(policy.SpecialChars, char):
			hasSpecial = true
		}
	}

	if policy.RequireLowercase && !hasLower {
		reasons = append(reasons, "must contain at least one lowercase letter (a-z)")
	}

	if policy.RequireUppercase && !hasUpper {
		reasons = append(reasons, "must contain at least one uppercase letter (A-Z)")
	}

	if policy.RequireDigit && !hasDigit {
		reasons = append(reasons, "must contain at least one digit (0-9)")
	}

	if policy.RequireSpecial && !hasSpecial {
		reasons = append(reasons, fmt.Sprintf("must contain at least one special character (e.g., %s)", policy.SpecialChars[:10]+"..."))
	}

	if len(reasons) > 0 {
		return &PasswordValidationError{Reasons: reasons}
	}

	return nil
}

// IsPasswordValidationError checks if an error is a PasswordValidationError
func IsPasswordValidationError(err error) bool {
	_, ok := err.(*PasswordValidationError)
	return ok
}

// FormatPasswordRequirements returns a human-readable string of password requirements
func FormatPasswordRequirements() string {
	policy := DefaultWazuhPasswordPolicy()
	return fmt.Sprintf(
		"Wazuh API password requirements: minimum %d characters, at least one lowercase letter, "+
			"one uppercase letter, one digit, and one special character (e.g., . * + ? - _ @ # $ %% &)",
		policy.MinLength,
	)
}
