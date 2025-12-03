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

package utils

import (
	"strings"
	"testing"
)

func TestGenerateRandomPassword(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"length 8", 8},
		{"length 16", 16},
		{"length 24", 24},
		{"length 32", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := GenerateRandomPassword(tt.length)
			if len(password) != tt.length {
				t.Errorf("GenerateRandomPassword(%d) = %q, want length %d, got %d", tt.length, password, tt.length, len(password))
			}
		})
	}
}

func TestGenerateRandomPassword_Uniqueness(t *testing.T) {
	// Generate multiple passwords and ensure they're different
	passwords := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pwd := GenerateRandomPassword(16)
		if passwords[pwd] {
			t.Errorf("GenerateRandomPassword generated duplicate password: %s", pwd)
		}
		passwords[pwd] = true
	}
}

func TestGenerateWazuhAPIPassword(t *testing.T) {
	const lowercase = "abcdefghijklmnopqrstuvwxyz"
	const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const digits = "0123456789"
	const specialChars = ".*+?-@#$%"

	tests := []struct {
		name           string
		length         int
		expectedLength int
	}{
		{"length 20", 20, 20},
		{"length 8 (minimum)", 8, 8},
		{"length 5 (below minimum, should use 20)", 5, 20},
		{"length 0 (should use 20)", 0, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password := GenerateWazuhAPIPassword(tt.length)

			// Check length
			if len(password) != tt.expectedLength {
				t.Errorf("GenerateWazuhAPIPassword(%d) = %q, want length %d, got %d", tt.length, password, tt.expectedLength, len(password))
			}

			// Check Wazuh password policy requirements:
			// - At least one lowercase letter
			hasLower := false
			for _, c := range password {
				if strings.ContainsRune(lowercase, c) {
					hasLower = true
					break
				}
			}
			if !hasLower {
				t.Errorf("GenerateWazuhAPIPassword(%d) = %q, should contain at least one lowercase letter", tt.length, password)
			}

			// - At least one uppercase letter
			hasUpper := false
			for _, c := range password {
				if strings.ContainsRune(uppercase, c) {
					hasUpper = true
					break
				}
			}
			if !hasUpper {
				t.Errorf("GenerateWazuhAPIPassword(%d) = %q, should contain at least one uppercase letter", tt.length, password)
			}

			// - At least one digit
			hasDigit := false
			for _, c := range password {
				if strings.ContainsRune(digits, c) {
					hasDigit = true
					break
				}
			}
			if !hasDigit {
				t.Errorf("GenerateWazuhAPIPassword(%d) = %q, should contain at least one digit", tt.length, password)
			}

			// - At least one special character
			hasSpecial := false
			for _, c := range password {
				if strings.ContainsRune(specialChars, c) {
					hasSpecial = true
					break
				}
			}
			if !hasSpecial {
				t.Errorf("GenerateWazuhAPIPassword(%d) = %q, should contain at least one special character from %q", tt.length, password, specialChars)
			}
		})
	}
}

func TestGenerateWazuhAPIPassword_Uniqueness(t *testing.T) {
	// Generate multiple passwords and ensure they're different
	passwords := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pwd := GenerateWazuhAPIPassword(20)
		if passwords[pwd] {
			t.Errorf("GenerateWazuhAPIPassword generated duplicate password: %s", pwd)
		}
		passwords[pwd] = true
	}
}

func TestGenerateWazuhAPIPassword_SpecialCharDistribution(t *testing.T) {
	specialChars := ".*+?-@#$%"

	// Generate many passwords and check special char distribution
	charCounts := make(map[rune]int)
	for i := 0; i < 1000; i++ {
		pwd := GenerateWazuhAPIPassword(20)
		for _, c := range pwd {
			if strings.ContainsRune(specialChars, c) {
				charCounts[c]++
			}
		}
	}

	// Each special character should appear at least once
	for _, c := range specialChars {
		if charCounts[c] == 0 {
			t.Errorf("Special character %q never appeared in 1000 generated passwords", string(c))
		}
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes, err := GenerateRandomBytes(tt.length)
			if err != nil {
				t.Errorf("GenerateRandomBytes(%d) returned error: %v", tt.length, err)
			}
			if len(bytes) != tt.length {
				t.Errorf("GenerateRandomBytes(%d) returned %d bytes, want %d", tt.length, len(bytes), tt.length)
			}
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	tests := []struct {
		name   string
		length int
	}{
		{"length 8", 8},
		{"length 16", 16},
		{"length 32", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateRandomString(tt.length)
			if len(result) != tt.length {
				t.Errorf("GenerateRandomString(%d) = %q, want length %d, got %d", tt.length, result, tt.length, len(result))
			}

			// Check that all characters are from the expected charset
			for _, c := range result {
				if !strings.ContainsRune(charset, c) {
					t.Errorf("GenerateRandomString(%d) = %q contains invalid character %q", tt.length, result, string(c))
				}
			}
		})
	}
}
