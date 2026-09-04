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

package config

import (
	"os"
	"testing"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestInitialize(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		expected    int
		expectError bool
	}{
		{
			name:        "default value when env not set",
			envValue:    "",
			expected:    constants.DefaultVMMaxMapCount,
			expectError: false,
		},
		{
			name:        "custom valid value",
			envValue:    "524288",
			expected:    524288,
			expectError: false,
		},
		{
			name:        "minimum valid value",
			envValue:    "65530",
			expected:    65530,
			expectError: false,
		},
		{
			name:        "invalid - too low",
			envValue:    "1000",
			expected:    0,
			expectError: true,
		},
		{
			name:        "invalid - not a number",
			envValue:    "abc",
			expected:    0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset state before each test
			Reset()

			// Set environment variable
			if tt.envValue != "" {
				t.Setenv(EnvVMMaxMapCount, tt.envValue)
			} else {
				os.Unsetenv(EnvVMMaxMapCount)
			}

			err := Initialize()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if VMMaxMapCount() != tt.expected {
				t.Errorf("VMMaxMapCount() = %d, want %d", VMMaxMapCount(), tt.expected)
			}
		})
	}
}

func TestInitializeWithValues(t *testing.T) {
	tests := []struct {
		name        string
		value       int
		expectError bool
	}{
		{
			name:        "valid value",
			value:       262144,
			expectError: false,
		},
		{
			name:        "minimum valid",
			value:       65530,
			expectError: false,
		},
		{
			name:        "too low",
			value:       1000,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Reset()

			err := InitializeWithValues(tt.value)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if VMMaxMapCount() != tt.value {
				t.Errorf("VMMaxMapCount() = %d, want %d", VMMaxMapCount(), tt.value)
			}
		})
	}
}

func TestIsInitialized(t *testing.T) {
	Reset()

	if IsInitialized() {
		t.Error("expected not initialized after Reset()")
	}

	_ = Initialize()

	if !IsInitialized() {
		t.Error("expected initialized after Initialize()")
	}
}

func TestVMMaxMapCountDefault(t *testing.T) {
	Reset()
	os.Unsetenv(EnvVMMaxMapCount)

	// VMMaxMapCount should return default even without initialization
	val := VMMaxMapCount()
	if val != constants.DefaultVMMaxMapCount {
		t.Errorf("VMMaxMapCount() = %d, want %d", val, constants.DefaultVMMaxMapCount)
	}
}
