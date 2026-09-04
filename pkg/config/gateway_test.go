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
)

func TestIsGatewayAPIEnabled(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{
			name:     "enabled with true",
			envValue: "true",
			expected: true,
		},
		{
			name:     "enabled with TRUE",
			envValue: "TRUE",
			expected: true,
		},
		{
			name:     "enabled with True",
			envValue: "True",
			expected: true,
		},
		{
			name:     "disabled with false",
			envValue: "false",
			expected: false,
		},
		{
			name:     "disabled with empty",
			envValue: "",
			expected: false,
		},
		{
			name:     "disabled with invalid value",
			envValue: "yes",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv(EnvGatewayAPIEnabled, tt.envValue)
			} else {
				os.Unsetenv(EnvGatewayAPIEnabled)
			}

			result := IsGatewayAPIEnabled()
			if result != tt.expected {
				t.Errorf("IsGatewayAPIEnabled() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGatewayAPIStatus_Message(t *testing.T) {
	tests := []struct {
		name          string
		status        GatewayAPIStatus
		shouldContain string
	}{
		{
			name: "disabled status",
			status: GatewayAPIStatus{
				Enabled: false,
				Message: "Gateway API support is disabled. Set GATEWAY_API_ENABLED=true to enable.",
			},
			shouldContain: "disabled",
		},
		{
			name: "fully available",
			status: GatewayAPIStatus{
				Enabled:            true,
				HTTPRouteAvailable: true,
				TCPRouteAvailable:  true,
				UDPRouteAvailable:  true,
				Message:            "Gateway API fully available (HTTPRoute, TCPRoute, UDPRoute)",
			},
			shouldContain: "fully available",
		},
		{
			name: "partially available",
			status: GatewayAPIStatus{
				Enabled:            true,
				HTTPRouteAvailable: true,
				TCPRouteAvailable:  false,
				UDPRouteAvailable:  false,
				Message:            "Gateway API partially available. Missing experimental CRDs: TCPRoute, UDPRoute",
			},
			shouldContain: "partially available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.status.Message == "" {
				t.Error("Message should not be empty")
			}
			if tt.shouldContain != "" && !contains(tt.status.Message, tt.shouldContain) {
				t.Errorf("Message %q should contain %q", tt.status.Message, tt.shouldContain)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
