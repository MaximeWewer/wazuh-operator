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

package telemetry

import (
	"context"
	"os"
	"testing"
)

func TestLoadFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected Config
	}{
		{
			name:    "default values when no env vars set",
			envVars: map[string]string{},
			expected: Config{
				Endpoint:       "",
				Insecure:       false,
				ServiceName:    "wazuh-operator",
				ServiceVersion: "0.1.0",
				SamplingRatio:  1.0,
			},
		},
		{
			name: "all env vars set",
			envVars: map[string]string{
				"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:4317",
				"OTEL_EXPORTER_OTLP_INSECURE": "true",
				"OTEL_SERVICE_NAME":           "test-operator",
				"OTEL_SERVICE_VERSION":        "1.0.0",
				"OTEL_TRACES_SAMPLER_ARG":     "0.5",
			},
			expected: Config{
				Endpoint:       "localhost:4317",
				Insecure:       true,
				ServiceName:    "test-operator",
				ServiceVersion: "1.0.0",
				SamplingRatio:  0.5,
			},
		},
		{
			name: "insecure with 1",
			envVars: map[string]string{
				"OTEL_EXPORTER_OTLP_INSECURE": "1",
			},
			expected: Config{
				Endpoint:       "",
				Insecure:       true,
				ServiceName:    "wazuh-operator",
				ServiceVersion: "0.1.0",
				SamplingRatio:  1.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear relevant env vars
			os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
			os.Unsetenv("OTEL_EXPORTER_OTLP_INSECURE")
			os.Unsetenv("OTEL_SERVICE_NAME")
			os.Unsetenv("OTEL_SERVICE_VERSION")
			os.Unsetenv("OTEL_TRACES_SAMPLER_ARG")

			// Set test env vars (t.Setenv restores them when the subtest ends)
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			config := LoadFromEnv()

			if config.Endpoint != tt.expected.Endpoint {
				t.Errorf("Endpoint = %v, want %v", config.Endpoint, tt.expected.Endpoint)
			}
			if config.Insecure != tt.expected.Insecure {
				t.Errorf("Insecure = %v, want %v", config.Insecure, tt.expected.Insecure)
			}
			if config.ServiceName != tt.expected.ServiceName {
				t.Errorf("ServiceName = %v, want %v", config.ServiceName, tt.expected.ServiceName)
			}
			if config.ServiceVersion != tt.expected.ServiceVersion {
				t.Errorf("ServiceVersion = %v, want %v", config.ServiceVersion, tt.expected.ServiceVersion)
			}
			if config.SamplingRatio != tt.expected.SamplingRatio {
				t.Errorf("SamplingRatio = %v, want %v", config.SamplingRatio, tt.expected.SamplingRatio)
			}
		})
	}
}

func TestConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected bool
	}{
		{
			name:     "disabled when endpoint is empty",
			config:   Config{Endpoint: ""},
			expected: false,
		},
		{
			name:     "enabled when endpoint is set",
			config:   Config{Endpoint: "localhost:4317"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsEnabled(); got != tt.expected {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInitProvider_Disabled(t *testing.T) {
	config := Config{Endpoint: ""}

	tp, err := InitProvider(context.Background(), config)
	if err != nil {
		t.Errorf("InitProvider() error = %v, want nil", err)
	}
	if tp != nil {
		t.Errorf("InitProvider() = %v, want nil", tp)
	}
}

func TestShutdown_NilProvider(t *testing.T) {
	err := Shutdown(context.Background(), nil)
	if err != nil {
		t.Errorf("Shutdown(nil) error = %v, want nil", err)
	}
}

func TestTracer(t *testing.T) {
	tracer := Tracer()
	if tracer == nil {
		t.Error("Tracer() returned nil")
	}
}

func TestSamplingRatioParsing(t *testing.T) {
	tests := []struct {
		name          string
		envValue      string
		expectedRatio float64
	}{
		{
			name:          "absent defaults to 1.0",
			envValue:      "",
			expectedRatio: 1.0,
		},
		{
			name:          "zero value",
			envValue:      "0.0",
			expectedRatio: 0.0,
		},
		{
			name:          "half sampling",
			envValue:      "0.5",
			expectedRatio: 0.5,
		},
		{
			name:          "full sampling",
			envValue:      "1.0",
			expectedRatio: 1.0,
		},
		{
			name:          "invalid value defaults to 1.0",
			envValue:      "invalid",
			expectedRatio: 1.0,
		},
		{
			name:          "negative value defaults to 1.0",
			envValue:      "-0.5",
			expectedRatio: 1.0,
		},
		{
			name:          "value over 1.0 defaults to 1.0",
			envValue:      "2.0",
			expectedRatio: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all env vars
			os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
			os.Unsetenv("OTEL_EXPORTER_OTLP_INSECURE")
			os.Unsetenv("OTEL_SERVICE_NAME")
			os.Unsetenv("OTEL_SERVICE_VERSION")
			os.Unsetenv("OTEL_TRACES_SAMPLER_ARG")

			if tt.envValue != "" {
				t.Setenv("OTEL_TRACES_SAMPLER_ARG", tt.envValue)
			}

			config := LoadFromEnv()
			if config.SamplingRatio != tt.expectedRatio {
				t.Errorf("SamplingRatio = %v, want %v", config.SamplingRatio, tt.expectedRatio)
			}
		})
	}
}
