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

package logging

import (
	"context"
	"os"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestLoadFromEnv(t *testing.T) {
	tests := []struct {
		name           string
		envFormat      string
		envLevel       string
		expectedFormat LogFormat
		expectedLevel  string
	}{
		{
			name:           "default values",
			envFormat:      "",
			envLevel:       "",
			expectedFormat: FormatJSON,
			expectedLevel:  "info",
		},
		{
			name:           "json format explicit",
			envFormat:      "json",
			envLevel:       "debug",
			expectedFormat: FormatJSON,
			expectedLevel:  "debug",
		},
		{
			name:           "console format",
			envFormat:      "console",
			envLevel:       "warn",
			expectedFormat: FormatConsole,
			expectedLevel:  "warn",
		},
		{
			name:           "case insensitive",
			envFormat:      "JSON",
			envLevel:       "ERROR",
			expectedFormat: FormatJSON,
			expectedLevel:  "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Setenv registers restoration of the original values (unset included)
			// when the subtest ends.
			t.Setenv(EnvLogFormat, os.Getenv(EnvLogFormat))
			t.Setenv(EnvLogLevel, os.Getenv(EnvLogLevel))

			// Set test env
			if tt.envFormat != "" {
				t.Setenv(EnvLogFormat, tt.envFormat)
			} else {
				os.Unsetenv(EnvLogFormat)
			}
			if tt.envLevel != "" {
				t.Setenv(EnvLogLevel, tt.envLevel)
			} else {
				os.Unsetenv(EnvLogLevel)
			}

			cfg := LoadFromEnv()

			if cfg.Format != tt.expectedFormat {
				t.Errorf("Format = %v, want %v", cfg.Format, tt.expectedFormat)
			}
			if cfg.Level != tt.expectedLevel {
				t.Errorf("Level = %v, want %v", cfg.Level, tt.expectedLevel)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Format != FormatJSON {
		t.Errorf("Default format should be JSON, got %v", cfg.Format)
	}
	if cfg.Level != "info" {
		t.Errorf("Default level should be info, got %v", cfg.Level)
	}
	if cfg.Development != false {
		t.Errorf("Default development should be false, got %v", cfg.Development)
	}
}

func TestWithTraceID(t *testing.T) {
	// Test without trace context
	ctx := context.Background()
	logger := WithTraceID(ctx)
	if logger.GetSink() == nil {
		t.Error("Logger should not be nil")
	}

	// Test with noop tracer (no trace context)
	otel.SetTracerProvider(noop.NewTracerProvider())
	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(ctx, "test-span")
	defer span.End()

	logger = WithTraceID(ctx)
	if logger.GetSink() == nil {
		t.Error("Logger with trace context should not be nil")
	}
}

func TestWithCluster(t *testing.T) {
	ctx := context.Background()
	logger := WithCluster(ctx, "test-cluster", "test-namespace")

	if logger.GetSink() == nil {
		t.Error("Logger should not be nil")
	}
}

func TestWithComponent(t *testing.T) {
	ctx := context.Background()
	logger := WithComponent(ctx, "indexer")

	if logger.GetSink() == nil {
		t.Error("Logger should not be nil")
	}
}

func TestWithReconcileContext(t *testing.T) {
	ctx := context.Background()
	logger := WithReconcileContext(ctx, "WazuhCluster", "my-cluster", "wazuh")

	if logger.GetSink() == nil {
		t.Error("Logger should not be nil")
	}
}
