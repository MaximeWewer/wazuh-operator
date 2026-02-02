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

// Package telemetry provides OpenTelemetry tracing integration for the wazuh-operator
package telemetry

import (
	"os"
	"strings"
)

// Config holds OpenTelemetry configuration
type Config struct {
	// Endpoint is the OTLP exporter endpoint (e.g., "localhost:4317")
	// If empty, tracing is disabled
	Endpoint string

	// Insecure determines whether to use insecure connection
	Insecure bool

	// ServiceName is the name of the service in traces
	ServiceName string

	// ServiceVersion is the version of the service
	ServiceVersion string
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() Config {
	config := Config{
		Endpoint:       os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		ServiceName:    os.Getenv("OTEL_SERVICE_NAME"),
		ServiceVersion: os.Getenv("OTEL_SERVICE_VERSION"),
	}

	// Default service name
	if config.ServiceName == "" {
		config.ServiceName = "wazuh-operator"
	}

	// Default version
	if config.ServiceVersion == "" {
		config.ServiceVersion = "0.1.0"
	}

	// Check for insecure flag
	insecure := os.Getenv("OTEL_EXPORTER_OTLP_INSECURE")
	config.Insecure = strings.EqualFold(insecure, "true") || insecure == "1"

	return config
}

// IsEnabled returns true if tracing is configured
func (c Config) IsEnabled() bool {
	return c.Endpoint != ""
}
