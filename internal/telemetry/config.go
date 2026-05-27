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
	"strconv"
	"strings"
)

// Config holds OpenTelemetry configuration
type Config struct {
	// Endpoint is the OTLP exporter endpoint. Accepts both "host:port" and a
	// full URL with scheme ("http://host:4318", "https://host:4317").
	// If empty, tracing is disabled.
	Endpoint string

	// Protocol selects the OTLP transport: "grpc" (default) or "http".
	// Accepts the standard values "grpc", "http/protobuf" and "http".
	Protocol string

	// Insecure determines whether to use a plaintext (no TLS) connection.
	Insecure bool

	// CACertPath is an optional path to a PEM CA bundle used to verify the
	// collector certificate when Insecure is false.
	CACertPath string

	// Headers are extra headers sent with every OTLP export (e.g. auth tokens).
	Headers map[string]string

	// ServiceName is the name of the service in traces
	ServiceName string

	// ServiceVersion is the version of the service
	ServiceVersion string

	// Sampler is the standard OTEL_TRACES_SAMPLER value (e.g. "always_on",
	// "parentbased_traceidratio"). Empty defaults to parent-based ratio.
	Sampler string

	// SamplingRatio is the trace sampling ratio (0.0-1.0) used by ratio samplers.
	SamplingRatio float64
}

// LoadFromEnv loads configuration from the standard OTEL_* environment variables.
func LoadFromEnv() Config {
	config := Config{
		Endpoint:       firstNonEmpty(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
		ServiceName:    os.Getenv("OTEL_SERVICE_NAME"),
		ServiceVersion: os.Getenv("OTEL_SERVICE_VERSION"),
		CACertPath:     firstNonEmpty(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE"), os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE")),
		Sampler:        strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER"))),
		Headers:        parseHeaders(firstNonEmpty(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS"), os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))),
	}

	// Protocol: grpc (default) or http. Normalize the standard spec values.
	switch strings.ToLower(strings.TrimSpace(firstNonEmpty(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"), os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")))) {
	case "http", "http/protobuf", "http/json":
		config.Protocol = "http"
	default:
		config.Protocol = "grpc"
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

	// Parse sampling ratio (default 1.0 = sample all)
	config.SamplingRatio = 1.0
	if samplerArg := os.Getenv("OTEL_TRACES_SAMPLER_ARG"); samplerArg != "" {
		if ratio, err := strconv.ParseFloat(samplerArg, 64); err == nil && ratio >= 0 && ratio <= 1.0 {
			config.SamplingRatio = ratio
		}
	}

	return config
}

// IsEnabled returns true if tracing is configured
func (c Config) IsEnabled() bool {
	return c.Endpoint != ""
}

// parseHeaders parses the W3C Baggage-style header list used by
// OTEL_EXPORTER_OTLP_HEADERS, e.g. "api-key=secret,x-tenant=acme".
func parseHeaders(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	headers := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		if key != "" {
			headers[key] = val
		}
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
