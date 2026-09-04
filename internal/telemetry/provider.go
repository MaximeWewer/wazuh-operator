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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/credentials"
)

// TracerName is the instrumentation name for the wazuh-operator
const TracerName = "wazuh-operator"

// InitProvider initializes the OpenTelemetry TracerProvider
// Returns nil TracerProvider if tracing is disabled (no endpoint configured)
func InitProvider(ctx context.Context, config Config) (*sdktrace.TracerProvider, error) {
	if !config.IsEnabled() {
		return nil, nil
	}

	exporter, err := buildExporter(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource with service information. resource.Default() also reads
	// OTEL_RESOURCE_ATTRIBUTES, so callers can inject k8s.pod.name / namespace.
	// Use a schemaless resource for the extra attributes so the merge never
	// conflicts with resource.Default()'s (SDK-version-dependent) schema URL.
	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion(config.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(buildSampler(config)),
	)

	// Set global TracerProvider and propagator
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, nil
}

// buildExporter creates an OTLP trace exporter for the configured protocol
// (gRPC by default, HTTP when Protocol=="http"), honoring endpoint scheme,
// headers, insecure mode and a custom CA bundle.
func buildExporter(ctx context.Context, config Config) (sdktrace.SpanExporter, error) {
	hasScheme := strings.Contains(config.Endpoint, "://")

	if config.Protocol == "http" {
		return buildHTTPExporter(ctx, config, hasScheme)
	}

	// gRPC (default)
	opts := []otlptracegrpc.Option{}
	if hasScheme {
		opts = append(opts, otlptracegrpc.WithEndpointURL(config.Endpoint))
	} else {
		opts = append(opts, otlptracegrpc.WithEndpoint(config.Endpoint))
	}
	if len(config.Headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(config.Headers))
	}
	if config.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	} else if config.CACertPath != "" {
		creds, err := credentials.NewClientTLSFromFile(config.CACertPath, "")
		if err != nil {
			return nil, fmt.Errorf("failed to load OTLP CA bundle %q: %w", config.CACertPath, err)
		}
		opts = append(opts, otlptracegrpc.WithTLSCredentials(creds))
	}
	return otlptracegrpc.New(ctx, opts...)
}

// buildHTTPExporter creates the OTLP/HTTP trace exporter.
func buildHTTPExporter(ctx context.Context, config Config, hasScheme bool) (sdktrace.SpanExporter, error) {
	opts := []otlptracehttp.Option{}
	if hasScheme {
		opts = append(opts, otlptracehttp.WithEndpointURL(config.Endpoint))
	} else {
		opts = append(opts, otlptracehttp.WithEndpoint(config.Endpoint))
	}
	if len(config.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(config.Headers))
	}
	if config.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	} else {
		tlsCfg, err := tlsConfigFromCA(config.CACertPath)
		if err != nil {
			return nil, err
		}
		if tlsCfg != nil {
			opts = append(opts, otlptracehttp.WithTLSClientConfig(tlsCfg))
		}
	}
	return otlptracehttp.New(ctx, opts...)
}

// tlsConfigFromCA builds a *tls.Config trusting the given PEM CA bundle.
// Returns nil (use system roots) when path is empty.
func tlsConfigFromCA(path string) (*tls.Config, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read OTLP CA bundle %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates found in OTLP CA bundle %q", path)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// buildSampler honors the standard OTEL_TRACES_SAMPLER value, falling back to a
// parent-based ratio sampler driven by SamplingRatio.
func buildSampler(config Config) sdktrace.Sampler {
	ratio := config.SamplingRatio
	switch config.Sampler {
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "traceidratio":
		return sdktrace.TraceIDRatioBased(ratio)
	case "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "parentbased_always_off":
		return sdktrace.ParentBased(sdktrace.NeverSample())
	case "parentbased_traceidratio":
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	default:
		switch {
		case ratio >= 1.0:
			return sdktrace.AlwaysSample()
		case ratio <= 0:
			return sdktrace.NeverSample()
		default:
			return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
		}
	}
}

// Shutdown gracefully shuts down the TracerProvider
func Shutdown(ctx context.Context, tp *sdktrace.TracerProvider) error {
	if tp == nil {
		return nil
	}
	return tp.Shutdown(ctx)
}

// Tracer returns a tracer instance for the wazuh-operator
func Tracer() trace.Tracer {
	return otel.Tracer(TracerName)
}

// WithAttributes returns a SpanStartOption that sets attributes on the span
func WithAttributes(attrs ...attribute.KeyValue) trace.SpanStartOption {
	return trace.WithAttributes(attrs...)
}

// RecordError records an error on the span and sets the status to error
func RecordError(span trace.Span, err error) {
	if err != nil && span != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}
