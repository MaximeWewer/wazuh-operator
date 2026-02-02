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

// Package logging provides structured logging utilities with OpenTelemetry trace correlation.
package logging

import (
	"context"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap/zapcore"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	// Environment variables for logging configuration
	EnvLogFormat = "LOG_FORMAT" // json or console
	EnvLogLevel  = "LOG_LEVEL"  // debug, info, warn, error
)

// LogFormat represents the output format for logs
type LogFormat string

const (
	// FormatJSON outputs logs in JSON format (recommended for production)
	FormatJSON LogFormat = "json"
	// FormatConsole outputs logs in human-readable console format
	FormatConsole LogFormat = "console"
)

// Config holds logging configuration
type Config struct {
	// Format is the log output format (json or console)
	Format LogFormat
	// Level is the minimum log level (debug, info, warn, error)
	Level string
	// Development enables development mode with more verbose output
	Development bool
}

// DefaultConfig returns the default logging configuration
func DefaultConfig() Config {
	return Config{
		Format:      FormatJSON,
		Level:       "info",
		Development: false,
	}
}

// LoadFromEnv loads logging configuration from environment variables
func LoadFromEnv() Config {
	cfg := DefaultConfig()

	if format := os.Getenv(EnvLogFormat); format != "" {
		switch strings.ToLower(format) {
		case "json":
			cfg.Format = FormatJSON
		case "console":
			cfg.Format = FormatConsole
		}
	}

	if level := os.Getenv(EnvLogLevel); level != "" {
		cfg.Level = strings.ToLower(level)
	}

	return cfg
}

// SetupLogger configures the global logger based on the provided configuration
func SetupLogger(cfg Config) {
	var encoder zapcore.Encoder
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	if cfg.Format == FormatJSON {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Parse log level
	var level zapcore.Level
	switch cfg.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn", "warning":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	opts := zap.Options{
		Development: cfg.Development,
		Encoder:     encoder,
		Level:       level,
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
}

// WithTraceID returns a logger enriched with OpenTelemetry trace context.
// If the context contains a valid trace span, trace_id and span_id are added.
func WithTraceID(ctx context.Context) logr.Logger {
	logger := log.FromContext(ctx)

	span := trace.SpanFromContext(ctx)
	if span != nil && span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		logger = logger.WithValues(
			"trace_id", spanCtx.TraceID().String(),
			"span_id", spanCtx.SpanID().String(),
		)
		if spanCtx.IsSampled() {
			logger = logger.WithValues("trace_sampled", true)
		}
	}

	return logger
}

// WithCluster returns a logger enriched with cluster context information.
func WithCluster(ctx context.Context, clusterName, namespace string) logr.Logger {
	logger := WithTraceID(ctx)
	return logger.WithValues(
		"cluster", clusterName,
		"namespace", namespace,
	)
}

// WithComponent returns a logger enriched with component information.
func WithComponent(ctx context.Context, component string) logr.Logger {
	logger := WithTraceID(ctx)
	return logger.WithValues("component", component)
}

// WithReconcileContext returns a logger with full reconciliation context.
func WithReconcileContext(ctx context.Context, crd, name, namespace string) logr.Logger {
	logger := WithTraceID(ctx)
	return logger.WithValues(
		"crd", crd,
		"name", name,
		"namespace", namespace,
	)
}

// Info logs an info message with trace context
func Info(ctx context.Context, msg string, keysAndValues ...interface{}) {
	WithTraceID(ctx).Info(msg, keysAndValues...)
}

// Error logs an error message with trace context
func Error(ctx context.Context, err error, msg string, keysAndValues ...interface{}) {
	WithTraceID(ctx).Error(err, msg, keysAndValues...)
}

// Debug logs a debug message with trace context (V(1) level)
func Debug(ctx context.Context, msg string, keysAndValues ...interface{}) {
	WithTraceID(ctx).V(1).Info(msg, keysAndValues...)
}
