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

// Package ratelimit provides rate limiting configuration for Kubernetes controllers.
package ratelimit

import (
	"os"
	"strconv"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// Environment variables for rate limiting configuration
	EnvRateLimitEnabled            = "RATE_LIMIT_ENABLED"
	EnvRateLimitMaxConcurrent      = "RATE_LIMIT_MAX_CONCURRENT"
	EnvRateLimitBaseDelay          = "RATE_LIMIT_BASE_DELAY"
	EnvRateLimitMaxDelay           = "RATE_LIMIT_MAX_DELAY"
	EnvRateLimitQPS                = "RATE_LIMIT_QPS"
	EnvRateLimitBurst              = "RATE_LIMIT_BURST"

	// Default values
	DefaultMaxConcurrentReconciles = 3
	DefaultBaseDelay               = 5 * time.Millisecond
	DefaultMaxDelay                = 1000 * time.Second
	DefaultQPS                     = 10.0
	DefaultBurst                   = 100
)

// Config holds rate limiting configuration for controllers
type Config struct {
	// Enabled indicates if rate limiting is enabled
	Enabled bool

	// MaxConcurrentReconciles is the maximum number of concurrent Reconciles
	MaxConcurrentReconciles int

	// BaseDelay is the base delay for exponential backoff
	BaseDelay time.Duration

	// MaxDelay is the maximum delay for exponential backoff
	MaxDelay time.Duration

	// QPS is the queries per second limit for the bucket rate limiter
	QPS float64

	// Burst is the burst size for the bucket rate limiter
	Burst int
}

// DefaultConfig returns the default rate limiting configuration
func DefaultConfig() Config {
	return Config{
		Enabled:                 true,
		MaxConcurrentReconciles: DefaultMaxConcurrentReconciles,
		BaseDelay:               DefaultBaseDelay,
		MaxDelay:                DefaultMaxDelay,
		QPS:                     DefaultQPS,
		Burst:                   DefaultBurst,
	}
}

// LoadFromEnv loads rate limiting configuration from environment variables
func LoadFromEnv() Config {
	cfg := DefaultConfig()

	if enabled := os.Getenv(EnvRateLimitEnabled); enabled != "" {
		cfg.Enabled = enabled == "true" || enabled == "1"
	}

	if maxConcurrent := os.Getenv(EnvRateLimitMaxConcurrent); maxConcurrent != "" {
		if val, err := strconv.Atoi(maxConcurrent); err == nil && val > 0 {
			cfg.MaxConcurrentReconciles = val
		}
	}

	if baseDelay := os.Getenv(EnvRateLimitBaseDelay); baseDelay != "" {
		if val, err := time.ParseDuration(baseDelay); err == nil {
			cfg.BaseDelay = val
		}
	}

	if maxDelay := os.Getenv(EnvRateLimitMaxDelay); maxDelay != "" {
		if val, err := time.ParseDuration(maxDelay); err == nil {
			cfg.MaxDelay = val
		}
	}

	if qps := os.Getenv(EnvRateLimitQPS); qps != "" {
		if val, err := strconv.ParseFloat(qps, 64); err == nil && val > 0 {
			cfg.QPS = val
		}
	}

	if burst := os.Getenv(EnvRateLimitBurst); burst != "" {
		if val, err := strconv.Atoi(burst); err == nil && val > 0 {
			cfg.Burst = val
		}
	}

	return cfg
}

// NewRateLimiter creates a new rate limiter based on the configuration.
// It combines exponential backoff with a bucket rate limiter.
func (c Config) NewRateLimiter() workqueue.TypedRateLimiter[reconcile.Request] {
	if !c.Enabled {
		// Return a no-op rate limiter that allows everything
		return workqueue.NewTypedMaxOfRateLimiter[reconcile.Request]()
	}

	return workqueue.NewTypedMaxOfRateLimiter[reconcile.Request](
		// Exponential backoff rate limiter for failed items
		workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](
			c.BaseDelay,
			c.MaxDelay,
		),
		// Overall rate limiter to prevent API server overload
		&workqueue.TypedBucketRateLimiter[reconcile.Request]{
			Limiter: rate.NewLimiter(rate.Limit(c.QPS), c.Burst),
		},
	)
}

// Global configuration instance
var globalConfig = DefaultConfig()
var initialized = false

// Initialize loads the global rate limiting configuration from environment
func Initialize() {
	globalConfig = LoadFromEnv()
	initialized = true
}

// GetConfig returns the global rate limiting configuration.
// If not initialized, it loads from environment first.
func GetConfig() Config {
	if !initialized {
		Initialize()
	}
	return globalConfig
}

// GetRateLimiter returns a new rate limiter using the global configuration
func GetRateLimiter() workqueue.TypedRateLimiter[reconcile.Request] {
	return GetConfig().NewRateLimiter()
}

// GetMaxConcurrentReconciles returns the configured max concurrent reconciles
func GetMaxConcurrentReconciles() int {
	return GetConfig().MaxConcurrentReconciles
}
