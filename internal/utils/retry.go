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

// Package utils provides shared utilities for the Wazuh Operator
package utils

import (
	"context"
	"fmt"
	"math"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Local constants to avoid import cycle with pkg/constants
const (
	retryInitialInterval = 1 * time.Second
	retryMaxInterval     = 30 * time.Second
)

// RetryConfig configures retry behavior
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts
	MaxRetries int

	// InitialInterval is the initial wait time between retries
	InitialInterval time.Duration

	// MaxInterval is the maximum wait time between retries
	MaxInterval time.Duration

	// Multiplier is the factor by which the interval increases
	Multiplier float64

	// Jitter adds randomness to prevent thundering herd
	Jitter bool
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      5,
		InitialInterval: retryInitialInterval,
		MaxInterval:     retryMaxInterval,
		Multiplier:      2.0,
		Jitter:          true,
	}
}

// RetryWithBackoff executes the given function with exponential backoff
func RetryWithBackoff(ctx context.Context, config RetryConfig, fn func() error) error {
	var lastErr error
	interval := config.InitialInterval

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Don't wait after the last attempt
		if attempt == config.MaxRetries {
			break
		}

		// Calculate next interval with exponential backoff
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
			// Calculate next interval
			nextInterval := time.Duration(float64(interval) * config.Multiplier)
			if nextInterval > config.MaxInterval {
				nextInterval = config.MaxInterval
			}
			interval = nextInterval
		}
	}

	return lastErr
}

// Retry executes the given function with default retry configuration
func Retry(ctx context.Context, fn func() error) error {
	return RetryWithBackoff(ctx, DefaultRetryConfig(), fn)
}

// RetryWithResult executes a function that returns a value with exponential backoff
func RetryWithResult[T any](ctx context.Context, config RetryConfig, fn func() (T, error)) (T, error) {
	var zero T
	var lastErr error
	interval := config.InitialInterval

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		lastErr = err

		// Don't wait after the last attempt
		if attempt == config.MaxRetries {
			break
		}

		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(interval):
			nextInterval := time.Duration(float64(interval) * config.Multiplier)
			if nextInterval > config.MaxInterval {
				nextInterval = config.MaxInterval
			}
			interval = nextInterval
		}
	}

	return zero, lastErr
}

// CalculateBackoff calculates the backoff duration for a given attempt
func CalculateBackoff(attempt int, config RetryConfig) time.Duration {
	backoff := float64(config.InitialInterval) * math.Pow(config.Multiplier, float64(attempt))
	if time.Duration(backoff) > config.MaxInterval {
		return config.MaxInterval
	}
	return time.Duration(backoff)
}

// IsRetryable checks if an error is retryable
type RetryableError interface {
	IsRetryable() bool
}

// ShouldRetry checks if an error should be retried
func ShouldRetry(err error) bool {
	if err == nil {
		return false
	}
	if retryable, ok := err.(RetryableError); ok {
		return retryable.IsRetryable()
	}
	// By default, retry all errors
	return true
}

// IsRetryableKubernetesError checks if a Kubernetes API error is retryable
func IsRetryableKubernetesError(err error) bool {
	if err == nil {
		return false
	}
	// Conflict errors (optimistic locking) are retryable
	if errors.IsConflict(err) {
		return true
	}
	// AlreadyExists errors are retryable in createOrUpdate patterns
	// (resource was created between our check and create attempt)
	if errors.IsAlreadyExists(err) {
		return true
	}
	// Server timeout errors are retryable
	if errors.IsServerTimeout(err) {
		return true
	}
	// Too many requests (rate limiting) are retryable
	if errors.IsTooManyRequests(err) {
		return true
	}
	// Service unavailable is retryable
	if errors.IsServiceUnavailable(err) {
		return true
	}
	// Internal server errors may be transient
	if errors.IsInternalError(err) {
		return true
	}
	return false
}

// ConflictRetryConfig returns a retry configuration optimized for conflict errors
func ConflictRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      3,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
	}
}

// RetryOnConflict executes a function that may encounter optimistic locking conflicts
// It automatically retries on conflict errors with exponential backoff
func RetryOnConflict(ctx context.Context, fn func() error) error {
	return RetryOnConflictWithConfig(ctx, ConflictRetryConfig(), fn)
}

// RetryOnConflictWithConfig executes a function with custom retry configuration
func RetryOnConflictWithConfig(ctx context.Context, config RetryConfig, fn func() error) error {
	log := logf.FromContext(ctx)
	var lastErr error
	interval := config.InitialInterval

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Only retry on retryable errors
		if !IsRetryableKubernetesError(lastErr) {
			return lastErr
		}

		// Don't wait after the last attempt
		if attempt == config.MaxRetries {
			break
		}

		log.V(1).Info("Retrying after conflict",
			"attempt", attempt+1,
			"maxRetries", config.MaxRetries,
			"interval", interval,
			"error", lastErr.Error())

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
			nextInterval := time.Duration(float64(interval) * config.Multiplier)
			if nextInterval > config.MaxInterval {
				nextInterval = config.MaxInterval
			}
			interval = nextInterval
		}
	}

	return fmt.Errorf("max retries (%d) exceeded: %w", config.MaxRetries, lastErr)
}

// RetryOnConflictWithResult executes a function that returns a value with conflict retry
func RetryOnConflictWithResult[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	return RetryOnConflictWithResultAndConfig(ctx, ConflictRetryConfig(), fn)
}

// RetryOnConflictWithResultAndConfig executes a function with custom config that returns a value
func RetryOnConflictWithResultAndConfig[T any](ctx context.Context, config RetryConfig, fn func() (T, error)) (T, error) {
	log := logf.FromContext(ctx)
	var zero T
	var lastErr error
	interval := config.InitialInterval

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		lastErr = err

		// Only retry on retryable errors
		if !IsRetryableKubernetesError(lastErr) {
			return zero, lastErr
		}

		// Don't wait after the last attempt
		if attempt == config.MaxRetries {
			break
		}

		log.V(1).Info("Retrying after conflict",
			"attempt", attempt+1,
			"maxRetries", config.MaxRetries,
			"interval", interval,
			"error", lastErr.Error())

		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(interval):
			nextInterval := time.Duration(float64(interval) * config.Multiplier)
			if nextInterval > config.MaxInterval {
				nextInterval = config.MaxInterval
			}
			interval = nextInterval
		}
	}

	return zero, fmt.Errorf("max retries (%d) exceeded: %w", config.MaxRetries, lastErr)
}

// RetryWithRefresh executes an update operation with automatic resource refresh on conflict
// The refreshFn should fetch the latest version of the resource
// The updateFn should apply changes and update the resource
func RetryWithRefresh[T any](ctx context.Context, refreshFn func() (T, error), updateFn func(T) error) error {
	return RetryOnConflict(ctx, func() error {
		obj, err := refreshFn()
		if err != nil {
			return err
		}
		return updateFn(obj)
	})
}
