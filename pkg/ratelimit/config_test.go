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

package ratelimit

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("Enabled should be true by default")
	}
	if cfg.MaxConcurrentReconciles != DefaultMaxConcurrentReconciles {
		t.Errorf("MaxConcurrentReconciles = %d, want %d", cfg.MaxConcurrentReconciles, DefaultMaxConcurrentReconciles)
	}
	if cfg.BaseDelay != DefaultBaseDelay {
		t.Errorf("BaseDelay = %v, want %v", cfg.BaseDelay, DefaultBaseDelay)
	}
	if cfg.MaxDelay != DefaultMaxDelay {
		t.Errorf("MaxDelay = %v, want %v", cfg.MaxDelay, DefaultMaxDelay)
	}
	if cfg.QPS != DefaultQPS {
		t.Errorf("QPS = %f, want %f", cfg.QPS, DefaultQPS)
	}
	if cfg.Burst != DefaultBurst {
		t.Errorf("Burst = %d, want %d", cfg.Burst, DefaultBurst)
	}
}

func TestLoadFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		validate func(t *testing.T, cfg Config)
	}{
		{
			name:    "default values when env not set",
			envVars: map[string]string{},
			validate: func(t *testing.T, cfg Config) {
				if !cfg.Enabled {
					t.Error("Enabled should be true by default")
				}
			},
		},
		{
			name: "disabled rate limiting",
			envVars: map[string]string{
				EnvRateLimitEnabled: "false",
			},
			validate: func(t *testing.T, cfg Config) {
				if cfg.Enabled {
					t.Error("Enabled should be false")
				}
			},
		},
		{
			name: "custom max concurrent",
			envVars: map[string]string{
				EnvRateLimitMaxConcurrent: "5",
			},
			validate: func(t *testing.T, cfg Config) {
				if cfg.MaxConcurrentReconciles != 5 {
					t.Errorf("MaxConcurrentReconciles = %d, want 5", cfg.MaxConcurrentReconciles)
				}
			},
		},
		{
			name: "custom delays",
			envVars: map[string]string{
				EnvRateLimitBaseDelay: "10ms",
				EnvRateLimitMaxDelay:  "5m",
			},
			validate: func(t *testing.T, cfg Config) {
				if cfg.BaseDelay != 10*time.Millisecond {
					t.Errorf("BaseDelay = %v, want 10ms", cfg.BaseDelay)
				}
				if cfg.MaxDelay != 5*time.Minute {
					t.Errorf("MaxDelay = %v, want 5m", cfg.MaxDelay)
				}
			},
		},
		{
			name: "custom qps and burst",
			envVars: map[string]string{
				EnvRateLimitQPS:   "20.5",
				EnvRateLimitBurst: "200",
			},
			validate: func(t *testing.T, cfg Config) {
				if cfg.QPS != 20.5 {
					t.Errorf("QPS = %f, want 20.5", cfg.QPS)
				}
				if cfg.Burst != 200 {
					t.Errorf("Burst = %d, want 200", cfg.Burst)
				}
			},
		},
		{
			name: "invalid values fallback to defaults",
			envVars: map[string]string{
				EnvRateLimitMaxConcurrent: "invalid",
				EnvRateLimitQPS:           "not-a-number",
			},
			validate: func(t *testing.T, cfg Config) {
				if cfg.MaxConcurrentReconciles != DefaultMaxConcurrentReconciles {
					t.Errorf("MaxConcurrentReconciles should fallback to default")
				}
				if cfg.QPS != DefaultQPS {
					t.Errorf("QPS should fallback to default")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and clear env
			savedEnv := map[string]string{}
			envKeys := []string{
				EnvRateLimitEnabled,
				EnvRateLimitMaxConcurrent,
				EnvRateLimitBaseDelay,
				EnvRateLimitMaxDelay,
				EnvRateLimitQPS,
				EnvRateLimitBurst,
			}
			for _, key := range envKeys {
				savedEnv[key] = os.Getenv(key)
				os.Unsetenv(key)
			}
			defer func() {
				for key, val := range savedEnv {
					if val != "" {
						os.Setenv(key, val)
					} else {
						os.Unsetenv(key)
					}
				}
			}()

			// Set test env
			for key, val := range tt.envVars {
				os.Setenv(key, val)
			}

			// Reset global state
			initialized = false

			cfg := LoadFromEnv()
			tt.validate(t, cfg)
		})
	}
}

func TestNewRateLimiter(t *testing.T) {
	t.Run("enabled rate limiter", func(t *testing.T) {
		cfg := Config{
			Enabled:   true,
			BaseDelay: 5 * time.Millisecond,
			MaxDelay:  1 * time.Second,
			QPS:       10,
			Burst:     100,
		}

		limiter := cfg.NewRateLimiter()
		if limiter == nil {
			t.Error("Rate limiter should not be nil")
		}
	})

	t.Run("disabled rate limiter", func(t *testing.T) {
		cfg := Config{
			Enabled: false,
		}

		limiter := cfg.NewRateLimiter()
		if limiter == nil {
			t.Error("Rate limiter should not be nil even when disabled")
		}
	})
}

func TestGetConfig(t *testing.T) {
	// Reset global state
	initialized = false

	cfg := GetConfig()
	if !initialized {
		t.Error("GetConfig should initialize if not already done")
	}
	if cfg.MaxConcurrentReconciles == 0 {
		t.Error("Config should have valid values")
	}
}

func TestGetMaxConcurrentReconciles(t *testing.T) {
	// Reset and set custom value
	initialized = false
	os.Setenv(EnvRateLimitMaxConcurrent, "7")
	defer os.Unsetenv(EnvRateLimitMaxConcurrent)

	max := GetMaxConcurrentReconciles()
	if max != 7 {
		t.Errorf("GetMaxConcurrentReconciles = %d, want 7", max)
	}
}
