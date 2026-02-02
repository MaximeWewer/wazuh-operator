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

// Package config provides runtime configuration for the wazuh-operator.
// It centralizes configuration that can be set via environment variables
// and provides thread-safe access to these values.
package config

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// EnvVMMaxMapCount is the environment variable for vm.max_map_count configuration.
	// When set, overrides the default value used by the indexer init container.
	EnvVMMaxMapCount = "VM_MAX_MAP_COUNT"
)

var (
	// vmMaxMapCount holds the configured vm.max_map_count value.
	vmMaxMapCount = constants.DefaultVMMaxMapCount

	// initialized tracks whether Initialize() has been called.
	initialized = false

	// mu protects concurrent access during initialization.
	mu sync.RWMutex
)

// Initialize reads configuration from environment variables.
// Must be called once at operator startup.
// Returns error if any configuration value is invalid.
func Initialize() error {
	mu.Lock()
	defer mu.Unlock()

	if initialized {
		return nil
	}

	// Read vm.max_map_count from environment
	if val := os.Getenv(EnvVMMaxMapCount); val != "" {
		parsed, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("invalid %s value %q: must be an integer", EnvVMMaxMapCount, val)
		}
		if parsed < 65530 {
			return fmt.Errorf("invalid %s value %d: must be at least 65530 (Linux default)", EnvVMMaxMapCount, parsed)
		}
		vmMaxMapCount = parsed
	}

	initialized = true
	return nil
}

// InitializeWithValues initializes the config package with specific values.
// This is primarily useful for testing.
func InitializeWithValues(vmMaxMap int) error {
	mu.Lock()
	defer mu.Unlock()

	if vmMaxMap < 65530 {
		return fmt.Errorf("invalid vm.max_map_count value %d: must be at least 65530", vmMaxMap)
	}

	vmMaxMapCount = vmMaxMap
	initialized = true
	return nil
}

// Reset resets the config package to uninitialized state.
// This is primarily useful for testing.
func Reset() {
	mu.Lock()
	defer mu.Unlock()

	vmMaxMapCount = constants.DefaultVMMaxMapCount
	initialized = false
}

// IsInitialized returns whether the config package has been initialized.
func IsInitialized() bool {
	mu.RLock()
	defer mu.RUnlock()
	return initialized
}

// VMMaxMapCount returns the configured vm.max_map_count value for OpenSearch.
// Returns the default value if Initialize() has not been called.
func VMMaxMapCount() int {
	mu.RLock()
	defer mu.RUnlock()
	return vmMaxMapCount
}
