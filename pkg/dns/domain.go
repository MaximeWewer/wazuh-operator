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

// Package dns provides Kubernetes cluster DNS domain configuration and FQDN generation.
// It centralizes all DNS-related functionality for the wazuh-operator, allowing
// the cluster domain to be configured via environment variable for clusters
// that use custom DNS domains instead of the standard "cluster.local".
package dns

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

const (
	// EnvClusterDomain is the environment variable for cluster domain configuration.
	// When set, overrides the default cluster domain.
	EnvClusterDomain = "KUBERNETES_CLUSTER_DOMAIN"

	// DefaultClusterDomain is the standard Kubernetes cluster DNS domain.
	DefaultClusterDomain = "cluster.local"
)

var (
	// clusterDomain holds the configured cluster domain.
	clusterDomain = DefaultClusterDomain

	// initialized tracks whether Initialize() has been called.
	initialized = false

	// mu protects concurrent access during initialization.
	mu sync.RWMutex

	// domainRegex validates DNS domain format per RFC 1123.
	// Allows: lowercase letters, digits, hyphens, dots.
	// Examples: cluster.local, svc.company.internal, k8s.prod.example.com
	domainRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// Initialize reads the cluster domain from environment and validates it.
// Must be called once at operator startup before any DNS functions are used.
// Returns error if domain format is invalid.
//
// The cluster domain is read from the KUBERNETES_CLUSTER_DOMAIN environment variable.
// If not set, defaults to "cluster.local".
func Initialize() error {
	mu.Lock()
	defer mu.Unlock()

	if initialized {
		return nil
	}

	domain := os.Getenv(EnvClusterDomain)
	if domain == "" {
		domain = DefaultClusterDomain
	}

	if err := ValidateDomain(domain); err != nil {
		return fmt.Errorf("invalid cluster domain %q: %w", domain, err)
	}

	clusterDomain = domain
	initialized = true

	return nil
}

// InitializeWithDomain initializes the DNS package with a specific domain.
// This is primarily useful for testing. In production, use Initialize().
func InitializeWithDomain(domain string) error {
	mu.Lock()
	defer mu.Unlock()

	if err := ValidateDomain(domain); err != nil {
		return fmt.Errorf("invalid cluster domain %q: %w", domain, err)
	}

	clusterDomain = domain
	initialized = true

	return nil
}

// Reset resets the DNS package to uninitialized state.
// This is primarily useful for testing.
func Reset() {
	mu.Lock()
	defer mu.Unlock()

	clusterDomain = DefaultClusterDomain
	initialized = false
}

// ValidateDomain checks if a domain string is valid per RFC 1123.
// Returns nil if valid, or an error describing the validation failure.
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain exceeds maximum length of 253 characters (got %d)", len(domain))
	}

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("domain must contain only lowercase letters, digits, hyphens, and dots, and must start and end with alphanumeric character")
	}

	// Check each label length (max 63 chars per RFC 1123)
	for label := range strings.SplitSeq(domain, ".") {
		if len(label) > 63 {
			return fmt.Errorf("domain label %q exceeds maximum length of 63 characters", label)
		}
		if label == "" {
			return fmt.Errorf("domain contains empty label (consecutive dots)")
		}
	}

	return nil
}

// IsInitialized returns whether the DNS package has been initialized.
func IsInitialized() bool {
	mu.RLock()
	defer mu.RUnlock()
	return initialized
}

// ClusterDomain returns the configured Kubernetes cluster domain.
// Panics if Initialize() has not been called.
func ClusterDomain() string {
	mu.RLock()
	defer mu.RUnlock()

	if !initialized {
		panic("dns.Initialize() must be called before using DNS functions")
	}

	return clusterDomain
}

// DNSSuffix returns the full DNS suffix including the svc prefix.
// Example: ".svc.cluster.local"
func DNSSuffix() string {
	return fmt.Sprintf(".svc.%s", ClusterDomain())
}

// ServiceFQDN returns the fully qualified domain name for a Kubernetes service.
// Format: <service>.<namespace>.svc.<cluster-domain>
//
// Example:
//
//	ServiceFQDN("my-service", "my-namespace") => "my-service.my-namespace.svc.cluster.local"
func ServiceFQDN(serviceName, namespace string) string {
	return fmt.Sprintf("%s.%s.svc.%s", serviceName, namespace, ClusterDomain())
}

// PodFQDN returns the FQDN for a pod in a headless service (StatefulSet).
// Format: <pod>.<service>.<namespace>.svc.<cluster-domain>
//
// Example:
//
//	PodFQDN("my-pod-0", "my-service", "my-namespace") => "my-pod-0.my-service.my-namespace.svc.cluster.local"
func PodFQDN(podName, serviceName, namespace string) string {
	return fmt.Sprintf("%s.%s.%s.svc.%s", podName, serviceName, namespace, ClusterDomain())
}

// HeadlessPodFQDN is an alias for PodFQDN for clarity in StatefulSet contexts.
// Format: <pod>.<headless-service>.<namespace>.svc.<cluster-domain>
func HeadlessPodFQDN(podName, headlessService, namespace string) string {
	return PodFQDN(podName, headlessService, namespace)
}

// WildcardServiceFQDN returns a wildcard FQDN for a service (useful for certificates).
// Format: *.<service>.<namespace>.svc.<cluster-domain>
//
// Example:
//
//	WildcardServiceFQDN("my-headless", "my-namespace") => "*.my-headless.my-namespace.svc.cluster.local"
func WildcardServiceFQDN(serviceName, namespace string) string {
	return fmt.Sprintf("*.%s.%s.svc.%s", serviceName, namespace, ClusterDomain())
}
