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

package dns

import (
	"os"
	"strings"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
		errMsg  string
	}{
		// Valid domains
		{
			name:    "valid default cluster.local",
			domain:  "cluster.local",
			wantErr: false,
		},
		{
			name:    "valid corporate domain",
			domain:  "svc.company.internal",
			wantErr: false,
		},
		{
			name:    "valid multi-level domain",
			domain:  "k8s.prod.example.com",
			wantErr: false,
		},
		{
			name:    "valid single label",
			domain:  "local",
			wantErr: false,
		},
		{
			name:    "valid with numbers",
			domain:  "cluster1.local",
			wantErr: false,
		},
		{
			name:    "valid with hyphens",
			domain:  "my-cluster.my-domain.local",
			wantErr: false,
		},
		{
			name:    "valid alphanumeric only",
			domain:  "abc123.xyz789",
			wantErr: false,
		},

		// Invalid domains
		{
			name:    "invalid empty",
			domain:  "",
			wantErr: true,
			errMsg:  "cannot be empty",
		},
		{
			name:    "invalid uppercase",
			domain:  "CLUSTER.LOCAL",
			wantErr: true,
			errMsg:  "lowercase",
		},
		{
			name:    "invalid mixed case",
			domain:  "Cluster.Local",
			wantErr: true,
			errMsg:  "lowercase",
		},
		{
			name:    "invalid consecutive dots",
			domain:  "cluster..local",
			wantErr: true,
			errMsg:  "start and end with alphanumeric",
		},
		{
			name:    "invalid starts with hyphen",
			domain:  "-cluster.local",
			wantErr: true,
			errMsg:  "start and end with alphanumeric",
		},
		{
			name:    "invalid ends with hyphen",
			domain:  "cluster-.local",
			wantErr: true,
			errMsg:  "start and end with alphanumeric",
		},
		{
			name:    "invalid starts with dot",
			domain:  ".cluster.local",
			wantErr: true,
			errMsg:  "start and end with alphanumeric",
		},
		{
			name:    "invalid ends with dot",
			domain:  "cluster.local.",
			wantErr: true,
			errMsg:  "start and end with alphanumeric",
		},
		{
			name:    "invalid contains underscore",
			domain:  "cluster_local",
			wantErr: true,
			errMsg:  "lowercase letters, digits, hyphens, and dots",
		},
		{
			name:    "invalid contains space",
			domain:  "cluster local",
			wantErr: true,
			errMsg:  "lowercase letters, digits, hyphens, and dots",
		},
		{
			name:    "invalid too long total",
			domain:  strings.Repeat("a", 254),
			wantErr: true,
			errMsg:  "exceeds maximum length of 253",
		},
		{
			name:    "invalid label too long",
			domain:  strings.Repeat("a", 64) + ".local",
			wantErr: true,
			errMsg:  "exceeds maximum length of 63",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateDomain(%q) error = %v, want error containing %q", tt.domain, err, tt.errMsg)
				}
			}
		})
	}
}

func TestInitialize(t *testing.T) {
	// Save original env and restore after test
	originalEnv := os.Getenv(EnvClusterDomain)
	defer func() {
		os.Setenv(EnvClusterDomain, originalEnv)
		Reset()
	}()

	t.Run("initialize with default domain", func(t *testing.T) {
		Reset()
		os.Unsetenv(EnvClusterDomain)

		err := Initialize()
		if err != nil {
			t.Errorf("Initialize() error = %v, want nil", err)
		}

		if got := ClusterDomain(); got != DefaultClusterDomain {
			t.Errorf("ClusterDomain() = %v, want %v", got, DefaultClusterDomain)
		}
	})

	t.Run("initialize with custom domain from env", func(t *testing.T) {
		Reset()
		customDomain := "custom.internal"
		os.Setenv(EnvClusterDomain, customDomain)

		err := Initialize()
		if err != nil {
			t.Errorf("Initialize() error = %v, want nil", err)
		}

		if got := ClusterDomain(); got != customDomain {
			t.Errorf("ClusterDomain() = %v, want %v", got, customDomain)
		}
	})

	t.Run("initialize with invalid domain from env", func(t *testing.T) {
		Reset()
		os.Setenv(EnvClusterDomain, "INVALID.DOMAIN")

		err := Initialize()
		if err == nil {
			t.Error("Initialize() error = nil, want error for invalid domain")
		}
	})

	t.Run("double initialization is no-op", func(t *testing.T) {
		Reset()
		os.Setenv(EnvClusterDomain, "first.domain")

		err := Initialize()
		if err != nil {
			t.Errorf("Initialize() first call error = %v", err)
		}

		// Change env and try to initialize again
		os.Setenv(EnvClusterDomain, "second.domain")
		err = Initialize()
		if err != nil {
			t.Errorf("Initialize() second call error = %v", err)
		}

		// Should still have first domain
		if got := ClusterDomain(); got != "first.domain" {
			t.Errorf("ClusterDomain() = %v, want first.domain (double init should be no-op)", got)
		}
	})
}

func TestInitializeWithDomain(t *testing.T) {
	defer Reset()

	t.Run("initialize with valid domain", func(t *testing.T) {
		Reset()
		domain := "test.custom.domain"

		err := InitializeWithDomain(domain)
		if err != nil {
			t.Errorf("InitializeWithDomain(%q) error = %v, want nil", domain, err)
		}

		if got := ClusterDomain(); got != domain {
			t.Errorf("ClusterDomain() = %v, want %v", got, domain)
		}
	})

	t.Run("initialize with invalid domain", func(t *testing.T) {
		Reset()
		domain := "INVALID"

		err := InitializeWithDomain(domain)
		if err == nil {
			t.Errorf("InitializeWithDomain(%q) error = nil, want error", domain)
		}
	})
}

func TestClusterDomainPanicsWithoutInit(t *testing.T) {
	Reset()

	defer func() {
		if r := recover(); r == nil {
			t.Error("ClusterDomain() did not panic without initialization")
		}
	}()

	_ = ClusterDomain()
}

func TestDNSSuffix(t *testing.T) {
	defer Reset()

	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{
			name:   "default domain",
			domain: "cluster.local",
			want:   ".svc.cluster.local",
		},
		{
			name:   "custom domain",
			domain: "custom.internal",
			want:   ".svc.custom.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Reset()
			if err := InitializeWithDomain(tt.domain); err != nil {
				t.Fatalf("InitializeWithDomain() error = %v", err)
			}

			if got := DNSSuffix(); got != tt.want {
				t.Errorf("DNSSuffix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceFQDN(t *testing.T) {
	defer Reset()

	tests := []struct {
		name        string
		domain      string
		serviceName string
		namespace   string
		want        string
	}{
		{
			name:        "default domain",
			domain:      "cluster.local",
			serviceName: "my-service",
			namespace:   "my-namespace",
			want:        "my-service.my-namespace.svc.cluster.local",
		},
		{
			name:        "custom domain",
			domain:      "k8s.company.internal",
			serviceName: "wazuh-indexer",
			namespace:   "wazuh",
			want:        "wazuh-indexer.wazuh.svc.k8s.company.internal",
		},
		{
			name:        "complex service name",
			domain:      "cluster.local",
			serviceName: "wazuh-manager-master",
			namespace:   "wazuh-system",
			want:        "wazuh-manager-master.wazuh-system.svc.cluster.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Reset()
			if err := InitializeWithDomain(tt.domain); err != nil {
				t.Fatalf("InitializeWithDomain() error = %v", err)
			}

			if got := ServiceFQDN(tt.serviceName, tt.namespace); got != tt.want {
				t.Errorf("ServiceFQDN(%q, %q) = %v, want %v", tt.serviceName, tt.namespace, got, tt.want)
			}
		})
	}
}

func TestPodFQDN(t *testing.T) {
	defer Reset()

	tests := []struct {
		name        string
		domain      string
		podName     string
		serviceName string
		namespace   string
		want        string
	}{
		{
			name:        "default domain",
			domain:      "cluster.local",
			podName:     "my-pod-0",
			serviceName: "my-service",
			namespace:   "my-namespace",
			want:        "my-pod-0.my-service.my-namespace.svc.cluster.local",
		},
		{
			name:        "custom domain with indexer pod",
			domain:      "k8s.company.internal",
			podName:     "wazuh-indexer-0",
			serviceName: "wazuh-indexer-headless",
			namespace:   "wazuh",
			want:        "wazuh-indexer-0.wazuh-indexer-headless.wazuh.svc.k8s.company.internal",
		},
		{
			name:        "manager pod",
			domain:      "cluster.local",
			podName:     "wazuh-manager-master-0",
			serviceName: "wazuh-manager-master",
			namespace:   "wazuh-system",
			want:        "wazuh-manager-master-0.wazuh-manager-master.wazuh-system.svc.cluster.local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Reset()
			if err := InitializeWithDomain(tt.domain); err != nil {
				t.Fatalf("InitializeWithDomain() error = %v", err)
			}

			if got := PodFQDN(tt.podName, tt.serviceName, tt.namespace); got != tt.want {
				t.Errorf("PodFQDN(%q, %q, %q) = %v, want %v", tt.podName, tt.serviceName, tt.namespace, got, tt.want)
			}
		})
	}
}

func TestHeadlessPodFQDN(t *testing.T) {
	defer Reset()

	// HeadlessPodFQDN is an alias for PodFQDN, verify they produce same output
	Reset()
	if err := InitializeWithDomain("cluster.local"); err != nil {
		t.Fatalf("InitializeWithDomain() error = %v", err)
	}

	podName := "wazuh-indexer-0"
	serviceName := "wazuh-indexer-headless"
	namespace := "wazuh"

	podFQDN := PodFQDN(podName, serviceName, namespace)
	headlessPodFQDN := HeadlessPodFQDN(podName, serviceName, namespace)

	if podFQDN != headlessPodFQDN {
		t.Errorf("HeadlessPodFQDN() = %v, PodFQDN() = %v, want them equal", headlessPodFQDN, podFQDN)
	}
}

func TestWildcardServiceFQDN(t *testing.T) {
	defer Reset()

	tests := []struct {
		name        string
		domain      string
		serviceName string
		namespace   string
		want        string
	}{
		{
			name:        "default domain",
			domain:      "cluster.local",
			serviceName: "my-headless",
			namespace:   "my-namespace",
			want:        "*.my-headless.my-namespace.svc.cluster.local",
		},
		{
			name:        "custom domain",
			domain:      "k8s.company.internal",
			serviceName: "wazuh-indexer-headless",
			namespace:   "wazuh",
			want:        "*.wazuh-indexer-headless.wazuh.svc.k8s.company.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Reset()
			if err := InitializeWithDomain(tt.domain); err != nil {
				t.Fatalf("InitializeWithDomain() error = %v", err)
			}

			if got := WildcardServiceFQDN(tt.serviceName, tt.namespace); got != tt.want {
				t.Errorf("WildcardServiceFQDN(%q, %q) = %v, want %v", tt.serviceName, tt.namespace, got, tt.want)
			}
		})
	}
}

func TestIsInitialized(t *testing.T) {
	Reset()

	if IsInitialized() {
		t.Error("IsInitialized() = true after Reset(), want false")
	}

	if err := InitializeWithDomain("cluster.local"); err != nil {
		t.Fatalf("InitializeWithDomain() error = %v", err)
	}

	if !IsInitialized() {
		t.Error("IsInitialized() = false after Initialize(), want true")
	}
}

func TestReset(t *testing.T) {
	if err := InitializeWithDomain("custom.domain"); err != nil {
		t.Fatalf("InitializeWithDomain() error = %v", err)
	}

	if !IsInitialized() {
		t.Error("IsInitialized() = false after Initialize(), want true")
	}

	Reset()

	if IsInitialized() {
		t.Error("IsInitialized() = true after Reset(), want false")
	}
}
