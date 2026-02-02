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

package reconciler

import (
	"testing"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestComputeClusterSettingsHash(t *testing.T) {
	tests := []struct {
		name     string
		settings *wazuhv1.ClusterSettingsSpec
		wantHash bool // true = expect non-empty hash, false = expect empty hash
	}{
		{
			name:     "nil settings returns empty hash",
			settings: nil,
			wantHash: false,
		},
		{
			name:     "empty settings returns empty hash",
			settings: &wazuhv1.ClusterSettingsSpec{},
			wantHash: false,
		},
		{
			name: "persistent settings only",
			settings: &wazuhv1.ClusterSettingsSpec{
				Persistent: map[string]string{
					"cluster.routing.allocation.enable": "all",
				},
			},
			wantHash: true,
		},
		{
			name: "transient settings only",
			settings: &wazuhv1.ClusterSettingsSpec{
				Transient: map[string]string{
					"indices.recovery.max_bytes_per_sec": "100mb",
				},
			},
			wantHash: true,
		},
		{
			name: "both persistent and transient settings",
			settings: &wazuhv1.ClusterSettingsSpec{
				Persistent: map[string]string{
					"cluster.routing.allocation.enable": "all",
				},
				Transient: map[string]string{
					"indices.recovery.max_bytes_per_sec": "100mb",
				},
			},
			wantHash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := computeClusterSettingsHash(tt.settings)
			if tt.wantHash && hash == "" {
				t.Error("computeClusterSettingsHash() returned empty hash, expected non-empty")
			}
			if !tt.wantHash && hash != "" {
				t.Errorf("computeClusterSettingsHash() returned %q, expected empty", hash)
			}
		})
	}
}

func TestComputeClusterSettingsHash_Deterministic(t *testing.T) {
	settings := &wazuhv1.ClusterSettingsSpec{
		Persistent: map[string]string{
			"cluster.routing.allocation.enable":                     "all",
			"indices.recovery.max_bytes_per_sec":                    "100mb",
			"cluster.routing.allocation.node_concurrent_recoveries": "4",
		},
		Transient: map[string]string{
			"cluster.routing.rebalance.enable": "none",
		},
	}

	// Compute hash multiple times
	hash1 := computeClusterSettingsHash(settings)
	hash2 := computeClusterSettingsHash(settings)
	hash3 := computeClusterSettingsHash(settings)

	if hash1 != hash2 || hash2 != hash3 {
		t.Errorf("computeClusterSettingsHash() not deterministic: %q, %q, %q", hash1, hash2, hash3)
	}
}

func TestComputeClusterSettingsHash_DifferentSettings(t *testing.T) {
	settings1 := &wazuhv1.ClusterSettingsSpec{
		Persistent: map[string]string{
			"cluster.routing.allocation.enable": "all",
		},
	}

	settings2 := &wazuhv1.ClusterSettingsSpec{
		Persistent: map[string]string{
			"cluster.routing.allocation.enable": "none",
		},
	}

	hash1 := computeClusterSettingsHash(settings1)
	hash2 := computeClusterSettingsHash(settings2)

	if hash1 == hash2 {
		t.Error("computeClusterSettingsHash() returned same hash for different settings")
	}
}

func TestComputeClusterSettingsHash_PersistentVsTransient(t *testing.T) {
	// Same key-value but in different sections should produce different hashes
	settings1 := &wazuhv1.ClusterSettingsSpec{
		Persistent: map[string]string{
			"cluster.routing.allocation.enable": "all",
		},
	}

	settings2 := &wazuhv1.ClusterSettingsSpec{
		Transient: map[string]string{
			"cluster.routing.allocation.enable": "all",
		},
	}

	hash1 := computeClusterSettingsHash(settings1)
	hash2 := computeClusterSettingsHash(settings2)

	if hash1 == hash2 {
		t.Error("computeClusterSettingsHash() returned same hash for persistent vs transient")
	}
}
