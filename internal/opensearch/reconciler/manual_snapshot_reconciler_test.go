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
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestManualSnapshotReconciler_generateSnapshotName(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewManualSnapshotReconciler(client, scheme)

	tests := []struct {
		name     string
		baseName string
	}{
		{
			name:     "simple base name",
			baseName: "my-snapshot",
		},
		{
			name:     "base name with dashes",
			baseName: "daily-backup-prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.generateSnapshotName(tt.baseName)

			// Must start with base name
			if !strings.HasPrefix(got, tt.baseName+"-") {
				t.Errorf("generateSnapshotName() = %v, expected prefix %v-", got, tt.baseName)
			}

			// Extract timestamp part
			timestamp := strings.TrimPrefix(got, tt.baseName+"-")

			// Verify timestamp format: YYYYMMDD-HHMMSS
			_, err := time.Parse("20060102-150405", timestamp)
			if err != nil {
				t.Errorf("generateSnapshotName() timestamp %q is not in expected format YYYYMMDD-HHMMSS: %v", timestamp, err)
			}
		})
	}
}

func TestManualSnapshotReconciler_generateSnapshotName_Uniqueness(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewManualSnapshotReconciler(client, scheme)

	// Generate two names with a small delay to verify they include timestamps
	name1 := r.generateSnapshotName("test")
	time.Sleep(time.Second)
	name2 := r.generateSnapshotName("test")

	// They should be different (different timestamps) unless called within the same second
	// At minimum, both should be valid
	if !strings.HasPrefix(name1, "test-") {
		t.Errorf("First name %q doesn't have expected prefix", name1)
	}
	if !strings.HasPrefix(name2, "test-") {
		t.Errorf("Second name %q doesn't have expected prefix", name2)
	}
	if name1 == name2 {
		t.Error("Expected different snapshot names when generated with delay")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{name: "zero bytes", bytes: 0, want: "0 B"},
		{name: "small bytes", bytes: 512, want: "512 B"},
		{name: "one KiB", bytes: 1024, want: "1.0 KiB"},
		{name: "one MiB", bytes: 1048576, want: "1.0 MiB"},
		{name: "one GiB", bytes: 1073741824, want: "1.0 GiB"},
		{name: "1.5 GiB", bytes: 1610612736, want: "1.5 GiB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatBytes(tt.bytes)
			if got != tt.want {
				t.Errorf("formatBytes(%d) = %v, want %v", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{name: "seconds only", duration: 45 * time.Second, want: "45s"},
		{name: "exact minutes", duration: 3 * time.Minute, want: "3m0s"},
		{name: "exact hours", duration: 2 * time.Hour, want: "2h0m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.duration)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %v, want %v", tt.duration, got, tt.want)
			}
		})
	}
}
