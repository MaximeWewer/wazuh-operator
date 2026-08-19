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

package v1

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestValidateManagerVolumeClaims(t *testing.T) {
	block := "block"
	tests := []struct {
		name     string
		vcs      []ManagerVolumeClaim
		wantErr  bool
		wantWarn bool
	}{
		{
			name: "valid queue/db on block",
			vcs:  []ManagerVolumeClaim{{Path: "/var/ossec/queue/db", Size: "5Gi", StorageClass: &block, AccessMode: corev1.ReadWriteOnce}},
		},
		{
			name:    "path not under /var/ossec",
			vcs:     []ManagerVolumeClaim{{Path: "/data/db", Size: "5Gi"}},
			wantErr: true,
		},
		{
			name:    "unclean path with ..",
			vcs:     []ManagerVolumeClaim{{Path: "/var/ossec/queue/../db", Size: "5Gi"}},
			wantErr: true,
		},
		{
			name:    "trailing slash",
			vcs:     []ManagerVolumeClaim{{Path: "/var/ossec/queue/db/", Size: "5Gi"}},
			wantErr: true,
		},
		{
			name: "duplicate paths",
			vcs: []ManagerVolumeClaim{
				{Path: "/var/ossec/logs", Size: "5Gi"},
				{Path: "/var/ossec/logs", Size: "6Gi"},
			},
			wantErr: true,
		},
		{
			name:    "invalid size",
			vcs:     []ManagerVolumeClaim{{Path: "/var/ossec/logs", Size: "notasize"}},
			wantErr: true,
		},
		{
			name:    "zero size",
			vcs:     []ManagerVolumeClaim{{Path: "/var/ossec/logs", Size: "0"}},
			wantErr: true,
		},
		{
			name:     "RWX on SQLite path warns",
			vcs:      []ManagerVolumeClaim{{Path: "/var/ossec/queue/db", Size: "5Gi", AccessMode: corev1.ReadWriteMany}},
			wantWarn: true,
		},
		{
			name:     "splitting etc warns",
			vcs:      []ManagerVolumeClaim{{Path: "/var/ossec/etc", Size: "1Gi"}},
			wantWarn: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs, warns := validateManagerVolumeClaims(tt.vcs, "spec.manager.master.volumeClaims")
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("errors = %v, wantErr %v", errs, tt.wantErr)
			}
			if (len(warns) > 0) != tt.wantWarn && !tt.wantErr {
				t.Errorf("warnings = %v, wantWarn %v", warns, tt.wantWarn)
			}
		})
	}
}

func TestVolumeClaimsChangeWarnings(t *testing.T) {
	nfs, block := "nfs", "block"
	old := []ManagerVolumeClaim{{Path: "/var/ossec/queue/db", Size: "5Gi", StorageClass: &nfs}}

	// storageClass change -> warn
	if w := volumeClaimsChangeWarnings(old, []ManagerVolumeClaim{{Path: "/var/ossec/queue/db", Size: "5Gi", StorageClass: &block}}, "master"); len(w) == 0 {
		t.Error("expected a warning for storageClass change")
	}
	// removal -> warn (orphan)
	if w := volumeClaimsChangeWarnings(old, nil, "master"); len(w) == 0 || !strings.Contains(strings.Join(w, " "), "orphan") {
		t.Errorf("expected an orphan warning on removal, got %v", w)
	}
	// addition -> warn
	if w := volumeClaimsChangeWarnings(nil, old, "master"); len(w) == 0 {
		t.Error("expected a warning for added path")
	}
	// unchanged -> no warning
	if w := volumeClaimsChangeWarnings(old, old, "master"); len(w) != 0 {
		t.Errorf("expected no warning for unchanged claims, got %v", w)
	}
}
