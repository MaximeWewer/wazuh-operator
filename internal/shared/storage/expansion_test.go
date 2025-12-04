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

package storage

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

func TestCompareStorageSizes(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		{
			name:     "equal sizes",
			a:        "50Gi",
			b:        "50Gi",
			expected: 0,
		},
		{
			name:     "a less than b",
			a:        "50Gi",
			b:        "100Gi",
			expected: -1,
		},
		{
			name:     "a greater than b",
			a:        "100Gi",
			b:        "50Gi",
			expected: 1,
		},
		{
			name:     "different units equal",
			a:        "1Ti",
			b:        "1024Gi",
			expected: 0,
		},
		{
			name:     "Mi to Gi",
			a:        "512Mi",
			b:        "1Gi",
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aQty := resource.MustParse(tt.a)
			bQty := resource.MustParse(tt.b)
			result := CompareStorageSizes(aQty, bQty)
			if result != tt.expected {
				t.Errorf("CompareStorageSizes(%s, %s) = %d, expected %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestCompareStorageSizeStrings(t *testing.T) {
	tests := []struct {
		name      string
		a         string
		b         string
		expected  int
		expectErr bool
	}{
		{
			name:     "equal sizes",
			a:        "50Gi",
			b:        "50Gi",
			expected: 0,
		},
		{
			name:     "a less than b",
			a:        "50Gi",
			b:        "100Gi",
			expected: -1,
		},
		{
			name:      "invalid a",
			a:         "invalid",
			b:         "50Gi",
			expectErr: true,
		},
		{
			name:      "invalid b",
			a:         "50Gi",
			b:         "invalid",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CompareStorageSizeStrings(tt.a, tt.b)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("CompareStorageSizeStrings(%s, %s) = %d, expected %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestIsShrinkRequest(t *testing.T) {
	tests := []struct {
		name      string
		current   string
		requested string
		expected  bool
		expectErr bool
	}{
		{
			name:      "not shrink - expansion",
			current:   "50Gi",
			requested: "100Gi",
			expected:  false,
		},
		{
			name:      "not shrink - same size",
			current:   "50Gi",
			requested: "50Gi",
			expected:  false,
		},
		{
			name:      "shrink request",
			current:   "100Gi",
			requested: "50Gi",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := IsShrinkRequest(tt.current, tt.requested)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("IsShrinkRequest(%s, %s) = %v, expected %v", tt.current, tt.requested, result, tt.expected)
			}
		})
	}
}

func TestIsExpansionRequest(t *testing.T) {
	tests := []struct {
		name      string
		current   string
		requested string
		expected  bool
	}{
		{
			name:      "expansion request",
			current:   "50Gi",
			requested: "100Gi",
			expected:  true,
		},
		{
			name:      "not expansion - same size",
			current:   "50Gi",
			requested: "50Gi",
			expected:  false,
		},
		{
			name:      "not expansion - shrink",
			current:   "100Gi",
			requested: "50Gi",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := IsExpansionRequest(tt.current, tt.requested)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("IsExpansionRequest(%s, %s) = %v, expected %v", tt.current, tt.requested, result, tt.expected)
			}
		})
	}
}

func TestGetPVCExpansionCondition(t *testing.T) {
	tests := []struct {
		name          string
		pvc           *corev1.PersistentVolumeClaim
		expectedPhase PVCExpansionPhase
		expectedDone  bool
	}{
		{
			name: "no conditions",
			pvc: &corev1.PersistentVolumeClaim{
				Status: corev1.PersistentVolumeClaimStatus{},
			},
			expectedPhase: PVCExpansionPhaseNone,
			expectedDone:  true,
		},
		{
			name: "resizing in progress",
			pvc: &corev1.PersistentVolumeClaim{
				Status: corev1.PersistentVolumeClaimStatus{
					Conditions: []corev1.PersistentVolumeClaimCondition{
						{
							Type:   corev1.PersistentVolumeClaimResizing,
							Status: corev1.ConditionTrue,
						},
					},
				},
			},
			expectedPhase: PVCExpansionPhaseResizing,
			expectedDone:  false,
		},
		{
			name: "filesystem resize pending",
			pvc: &corev1.PersistentVolumeClaim{
				Status: corev1.PersistentVolumeClaimStatus{
					Conditions: []corev1.PersistentVolumeClaimCondition{
						{
							Type:   corev1.PersistentVolumeClaimFileSystemResizePending,
							Status: corev1.ConditionTrue,
						},
					},
				},
			},
			expectedPhase: PVCExpansionPhaseFileSystemResizePending,
			expectedDone:  false,
		},
		{
			name: "expansion completed with annotation",
			pvc: &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						constants.AnnotationRequestedStorageSize: "100Gi",
					},
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("100Gi"),
						},
					},
				},
				Status: corev1.PersistentVolumeClaimStatus{},
			},
			expectedPhase: PVCExpansionPhaseCompleted,
			expectedDone:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPVCExpansionCondition(tt.pvc)
			if result.Phase != tt.expectedPhase {
				t.Errorf("GetPVCExpansionCondition() phase = %v, expected %v", result.Phase, tt.expectedPhase)
			}
			if result.IsComplete != tt.expectedDone {
				t.Errorf("GetPVCExpansionCondition() IsComplete = %v, expected %v", result.IsComplete, tt.expectedDone)
			}
		})
	}
}

func TestGetPVCStorageSize(t *testing.T) {
	tests := []struct {
		name     string
		pvc      *corev1.PersistentVolumeClaim
		expected string
	}{
		{
			name: "has storage size",
			pvc: &corev1.PersistentVolumeClaim{
				Spec: corev1.PersistentVolumeClaimSpec{
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("50Gi"),
						},
					},
				},
			},
			expected: "50Gi",
		},
		{
			name: "no requests",
			pvc: &corev1.PersistentVolumeClaim{
				Spec: corev1.PersistentVolumeClaimSpec{},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPVCStorageSize(tt.pvc)
			if result != tt.expected {
				t.Errorf("GetPVCStorageSize() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
