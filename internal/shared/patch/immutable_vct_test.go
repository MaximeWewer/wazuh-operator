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

package patch

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testVCT(name, sc, size string, mode corev1.PersistentVolumeAccessMode) corev1.PersistentVolumeClaim {
	scCopy := sc
	return corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeClaimSpec{
			StorageClassName: &scCopy,
			AccessModes:      []corev1.PersistentVolumeAccessMode{mode},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(size)},
			},
		},
	}
}

func stsWithVCTs(vcts ...corev1.PersistentVolumeClaim) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{VolumeClaimTemplates: vcts}}
}

func TestVolumeClaimTemplatesNeedRecreation(t *testing.T) {
	rwo := corev1.ReadWriteOnce
	base := testVCT("wazuh-data", "nfs", "50Gi", rwo)

	tests := []struct {
		name           string
		current        *appsv1.StatefulSet
		desired        *appsv1.StatefulSet
		wantRecreation bool
	}{
		{"identical", stsWithVCTs(base), stsWithVCTs(base), false},
		{
			"size-only change (handled by expansion, no recreation)",
			stsWithVCTs(testVCT("wazuh-data", "nfs", "50Gi", rwo)),
			stsWithVCTs(testVCT("wazuh-data", "nfs", "100Gi", rwo)),
			false,
		},
		{
			"VCT added",
			stsWithVCTs(base),
			stsWithVCTs(base, testVCT("wazuh-data-queue-db", "block", "5Gi", rwo)),
			true,
		},
		{
			"VCT removed",
			stsWithVCTs(base, testVCT("wazuh-data-queue-db", "block", "5Gi", rwo)),
			stsWithVCTs(base),
			true,
		},
		{
			"storageClass changed",
			stsWithVCTs(testVCT("wazuh-data", "nfs", "50Gi", rwo)),
			stsWithVCTs(testVCT("wazuh-data", "block", "50Gi", rwo)),
			true,
		},
		{
			"accessMode changed",
			stsWithVCTs(testVCT("wazuh-data", "nfs", "50Gi", rwo)),
			stsWithVCTs(testVCT("wazuh-data", "nfs", "50Gi", corev1.ReadWriteMany)),
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := volumeClaimTemplatesNeedRecreation(tt.current, tt.desired); got != tt.wantRecreation {
				t.Errorf("volumeClaimTemplatesNeedRecreation = %v, want %v", got, tt.wantRecreation)
			}
			// NeedsStatefulSetRecreation wires the VCT check in (same STS => other fields equal).
			if got, _ := NeedsStatefulSetRecreation(tt.current, tt.desired); got != tt.wantRecreation {
				t.Errorf("NeedsStatefulSetRecreation = %v, want %v", got, tt.wantRecreation)
			}
		})
	}
}
