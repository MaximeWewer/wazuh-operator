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
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// TestDeleteContentConfigMap asserts a content ConfigMap is deleted only once the cluster's
// manager StatefulSets no longer mount it and have rolled out: deleting it first leaves a
// starting manager pod with a missing or emptied file, and analysisd does not come up.
func TestDeleteContentConfigMap(t *testing.T) {
	one := int32(1)
	managerSTS := func(mountsCM, rolledOut bool) *appsv1.StatefulSet {
		sts := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "c-manager-master", Namespace: "ns", Generation: 2, Labels: map[string]string{
				constants.LabelWazuhCluster: "c", constants.LabelComponent: constants.ComponentManager,
			}},
			Spec: appsv1.StatefulSetSpec{Replicas: &one},
			Status: appsv1.StatefulSetStatus{ObservedGeneration: 2, Replicas: 1, ReadyReplicas: 1, UpdatedReplicas: 1,
				CurrentRevision: "r2", UpdateRevision: "r2"},
		}
		if mountsCM {
			sts.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}},
			}}}
		}
		if !rolledOut {
			sts.Status.UpdatedReplicas, sts.Status.CurrentRevision = 0, "r1"
		}
		return sts
	}
	// A StatefulSet of another cluster mounting a ConfigMap of the same name is ignored.
	otherCluster := managerSTS(true, true)
	otherCluster.Name, otherCluster.Labels[constants.LabelWazuhCluster] = "other-manager-master", "other"

	for name, tc := range map[string]struct {
		sts       *appsv1.StatefulSet
		wantKept  bool
		wantError error
	}{
		"still mounted":                   {sts: managerSTS(true, true), wantKept: true, wantError: ErrContentStillMounted},
		"unmounted, rollout not finished": {sts: managerSTS(false, false), wantKept: true, wantError: ErrContentStillMounted},
		"unmounted and rolled out":        {sts: managerSTS(false, true)},
		"cluster without manager anymore": {},
	} {
		t.Run(name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = appsv1.AddToScheme(scheme)
			objs := []runtime.Object{otherCluster, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "ns"}}}
			if tc.sts != nil {
				objs = append(objs, tc.sts)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()

			err := deleteContentConfigMap(context.Background(), c, []wazuhv1.WazuhClusterRef{{Name: "c", Namespace: "ns"}}, "cm")
			if !errors.Is(err, tc.wantError) || (tc.wantError == nil && err != nil) {
				t.Fatalf("deleteContentConfigMap error = %v, want %v", err, tc.wantError)
			}
			getErr := c.Get(context.Background(), types.NamespacedName{Name: "cm", Namespace: "ns"}, &corev1.ConfigMap{})
			if kept := getErr == nil; kept != tc.wantKept {
				t.Errorf("ConfigMap kept = %v (get error %v), want %v", kept, getErr, tc.wantKept)
			}
			if !tc.wantKept && !apierrors.IsNotFound(getErr) {
				t.Errorf("unexpected get error %v", getErr)
			}
		})
	}
}

// TestContentBeingDeletedIsNotDelivered asserts a decoder being deleted is left out of the
// cluster's mounts, so the cluster reconcile drops its mount before its ConfigMap goes.
func TestContentBeingDeletedIsNotDelivered(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)
	now := metav1.Now()
	decoder := func(name string, deleting bool) *wazuhv1.WazuhDecoder {
		d := &wazuhv1.WazuhDecoder{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", Finalizers: []string{DecoderFinalizer}},
			Spec:       wazuhv1.WazuhDecoderSpec{ClusterRefs: []wazuhv1.WazuhClusterRef{{Name: "c", Namespace: "ns"}}},
		}
		if deleting {
			d.DeletionTimestamp = &now
		}
		return d
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(decoder("kept", false), decoder("deleting", true)).Build()
	r := &DecoderReconciler{Client: c}
	got, err := r.ListDecodersForCluster(context.Background(), "c", "ns")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "kept" {
		t.Errorf("decoders delivered = %v, want only kept", got)
	}
}
