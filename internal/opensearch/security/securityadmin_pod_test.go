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

package security

import (
	"context"
	"maps"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// TestSecurityAdminPod asserts securityadmin.sh runs in a running indexer pod of the
// cluster, ready ones first, in simple mode as with nodePools (no <cluster>-indexer-0).
func TestSecurityAdminPod(t *testing.T) {
	pod := func(name, cluster string, phase corev1.PodPhase, ready bool) *corev1.Pod {
		labels := constants.CommonLabels(cluster, constants.ComponentIndexer, "4.14.8")
		maps.Copy(labels, constants.SelectorLabels(cluster, constants.ComponentIndexer))
		status := corev1.ConditionFalse
		if ready {
			status = corev1.ConditionTrue
		}
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", Labels: labels},
			Status:     corev1.PodStatus{Phase: phase, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}},
		}
	}
	for name, tc := range map[string]struct {
		pods    []*corev1.Pod
		want    string
		wantErr bool
	}{
		"simple mode": {pods: []*corev1.Pod{pod("c-indexer-1", "c", corev1.PodRunning, true), pod("c-indexer-0", "c", corev1.PodRunning, true)}, want: "c-indexer-0"},
		"node pools":  {pods: []*corev1.Pod{pod("c-indexer-warm-0", "c", corev1.PodRunning, true), pod("c-indexer-hot-0", "c", corev1.PodRunning, true)}, want: "c-indexer-hot-0"},
		"first pod down": {pods: []*corev1.Pod{pod("c-indexer-0", "c", corev1.PodPending, false), pod("c-indexer-1", "c", corev1.PodRunning, true)},
			want: "c-indexer-1"},
		"ready pod preferred": {pods: []*corev1.Pod{pod("c-indexer-0", "c", corev1.PodRunning, false), pod("c-indexer-1", "c", corev1.PodRunning, true)},
			want: "c-indexer-1"},
		"other cluster ignored": {pods: []*corev1.Pod{pod("other-indexer-0", "other", corev1.PodRunning, true)}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			b := fake.NewClientBuilder().WithScheme(scheme)
			for _, p := range tc.pods {
				b = b.WithObjects(p)
			}
			e := &SecurityAdminExecutor{k8sClient: b.Build()}
			got, err := e.securityAdminPod(context.Background(), "c", "ns")
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("securityAdminPod = %q, %v; want %q, error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
