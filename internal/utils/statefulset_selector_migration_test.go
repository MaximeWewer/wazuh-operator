package utils //nolint:revive // utils is a common package name

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func selectorSTS(name string, selector, templateLabels map[string]string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(name + "-uid")},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: templateLabels}},
		},
	}
}

func labeledPod(name string, labels map[string]string) *corev1.Pod {
	l := map[string]string{"controller-revision-hash": "rev-old"}
	for k, v := range labels {
		l[k] = v
	}
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", Labels: l}}
}

// TestMigrateStatefulSetSelector covers the migration of the manager StatefulSets from the
// legacy app.kubernetes.io/name=wazuh-wazuh-manager selector: the StatefulSet is deleted
// (orphaning its pods), its pods are relabeled so the recreated StatefulSet adopts them, its
// revisions are removed, and nothing else is touched.
func TestMigrateStatefulSetSelector(t *testing.T) {
	oldSel := map[string]string{"app.kubernetes.io/name": "wazuh-wazuh-manager", "node-type": "master"}
	newSel := map[string]string{"app.kubernetes.io/name": "wazuh-manager", "node-type": "master"}
	newTemplate := map[string]string{"app.kubernetes.io/name": "wazuh-manager", "app.kubernetes.io/component": "manager", "node-type": "master"}
	workerSel := map[string]string{"app.kubernetes.io/name": "wazuh-wazuh-manager", "node-type": "worker"}

	existing := selectorSTS("c-manager-master", oldSel, oldSel)
	desired := selectorSTS("c-manager-master", newSel, newTemplate)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		existing,
		labeledPod("c-manager-master-0", oldSel),
		labeledPod("c-manager-master-1", oldSel),
		labeledPod("c-manager-master-backup", oldSel), // not an ordinal pod of the StatefulSet
		labeledPod("c-manager-worker-0", workerSel),
		&appsv1.ControllerRevision{ObjectMeta: metav1.ObjectMeta{Name: "c-manager-master-abc", Namespace: "ns", Labels: oldSel}},
		&appsv1.ControllerRevision{ObjectMeta: metav1.ObjectMeta{Name: "c-manager-worker-def", Namespace: "ns", Labels: workerSel}},
	).Build()
	ctx := context.Background()

	migrating, err := MigrateStatefulSetSelector(ctx, c, nil, desired, existing)
	if err != nil || !migrating {
		t.Fatalf("MigrateStatefulSetSelector() = %v, %v; want true, nil", migrating, err)
	}

	if err := c.Get(ctx, client.ObjectKeyFromObject(existing), &appsv1.StatefulSet{}); !apierrors.IsNotFound(err) {
		t.Errorf("old StatefulSet not deleted: %v", err)
	}
	for _, name := range []string{"c-manager-master-0", "c-manager-master-1"} {
		pod := &corev1.Pod{}
		if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: "ns"}, pod); err != nil {
			t.Fatalf("pod %s must keep running: %v", name, err)
		}
		for k, v := range newTemplate {
			if pod.Labels[k] != v {
				t.Errorf("pod %s label %s = %q, want %q", name, k, pod.Labels[k], v)
			}
		}
		if pod.Labels["controller-revision-hash"] != "rev-old" {
			t.Errorf("pod %s revision hash must be kept so the new StatefulSet rolls it", name)
		}
	}
	for name, want := range map[string]string{"c-manager-master-backup": "wazuh-wazuh-manager", "c-manager-worker-0": "wazuh-wazuh-manager"} {
		pod := &corev1.Pod{}
		_ = c.Get(ctx, types.NamespacedName{Name: name, Namespace: "ns"}, pod)
		if pod.Labels["app.kubernetes.io/name"] != want {
			t.Errorf("unrelated pod %s was relabeled", name)
		}
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "c-manager-master-abc", Namespace: "ns"}, &appsv1.ControllerRevision{}); !apierrors.IsNotFound(err) {
		t.Errorf("old controller revision not deleted: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "c-manager-worker-def", Namespace: "ns"}, &appsv1.ControllerRevision{}); err != nil {
		t.Errorf("worker controller revision must be kept: %v", err)
	}
}

func TestMigrateStatefulSetSelector_SameSelectorIsNoop(t *testing.T) {
	sel := map[string]string{"app.kubernetes.io/name": "wazuh-manager"}
	existing := selectorSTS("s", sel, sel)
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	migrating, err := MigrateStatefulSetSelector(context.Background(), c, nil, selectorSTS("s", sel, sel), existing)
	if err != nil || migrating {
		t.Fatalf("MigrateStatefulSetSelector() = %v, %v; want false, nil", migrating, err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(existing), &appsv1.StatefulSet{}); err != nil {
		t.Errorf("StatefulSet must not be deleted: %v", err)
	}
}

func TestIsStatefulSetPodName(t *testing.T) {
	for name, want := range map[string]bool{
		"c-manager-master-0": true, "c-manager-master-12": true,
		"c-manager-master-": false, "c-manager-master-x": false, "c-manager-masterx-0": false,
	} {
		if got := isStatefulSetPodName("c-manager-master", name); got != want {
			t.Errorf("isStatefulSetPodName(%q) = %v, want %v", name, got, want)
		}
	}
}
