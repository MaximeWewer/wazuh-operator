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

// Package adapters provides external API adapters for the Wazuh Operator
package adapters

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// K8sAdapter wraps the controller-runtime client with helper methods
type K8sAdapter struct {
	client client.Client
	scheme *runtime.Scheme
}

// NewK8sAdapter creates a new K8sAdapter
func NewK8sAdapter(c client.Client, s *runtime.Scheme) *K8sAdapter {
	return &K8sAdapter{
		client: c,
		scheme: s,
	}
}

// Client returns the underlying client
func (a *K8sAdapter) Client() client.Client {
	return a.client
}

// Scheme returns the scheme
func (a *K8sAdapter) Scheme() *runtime.Scheme {
	return a.scheme
}

// Get retrieves an object from the cluster
func (a *K8sAdapter) Get(ctx context.Context, key types.NamespacedName, obj client.Object) error {
	return a.client.Get(ctx, key, obj)
}

// List lists objects from the cluster
func (a *K8sAdapter) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return a.client.List(ctx, list, opts...)
}

// Create creates an object in the cluster
func (a *K8sAdapter) Create(ctx context.Context, obj client.Object) error {
	return a.client.Create(ctx, obj)
}

// Update updates an object in the cluster
func (a *K8sAdapter) Update(ctx context.Context, obj client.Object) error {
	return a.client.Update(ctx, obj)
}

// Delete deletes an object from the cluster
func (a *K8sAdapter) Delete(ctx context.Context, obj client.Object) error {
	return a.client.Delete(ctx, obj)
}

// Patch patches an object in the cluster
func (a *K8sAdapter) Patch(ctx context.Context, obj client.Object, patch client.Patch) error {
	return a.client.Patch(ctx, obj, patch)
}

// UpdateStatus updates the status of an object
func (a *K8sAdapter) UpdateStatus(ctx context.Context, obj client.Object) error {
	return a.client.Status().Update(ctx, obj)
}

// SetOwnerReference sets the owner reference on an object
func (a *K8sAdapter) SetOwnerReference(owner, controlled metav1.Object) error {
	return controllerutil.SetControllerReference(owner, controlled, a.scheme)
}

// CreateOrUpdate creates or updates an object
func (a *K8sAdapter) CreateOrUpdate(ctx context.Context, obj client.Object, mutate func() error) (controllerutil.OperationResult, error) {
	return controllerutil.CreateOrUpdate(ctx, a.client, obj, mutate)
}

// Exists checks if an object exists in the cluster
func (a *K8sAdapter) Exists(ctx context.Context, key types.NamespacedName, obj client.Object) (bool, error) {
	err := a.client.Get(ctx, key, obj)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// EnsureDeleted ensures an object is deleted from the cluster
func (a *K8sAdapter) EnsureDeleted(ctx context.Context, obj client.Object) error {
	err := a.client.Delete(ctx, obj)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	return nil
}

// GetSecret retrieves a secret from the cluster
func (a *K8sAdapter) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := a.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// GetConfigMap retrieves a ConfigMap from the cluster
func (a *K8sAdapter) GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	err := a.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, cm)
	if err != nil {
		return nil, err
	}
	return cm, nil
}

// GetService retrieves a Service from the cluster
func (a *K8sAdapter) GetService(ctx context.Context, namespace, name string) (*corev1.Service, error) {
	svc := &corev1.Service{}
	err := a.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, svc)
	if err != nil {
		return nil, err
	}
	return svc, nil
}

// GetDeployment retrieves a Deployment from the cluster
func (a *K8sAdapter) GetDeployment(ctx context.Context, namespace, name string) (*appsv1.Deployment, error) {
	deployment := &appsv1.Deployment{}
	err := a.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, deployment)
	if err != nil {
		return nil, err
	}
	return deployment, nil
}

// GetStatefulSet retrieves a StatefulSet from the cluster
func (a *K8sAdapter) GetStatefulSet(ctx context.Context, namespace, name string) (*appsv1.StatefulSet, error) {
	sts := &appsv1.StatefulSet{}
	err := a.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, sts)
	if err != nil {
		return nil, err
	}
	return sts, nil
}

// ListPodsByLabel lists pods by label selector
func (a *K8sAdapter) ListPodsByLabel(ctx context.Context, namespace string, labels map[string]string) (*corev1.PodList, error) {
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels(labels),
	}
	if err := a.client.List(ctx, podList, listOpts...); err != nil {
		return nil, err
	}
	return podList, nil
}

// IsPodReady checks if a pod is ready
func (a *K8sAdapter) IsPodReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// IsDeploymentReady checks if a deployment is ready
func (a *K8sAdapter) IsDeploymentReady(deployment *appsv1.Deployment) bool {
	if deployment.Status.ReadyReplicas < *deployment.Spec.Replicas {
		return false
	}
	return deployment.Status.UpdatedReplicas == deployment.Status.Replicas
}

// IsStatefulSetReady checks if a StatefulSet is ready
func (a *K8sAdapter) IsStatefulSetReady(sts *appsv1.StatefulSet) bool {
	if sts.Status.ReadyReplicas < *sts.Spec.Replicas {
		return false
	}
	return sts.Status.UpdatedReplicas == sts.Status.Replicas
}

// CreateSecretIfNotExists creates a secret if it doesn't exist
func (a *K8sAdapter) CreateSecretIfNotExists(ctx context.Context, secret *corev1.Secret) error {
	existing := &corev1.Secret{}
	err := a.client.Get(ctx, client.ObjectKeyFromObject(secret), existing)
	if errors.IsNotFound(err) {
		return a.client.Create(ctx, secret)
	}
	return err
}

// CreateConfigMapIfNotExists creates a ConfigMap if it doesn't exist
func (a *K8sAdapter) CreateConfigMapIfNotExists(ctx context.Context, cm *corev1.ConfigMap) error {
	existing := &corev1.ConfigMap{}
	err := a.client.Get(ctx, client.ObjectKeyFromObject(cm), existing)
	if errors.IsNotFound(err) {
		return a.client.Create(ctx, cm)
	}
	return err
}

// CreateEvent creates a Kubernetes event
func (a *K8sAdapter) CreateEvent(ctx context.Context, obj client.Object, eventType, reason, message string) error {
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: obj.GetName() + "-",
			Namespace:    obj.GetNamespace(),
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       obj.GetObjectKind().GroupVersionKind().Kind,
			Name:       obj.GetName(),
			Namespace:  obj.GetNamespace(),
			UID:        obj.GetUID(),
			APIVersion: obj.GetObjectKind().GroupVersionKind().GroupVersion().String(),
		},
		Reason:  reason,
		Message: message,
		Type:    eventType,
		Source: corev1.EventSource{
			Component: "wazuh-operator",
		},
		FirstTimestamp: metav1.Now(),
		LastTimestamp:  metav1.Now(),
	}
	return a.client.Create(ctx, event)
}

// EmitEvent is a helper to emit events with standard formatting
func (a *K8sAdapter) EmitEvent(ctx context.Context, obj client.Object, eventType, reason string, messageFmt string, args ...interface{}) error {
	message := fmt.Sprintf(messageFmt, args...)
	return a.CreateEvent(ctx, obj, eventType, reason, message)
}
