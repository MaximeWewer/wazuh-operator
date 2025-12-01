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

package reconciler

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DecoderReconciler handles reconciliation of Wazuh Decoders
type DecoderReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// NewDecoderReconciler creates a new DecoderReconciler
func NewDecoderReconciler(c client.Client, scheme *runtime.Scheme) *DecoderReconciler {
	return &DecoderReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles the Wazuh Decoder
func (r *DecoderReconciler) Reconcile(ctx context.Context, decoder *wazuhv1alpha1.WazuhDecoder) error {
	log := logf.FromContext(ctx)

	// Create ConfigMap for the decoder
	if err := r.reconcileConfigMap(ctx, decoder); err != nil {
		return fmt.Errorf("failed to reconcile decoder configmap: %w", err)
	}

	// Update status
	if err := r.updateStatus(ctx, decoder); err != nil {
		return fmt.Errorf("failed to update decoder status: %w", err)
	}

	log.Info("Decoder reconciliation completed", "name", decoder.Name)
	return nil
}

// reconcileConfigMap reconciles the ConfigMap for the decoder
func (r *DecoderReconciler) reconcileConfigMap(ctx context.Context, decoder *wazuhv1alpha1.WazuhDecoder) error {
	log := logf.FromContext(ctx)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-decoder", decoder.Name),
			Namespace: decoder.Namespace,
			Labels: map[string]string{
				constants.LabelName:      "wazuh-decoder",
				constants.LabelInstance:  decoder.Name,
				constants.LabelManagedBy: "wazuh-operator",
				constants.LabelComponent: "decoder",
			},
		},
		Data: map[string]string{
			fmt.Sprintf("%s.xml", decoder.Spec.DecoderName): decoder.Spec.Decoders,
		},
	}

	if err := controllerutil.SetControllerReference(decoder, cm, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating decoder ConfigMap", "name", cm.Name)
		return r.Create(ctx, cm)
	} else if err != nil {
		return err
	}

	// Update existing
	existing.Data = cm.Data
	existing.Labels = cm.Labels
	log.V(1).Info("Updating decoder ConfigMap", "name", cm.Name)
	return r.Update(ctx, existing)
}

// updateStatus updates the decoder status
func (r *DecoderReconciler) updateStatus(ctx context.Context, decoder *wazuhv1alpha1.WazuhDecoder) error {
	decoder.Status.Phase = wazuhv1alpha1.DecoderPhaseApplied
	decoder.Status.Message = "Decoder ConfigMap created successfully"
	now := metav1.Now()
	decoder.Status.LastAppliedTime = &now

	return r.Status().Update(ctx, decoder)
}

// Delete handles cleanup when a decoder is deleted
func (r *DecoderReconciler) Delete(ctx context.Context, decoder *wazuhv1alpha1.WazuhDecoder) error {
	log := logf.FromContext(ctx)

	// The ConfigMap will be garbage collected due to owner reference
	log.Info("Decoder deletion handled", "name", decoder.Name)
	return nil
}
