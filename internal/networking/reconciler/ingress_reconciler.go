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
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/networking/builder/ingresses"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
)

// IngressReconciler handles reconciliation of Ingress resources for Wazuh components
type IngressReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// NewIngressReconciler creates a new IngressReconciler
func NewIngressReconciler(c client.Client, scheme *runtime.Scheme) *IngressReconciler {
	return &IngressReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles Ingress resources for the cluster
func (r *IngressReconciler) Reconcile(ctx context.Context, cluster *wazuhv1.WazuhCluster) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "IngressReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", cluster.Name),
			attribute.String("resource.namespace", cluster.Namespace),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)

	// Reconcile Dashboard Ingress
	if err := r.reconcileDashboardIngress(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard ingress: %w", err)
	}

	// Reconcile Manager Master Ingress
	if err := r.reconcileManagerMasterIngress(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile manager master ingress: %w", err)
	}

	// Reconcile Manager Workers Ingress
	if err := r.reconcileManagerWorkersIngress(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile manager workers ingress: %w", err)
	}

	// Reconcile Indexer Ingress
	if err := r.reconcileIndexerIngress(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer ingress: %w", err)
	}

	log.V(1).Info("Ingress reconciliation completed")
	return nil
}

// reconcileDashboardIngress reconciles the Ingress for the Dashboard
func (r *IngressReconciler) reconcileDashboardIngress(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get Ingress spec from Dashboard
	var ingressSpec *wazuhv1.IngressSpec
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.Ingress != nil {
		ingressSpec = cluster.Spec.Dashboard.Ingress
	}

	ingressName := fmt.Sprintf("%s-dashboard", cluster.Name)

	// If Ingress is not enabled, delete existing ingress if any
	if ingressSpec == nil || !ingressSpec.Enabled {
		return r.deleteIngressIfExists(ctx, ingressName, cluster.Namespace)
	}

	// Validate mutual exclusivity with GatewayAPI
	if cluster.Spec.Dashboard.GatewayAPI != nil && cluster.Spec.Dashboard.GatewayAPI.Enabled {
		return fmt.Errorf("dashboard: Ingress and GatewayAPI cannot both be enabled")
	}

	log.Info("Reconciling Dashboard Ingress", "name", ingressName)

	// Build and create/update Ingress
	ingress := ingresses.BuildDashboardIngress(cluster.Name, cluster.Namespace, ingressSpec)
	if err := controllerutil.SetControllerReference(cluster, ingress, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard Ingress: %w", err)
	}

	return r.createOrUpdateIngress(ctx, ingress)
}

// reconcileManagerMasterIngress reconciles the Ingress for the Manager Master
func (r *IngressReconciler) reconcileManagerMasterIngress(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get Ingress spec from Manager Master
	var ingressSpec *wazuhv1.IngressSpec
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.Ingress != nil {
		ingressSpec = cluster.Spec.Manager.Master.Ingress
	}

	ingressName := fmt.Sprintf("%s-manager-master", cluster.Name)

	// If Ingress is not enabled, delete existing ingress if any
	if ingressSpec == nil || !ingressSpec.Enabled {
		return r.deleteIngressIfExists(ctx, ingressName, cluster.Namespace)
	}

	// Validate mutual exclusivity with GatewayAPI
	if cluster.Spec.Manager.Master.GatewayAPI != nil && cluster.Spec.Manager.Master.GatewayAPI.Enabled {
		return fmt.Errorf("manager master: Ingress and GatewayAPI cannot both be enabled")
	}

	log.Info("Reconciling Manager Master Ingress", "name", ingressName)

	// Build and create/update Ingress
	ingress := ingresses.BuildManagerMasterIngress(cluster.Name, cluster.Namespace, ingressSpec)
	if err := controllerutil.SetControllerReference(cluster, ingress, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for manager master Ingress: %w", err)
	}

	return r.createOrUpdateIngress(ctx, ingress)
}

// reconcileManagerWorkersIngress reconciles the Ingress for the Manager Workers
func (r *IngressReconciler) reconcileManagerWorkersIngress(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get Ingress spec from Manager Workers
	var ingressSpec *wazuhv1.IngressSpec
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Ingress != nil {
		ingressSpec = cluster.Spec.Manager.Workers.Ingress
	}

	ingressName := fmt.Sprintf("%s-manager-workers", cluster.Name)

	// If Ingress is not enabled, delete existing ingress if any
	if ingressSpec == nil || !ingressSpec.Enabled {
		return r.deleteIngressIfExists(ctx, ingressName, cluster.Namespace)
	}

	// Validate mutual exclusivity with GatewayAPI
	if cluster.Spec.Manager.Workers.GatewayAPI != nil && cluster.Spec.Manager.Workers.GatewayAPI.Enabled {
		return fmt.Errorf("manager workers: Ingress and GatewayAPI cannot both be enabled")
	}

	log.Info("Reconciling Manager Workers Ingress", "name", ingressName)

	// Build and create/update Ingress
	ingress := ingresses.BuildManagerWorkersIngress(cluster.Name, cluster.Namespace, ingressSpec)
	if err := controllerutil.SetControllerReference(cluster, ingress, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for manager workers Ingress: %w", err)
	}

	return r.createOrUpdateIngress(ctx, ingress)
}

// reconcileIndexerIngress reconciles the Ingress for the Indexer
func (r *IngressReconciler) reconcileIndexerIngress(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get Ingress spec from Indexer
	var ingressSpec *wazuhv1.IngressSpec
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.Ingress != nil {
		ingressSpec = cluster.Spec.Indexer.Ingress
	}

	ingressName := fmt.Sprintf("%s-indexer", cluster.Name)

	// If Ingress is not enabled, delete existing ingress if any
	if ingressSpec == nil || !ingressSpec.Enabled {
		return r.deleteIngressIfExists(ctx, ingressName, cluster.Namespace)
	}

	// Validate mutual exclusivity with GatewayAPI
	if cluster.Spec.Indexer.GatewayAPI != nil && cluster.Spec.Indexer.GatewayAPI.Enabled {
		return fmt.Errorf("indexer: Ingress and GatewayAPI cannot both be enabled")
	}

	log.Info("Reconciling Indexer Ingress", "name", ingressName)

	// Build and create/update Ingress
	ingress := ingresses.BuildIndexerIngress(cluster.Name, cluster.Namespace, ingressSpec)
	if err := controllerutil.SetControllerReference(cluster, ingress, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer Ingress: %w", err)
	}

	return r.createOrUpdateIngress(ctx, ingress)
}

// createOrUpdateIngress creates or updates an Ingress
func (r *IngressReconciler) createOrUpdateIngress(ctx context.Context, ingress *networkingv1.Ingress) error {
	log := logf.FromContext(ctx)

	return utils.RetryOnConflict(ctx, func() error {
		existing := &networkingv1.Ingress{}
		err := r.Get(ctx, types.NamespacedName{Name: ingress.Name, Namespace: ingress.Namespace}, existing)
		if err != nil && errors.IsNotFound(err) {
			log.Info("Creating Ingress", "name", ingress.Name)
			return r.Create(ctx, ingress)
		} else if err != nil {
			return fmt.Errorf("failed to get Ingress: %w", err)
		}

		// Update existing ingress
		log.V(1).Info("Updating Ingress", "name", ingress.Name)
		existing.Labels = ingress.Labels
		existing.Annotations = ingress.Annotations
		existing.Spec = ingress.Spec
		return r.Update(ctx, existing)
	})
}

// deleteIngressIfExists deletes an Ingress if it exists
func (r *IngressReconciler) deleteIngressIfExists(ctx context.Context, name, namespace string) error {
	log := logf.FromContext(ctx)

	ingress := &networkingv1.Ingress{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, ingress)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get Ingress for deletion: %w", err)
	}

	log.Info("Deleting Ingress", "name", name)
	return r.Delete(ctx, ingress)
}
