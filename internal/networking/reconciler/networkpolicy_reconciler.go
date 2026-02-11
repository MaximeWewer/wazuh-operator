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

// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete

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
	"github.com/MaximeWewer/wazuh-operator/internal/networking/builder/networkpolicies"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
)

// NetworkPolicyReconciler handles reconciliation of NetworkPolicy resources for Wazuh components
type NetworkPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// NewNetworkPolicyReconciler creates a new NetworkPolicyReconciler
func NewNetworkPolicyReconciler(c client.Client, scheme *runtime.Scheme) *NetworkPolicyReconciler {
	return &NetworkPolicyReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles NetworkPolicy resources for the cluster
func (r *NetworkPolicyReconciler) Reconcile(ctx context.Context, cluster *wazuhv1.WazuhCluster) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "NetworkPolicyReconciler.Reconcile",
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

	// Reconcile Indexer NetworkPolicy
	if err := r.reconcileIndexerNetworkPolicy(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer network policy: %w", err)
	}

	// Reconcile Manager NetworkPolicy
	if err := r.reconcileManagerNetworkPolicy(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile manager network policy: %w", err)
	}

	// Reconcile Dashboard NetworkPolicy
	if err := r.reconcileDashboardNetworkPolicy(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard network policy: %w", err)
	}

	log.V(1).Info("NetworkPolicy reconciliation completed")
	return nil
}

// reconcileIndexerNetworkPolicy reconciles the NetworkPolicy for the Indexer
func (r *NetworkPolicyReconciler) reconcileIndexerNetworkPolicy(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	var npSpec *wazuhv1.NetworkPolicySpec
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.NetworkPolicy != nil {
		npSpec = cluster.Spec.Indexer.NetworkPolicy
	}

	npName := cluster.Name + "-indexer"

	if npSpec == nil || !npSpec.Enabled {
		return r.deleteNetworkPolicyIfExists(ctx, npName, cluster.Namespace)
	}

	log.Info("Reconciling Indexer NetworkPolicy", "name", npName)

	np := networkpolicies.BuildIndexerNetworkPolicy(cluster.Name, cluster.Namespace, npSpec)
	if err := controllerutil.SetControllerReference(cluster, np, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer NetworkPolicy: %w", err)
	}

	return r.createOrUpdateNetworkPolicy(ctx, np)
}

// reconcileManagerNetworkPolicy reconciles the NetworkPolicy for the Manager
func (r *NetworkPolicyReconciler) reconcileManagerNetworkPolicy(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	var npSpec *wazuhv1.NetworkPolicySpec
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.NetworkPolicy != nil {
		npSpec = cluster.Spec.Manager.NetworkPolicy
	}

	npName := cluster.Name + "-manager"

	if npSpec == nil || !npSpec.Enabled {
		return r.deleteNetworkPolicyIfExists(ctx, npName, cluster.Namespace)
	}

	log.Info("Reconciling Manager NetworkPolicy", "name", npName)

	np := networkpolicies.BuildManagerNetworkPolicy(cluster.Name, cluster.Namespace, npSpec)
	if err := controllerutil.SetControllerReference(cluster, np, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for manager NetworkPolicy: %w", err)
	}

	return r.createOrUpdateNetworkPolicy(ctx, np)
}

// reconcileDashboardNetworkPolicy reconciles the NetworkPolicy for the Dashboard
func (r *NetworkPolicyReconciler) reconcileDashboardNetworkPolicy(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	var npSpec *wazuhv1.NetworkPolicySpec
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.NetworkPolicy != nil {
		npSpec = cluster.Spec.Dashboard.NetworkPolicy
	}

	npName := cluster.Name + "-dashboard"

	if npSpec == nil || !npSpec.Enabled {
		return r.deleteNetworkPolicyIfExists(ctx, npName, cluster.Namespace)
	}

	log.Info("Reconciling Dashboard NetworkPolicy", "name", npName)

	np := networkpolicies.BuildDashboardNetworkPolicy(cluster.Name, cluster.Namespace, npSpec)
	if err := controllerutil.SetControllerReference(cluster, np, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard NetworkPolicy: %w", err)
	}

	return r.createOrUpdateNetworkPolicy(ctx, np)
}

// createOrUpdateNetworkPolicy creates or updates a NetworkPolicy
func (r *NetworkPolicyReconciler) createOrUpdateNetworkPolicy(ctx context.Context, np *networkingv1.NetworkPolicy) error {
	log := logf.FromContext(ctx)

	existing := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, types.NamespacedName{Name: np.Name, Namespace: np.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating NetworkPolicy", "name", np.Name)
		return r.Create(ctx, np)
	} else if err != nil {
		return fmt.Errorf("failed to get NetworkPolicy: %w", err)
	}

	// Update existing network policy
	log.V(1).Info("Updating NetworkPolicy", "name", np.Name)
	np.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, np)
}

// deleteNetworkPolicyIfExists deletes a NetworkPolicy if it exists
func (r *NetworkPolicyReconciler) deleteNetworkPolicyIfExists(ctx context.Context, name, namespace string) error {
	log := logf.FromContext(ctx)

	np := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, np)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get NetworkPolicy for deletion: %w", err)
	}

	log.Info("Deleting NetworkPolicy", "name", name)
	return r.Delete(ctx, np)
}
