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

package monitoring

import (
	"context"
	"fmt"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
)

// MonitoringReconciler reconciles monitoring resources for a WazuhCluster
type MonitoringReconciler struct {
	Client client.Client
	Scheme *runtime.Scheme
}

// NewMonitoringReconciler creates a new MonitoringReconciler
func NewMonitoringReconciler(c client.Client, scheme *runtime.Scheme) *MonitoringReconciler {
	return &MonitoringReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles all monitoring resources for a WazuhCluster
func (r *MonitoringReconciler) Reconcile(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if monitoring is enabled
	if cluster.Spec.Monitoring == nil || !cluster.Spec.Monitoring.Enabled {
		// Delete any existing ServiceMonitors if monitoring was disabled
		return r.cleanupMonitoringResources(ctx, cluster)
	}

	// Reconcile Manager ServiceMonitor if Wazuh exporter is enabled
	if isWazuhExporterEnabled(cluster) {
		managerSM := NewManagerServiceMonitor(cluster)
		if managerSM != nil {
			if err := r.reconcileServiceMonitor(ctx, cluster, managerSM); err != nil {
				log.Error(err, "Failed to reconcile Manager ServiceMonitor")
				return err
			}
			log.V(1).Info("Manager ServiceMonitor reconciled")
		}
	} else {
		// Clean up if disabled
		if err := r.deleteServiceMonitorIfExists(ctx, cluster.Namespace, fmt.Sprintf("%s-manager-metrics", cluster.Name)); err != nil {
			log.Error(err, "Failed to cleanup Manager ServiceMonitor")
		}
	}

	// Reconcile Indexer ServiceMonitor if indexer exporter is enabled
	if isIndexerExporterEnabled(cluster) {
		indexerSM := NewIndexerServiceMonitor(cluster)
		if indexerSM != nil {
			if err := r.reconcileServiceMonitor(ctx, cluster, indexerSM); err != nil {
				log.Error(err, "Failed to reconcile Indexer ServiceMonitor")
				return err
			}
			log.V(1).Info("Indexer ServiceMonitor reconciled")
		}
	} else {
		// Clean up if disabled
		if err := r.deleteServiceMonitorIfExists(ctx, cluster.Namespace, fmt.Sprintf("%s-indexer-metrics", cluster.Name)); err != nil {
			log.Error(err, "Failed to cleanup Indexer ServiceMonitor")
		}
	}

	return nil
}

// reconcileServiceMonitor creates or updates a ServiceMonitor
func (r *MonitoringReconciler) reconcileServiceMonitor(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, desired *monitoringv1.ServiceMonitor) error {
	log := logf.FromContext(ctx)

	// Set owner reference
	if err := controllerutil.SetControllerReference(cluster, desired, r.Scheme); err != nil {
		return fmt.Errorf("failed to set owner reference: %w", err)
	}

	// Check if ServiceMonitor exists
	existing := &monitoringv1.ServiceMonitor{}
	err := r.Client.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			// Create new ServiceMonitor
			log.Info("Creating ServiceMonitor", "name", desired.Name)
			return r.Client.Create(ctx, desired)
		}
		return err
	}

	// Update existing ServiceMonitor
	existing.Labels = desired.Labels
	existing.Spec = desired.Spec
	log.V(1).Info("Updating ServiceMonitor", "name", desired.Name)
	return r.Client.Update(ctx, existing)
}

// cleanupMonitoringResources removes all monitoring resources when monitoring is disabled
func (r *MonitoringReconciler) cleanupMonitoringResources(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Delete Manager ServiceMonitor
	if err := r.deleteServiceMonitorIfExists(ctx, cluster.Namespace, fmt.Sprintf("%s-manager-metrics", cluster.Name)); err != nil {
		log.Error(err, "Failed to delete Manager ServiceMonitor")
	}

	// Delete Indexer ServiceMonitor
	if err := r.deleteServiceMonitorIfExists(ctx, cluster.Namespace, fmt.Sprintf("%s-indexer-metrics", cluster.Name)); err != nil {
		log.Error(err, "Failed to delete Indexer ServiceMonitor")
	}

	return nil
}

// deleteServiceMonitorIfExists deletes a ServiceMonitor if it exists
func (r *MonitoringReconciler) deleteServiceMonitorIfExists(ctx context.Context, namespace, name string) error {
	sm := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	err := r.Client.Delete(ctx, sm)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	return nil
}

// IsMonitoringCRDAvailable checks if the ServiceMonitor CRD is installed
func (r *MonitoringReconciler) IsMonitoringCRDAvailable(ctx context.Context) bool {
	// Try to list ServiceMonitors - if CRD doesn't exist, it will fail
	list := &monitoringv1.ServiceMonitorList{}
	err := r.Client.List(ctx, list, client.InNamespace("default"), client.Limit(1))
	if err != nil {
		// CRD not installed or other error
		return false
	}
	return true
}
