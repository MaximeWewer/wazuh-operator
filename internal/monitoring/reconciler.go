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

package monitoring

import (
	"context"
	"fmt"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
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
func (r *MonitoringReconciler) Reconcile(ctx context.Context, cluster *wazuhv1.WazuhCluster) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "MonitoringReconciler.Reconcile",
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
// If the ServiceMonitor CRD is not installed, logs a warning and returns nil
func (r *MonitoringReconciler) reconcileServiceMonitor(ctx context.Context, cluster *wazuhv1.WazuhCluster, desired *monitoringv1.ServiceMonitor) error {
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
			if err := r.Client.Create(ctx, desired); err != nil {
				// If CRD is not installed, log warning and continue
				if utils.IsCRDNotInstalledError(err) {
					log.Info("ServiceMonitor CRD not installed, skipping monitoring setup. Install prometheus-operator to enable monitoring.")
					return nil
				}
				return err
			}
			return nil
		}
		// If CRD is not installed, log warning and continue
		if utils.IsCRDNotInstalledError(err) {
			log.Info("ServiceMonitor CRD not installed, skipping monitoring setup. Install prometheus-operator to enable monitoring.")
			return nil
		}
		return err
	}

	// Skip update if nothing changed
	if apiequality.Semantic.DeepEqual(existing.Spec, desired.Spec) &&
		mapsEqual(existing.Labels, desired.Labels) {
		return nil
	}

	// Update existing ServiceMonitor
	existing.Labels = desired.Labels
	existing.Spec = desired.Spec
	log.V(1).Info("Updating ServiceMonitor", "name", desired.Name)
	return r.Client.Update(ctx, existing)
}

// cleanupMonitoringResources removes all monitoring resources when monitoring is disabled
func (r *MonitoringReconciler) cleanupMonitoringResources(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)
	var errs []error

	// Delete Manager ServiceMonitor
	if err := r.deleteServiceMonitorIfExists(ctx, cluster.Namespace, fmt.Sprintf("%s-manager-metrics", cluster.Name)); err != nil {
		log.Error(err, "Failed to delete Manager ServiceMonitor")
		errs = append(errs, err)
	}

	// Delete Indexer ServiceMonitor
	if err := r.deleteServiceMonitorIfExists(ctx, cluster.Namespace, fmt.Sprintf("%s-indexer-metrics", cluster.Name)); err != nil {
		log.Error(err, "Failed to delete Indexer ServiceMonitor")
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to cleanup monitoring resources: %v", errs)
	}
	return nil
}

// deleteServiceMonitorIfExists deletes a ServiceMonitor if it exists
// Returns nil if the resource doesn't exist or if the CRD is not installed
func (r *MonitoringReconciler) deleteServiceMonitorIfExists(ctx context.Context, namespace, name string) error {
	sm := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	err := r.Client.Delete(ctx, sm)
	if err != nil {
		// Ignore "not found" errors (resource doesn't exist)
		if errors.IsNotFound(err) {
			return nil
		}
		// Ignore "no matches for kind" errors (CRD not installed)
		if utils.IsCRDNotInstalledError(err) {
			return nil
		}
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
