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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/networking/builder/routes"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
)

// GatewayReconciler handles reconciliation of Gateway API routes for Wazuh components
type GatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// NewGatewayReconciler creates a new GatewayReconciler
func NewGatewayReconciler(c client.Client, scheme *runtime.Scheme) *GatewayReconciler {
	return &GatewayReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles Gateway API routes for the cluster
func (r *GatewayReconciler) Reconcile(ctx context.Context, cluster *wazuhv1.WazuhCluster) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "GatewayReconciler.Reconcile",
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

	// Reconcile Dashboard Gateway API routes
	if err := r.reconcileDashboardRoutes(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard gateway routes: %w", err)
	}

	// Reconcile Manager Gateway API routes (master)
	if err := r.reconcileManagerRoutes(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile manager gateway routes: %w", err)
	}

	// Reconcile Indexer Gateway API routes
	if err := r.reconcileIndexerRoutes(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile indexer gateway routes: %w", err)
	}

	log.V(1).Info("Gateway API reconciliation completed")
	return nil
}

// reconcileDashboardRoutes reconciles HTTPRoute for the Dashboard
func (r *GatewayReconciler) reconcileDashboardRoutes(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get GatewayAPI spec from Dashboard
	var gatewayAPI *wazuhv1.GatewayAPISpec
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.GatewayAPI != nil {
		gatewayAPI = cluster.Spec.Dashboard.GatewayAPI
	}

	routeName := fmt.Sprintf("%s-dashboard", cluster.Name)

	// If GatewayAPI is not enabled, delete existing route if any
	if gatewayAPI == nil || !gatewayAPI.Enabled {
		return r.deleteHTTPRouteIfExists(ctx, routeName, cluster.Namespace)
	}

	// Validate mutual exclusivity with Ingress
	if cluster.Spec.Dashboard.Ingress != nil && cluster.Spec.Dashboard.Ingress.Enabled {
		return fmt.Errorf("dashboard: GatewayAPI and Ingress cannot both be enabled")
	}

	log.Info("Reconciling Dashboard HTTPRoute", "name", routeName)

	// Build and create/update HTTPRoute
	httpRoute := routes.BuildDashboardHTTPRoute(cluster.Name, cluster.Namespace, gatewayAPI)
	if err := controllerutil.SetControllerReference(cluster, httpRoute, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard HTTPRoute: %w", err)
	}

	return r.createOrUpdateHTTPRoute(ctx, httpRoute)
}

// reconcileManagerRoutes reconciles HTTPRoute, TCPRoute, and UDPRoute for the Manager
func (r *GatewayReconciler) reconcileManagerRoutes(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get GatewayAPI spec from Master
	var gatewayAPI *wazuhv1.GatewayAPISpec
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.GatewayAPI != nil {
		gatewayAPI = cluster.Spec.Manager.Master.GatewayAPI
	}

	apiRouteName := fmt.Sprintf("%s-manager-master-api", cluster.Name)
	enrollmentRouteName := fmt.Sprintf("%s-manager-master-enrollment", cluster.Name)
	eventsRouteName := fmt.Sprintf("%s-manager-master-events", cluster.Name)
	clusterRouteName := fmt.Sprintf("%s-manager-master-cluster", cluster.Name)
	syslogRouteName := fmt.Sprintf("%s-manager-master-syslog", cluster.Name)

	// If GatewayAPI is not enabled, delete existing routes if any
	if gatewayAPI == nil || !gatewayAPI.Enabled {
		if err := r.deleteHTTPRouteIfExists(ctx, apiRouteName, cluster.Namespace); err != nil {
			return err
		}
		if err := r.deleteTCPRouteIfExists(ctx, enrollmentRouteName, cluster.Namespace); err != nil {
			return err
		}
		if err := r.deleteTCPRouteIfExists(ctx, eventsRouteName, cluster.Namespace); err != nil {
			return err
		}
		if err := r.deleteTCPRouteIfExists(ctx, clusterRouteName, cluster.Namespace); err != nil {
			return err
		}
		if err := r.deleteUDPRouteIfExists(ctx, syslogRouteName, cluster.Namespace); err != nil {
			return err
		}
		return nil
	}

	// Validate mutual exclusivity with Ingress
	if cluster.Spec.Manager.Master.Ingress != nil && cluster.Spec.Manager.Master.Ingress.Enabled {
		return fmt.Errorf("manager master: GatewayAPI and Ingress cannot both be enabled")
	}

	// Reconcile Manager API HTTPRoute
	log.Info("Reconciling Manager API HTTPRoute", "name", apiRouteName)
	apiRoute := routes.BuildManagerAPIHTTPRoute(cluster.Name, cluster.Namespace, gatewayAPI, true)
	if err := controllerutil.SetControllerReference(cluster, apiRoute, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for manager API HTTPRoute: %w", err)
	}
	if err := r.createOrUpdateHTTPRoute(ctx, apiRoute); err != nil {
		return err
	}

	// Reconcile TCPRoutes if enabled
	if gatewayAPI.TCP != nil && gatewayAPI.TCP.Enabled {
		// Enrollment route (port 1515)
		if gatewayAPI.TCP.EnrollmentEnabled {
			log.Info("Reconciling Manager Enrollment TCPRoute", "name", enrollmentRouteName)
			enrollmentRoute := routes.BuildAgentEnrollmentTCPRoute(cluster.Name, cluster.Namespace, gatewayAPI, true)
			if err := controllerutil.SetControllerReference(cluster, enrollmentRoute, r.Scheme); err != nil {
				return fmt.Errorf("failed to set controller reference for enrollment TCPRoute: %w", err)
			}
			if err := r.createOrUpdateTCPRoute(ctx, enrollmentRoute); err != nil {
				return err
			}
		} else {
			if err := r.deleteTCPRouteIfExists(ctx, enrollmentRouteName, cluster.Namespace); err != nil {
				return err
			}
		}

		// Events route (port 1514)
		if gatewayAPI.TCP.EventsEnabled {
			log.Info("Reconciling Manager Events TCPRoute", "name", eventsRouteName)
			eventsRoute := routes.BuildAgentEventsTCPRoute(cluster.Name, cluster.Namespace, gatewayAPI, true)
			if err := controllerutil.SetControllerReference(cluster, eventsRoute, r.Scheme); err != nil {
				return fmt.Errorf("failed to set controller reference for events TCPRoute: %w", err)
			}
			if err := r.createOrUpdateTCPRoute(ctx, eventsRoute); err != nil {
				return err
			}
		} else {
			if err := r.deleteTCPRouteIfExists(ctx, eventsRouteName, cluster.Namespace); err != nil {
				return err
			}
		}

		// Cluster route (port 1516)
		if gatewayAPI.TCP.ClusterEnabled {
			log.Info("Reconciling Manager Cluster TCPRoute", "name", clusterRouteName)
			clusterRoute := routes.BuildClusterCommTCPRoute(cluster.Name, cluster.Namespace, gatewayAPI, true)
			if err := controllerutil.SetControllerReference(cluster, clusterRoute, r.Scheme); err != nil {
				return fmt.Errorf("failed to set controller reference for cluster TCPRoute: %w", err)
			}
			if err := r.createOrUpdateTCPRoute(ctx, clusterRoute); err != nil {
				return err
			}
		} else {
			if err := r.deleteTCPRouteIfExists(ctx, clusterRouteName, cluster.Namespace); err != nil {
				return err
			}
		}
	} else {
		// TCP not enabled, delete all TCP routes
		if err := r.deleteTCPRouteIfExists(ctx, enrollmentRouteName, cluster.Namespace); err != nil {
			return err
		}
		if err := r.deleteTCPRouteIfExists(ctx, eventsRouteName, cluster.Namespace); err != nil {
			return err
		}
		if err := r.deleteTCPRouteIfExists(ctx, clusterRouteName, cluster.Namespace); err != nil {
			return err
		}
	}

	// Reconcile UDPRoute for syslog if enabled
	if gatewayAPI.UDP != nil && gatewayAPI.UDP.Enabled {
		log.Info("Reconciling Manager Syslog UDPRoute", "name", syslogRouteName)
		syslogRoute := routes.BuildSyslogUDPRoute(cluster.Name, cluster.Namespace, gatewayAPI, true)
		if err := controllerutil.SetControllerReference(cluster, syslogRoute, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for syslog UDPRoute: %w", err)
		}
		if err := r.createOrUpdateUDPRoute(ctx, syslogRoute); err != nil {
			return err
		}
	} else {
		if err := r.deleteUDPRouteIfExists(ctx, syslogRouteName, cluster.Namespace); err != nil {
			return err
		}
	}

	return nil
}

// reconcileIndexerRoutes reconciles HTTPRoute for the Indexer
func (r *GatewayReconciler) reconcileIndexerRoutes(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get GatewayAPI spec from Indexer
	var gatewayAPI *wazuhv1.GatewayAPISpec
	if cluster.Spec.Indexer != nil && cluster.Spec.Indexer.GatewayAPI != nil {
		gatewayAPI = cluster.Spec.Indexer.GatewayAPI
	}

	routeName := fmt.Sprintf("%s-indexer", cluster.Name)

	// If GatewayAPI is not enabled, delete existing route if any
	if gatewayAPI == nil || !gatewayAPI.Enabled {
		return r.deleteHTTPRouteIfExists(ctx, routeName, cluster.Namespace)
	}

	// Validate mutual exclusivity with Ingress
	if cluster.Spec.Indexer.Ingress != nil && cluster.Spec.Indexer.Ingress.Enabled {
		return fmt.Errorf("indexer: GatewayAPI and Ingress cannot both be enabled")
	}

	log.Info("Reconciling Indexer HTTPRoute", "name", routeName)

	// Build and create/update HTTPRoute
	httpRoute := routes.BuildIndexerHTTPRoute(cluster.Name, cluster.Namespace, gatewayAPI)
	if err := controllerutil.SetControllerReference(cluster, httpRoute, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for indexer HTTPRoute: %w", err)
	}

	return r.createOrUpdateHTTPRoute(ctx, httpRoute)
}

// createOrUpdateHTTPRoute creates or updates an HTTPRoute
func (r *GatewayReconciler) createOrUpdateHTTPRoute(ctx context.Context, route *gatewayv1.HTTPRoute) error {
	log := logf.FromContext(ctx)

	existing := &gatewayv1.HTTPRoute{}
	err := r.Get(ctx, types.NamespacedName{Name: route.Name, Namespace: route.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating HTTPRoute", "name", route.Name)
		createErr := r.Create(ctx, route)
		if createErr != nil && utils.IsCRDNotInstalledError(createErr) {
			return fmt.Errorf("gateway API CRDs not installed: HTTPRoute CRD is required to enable GatewayAPI, install Gateway API CRDs first (kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml)")
		}
		return createErr
	} else if err != nil {
		if utils.IsCRDNotInstalledError(err) {
			return fmt.Errorf("gateway API CRDs not installed: HTTPRoute CRD is required to enable GatewayAPI, install Gateway API CRDs first (kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/standard-install.yaml)")
		}
		return fmt.Errorf("failed to get HTTPRoute: %w", err)
	}

	// Update existing route
	log.V(1).Info("Updating HTTPRoute", "name", route.Name)
	route.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, route)
}

// createOrUpdateTCPRoute creates or updates a TCPRoute
func (r *GatewayReconciler) createOrUpdateTCPRoute(ctx context.Context, route *gatewayv1alpha2.TCPRoute) error {
	log := logf.FromContext(ctx)

	existing := &gatewayv1alpha2.TCPRoute{}
	err := r.Get(ctx, types.NamespacedName{Name: route.Name, Namespace: route.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating TCPRoute", "name", route.Name)
		createErr := r.Create(ctx, route)
		if createErr != nil && utils.IsCRDNotInstalledError(createErr) {
			return fmt.Errorf("gateway API CRDs not installed: TCPRoute CRD is required for TCP routing, install Gateway API experimental CRDs first (kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/experimental-install.yaml)")
		}
		return createErr
	} else if err != nil {
		if utils.IsCRDNotInstalledError(err) {
			return fmt.Errorf("gateway API CRDs not installed: TCPRoute CRD is required for TCP routing, install Gateway API experimental CRDs first (kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/experimental-install.yaml)")
		}
		return fmt.Errorf("failed to get TCPRoute: %w", err)
	}

	// Update existing route
	log.V(1).Info("Updating TCPRoute", "name", route.Name)
	route.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, route)
}

// createOrUpdateUDPRoute creates or updates a UDPRoute
func (r *GatewayReconciler) createOrUpdateUDPRoute(ctx context.Context, route *gatewayv1alpha2.UDPRoute) error {
	log := logf.FromContext(ctx)

	existing := &gatewayv1alpha2.UDPRoute{}
	err := r.Get(ctx, types.NamespacedName{Name: route.Name, Namespace: route.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating UDPRoute", "name", route.Name)
		createErr := r.Create(ctx, route)
		if createErr != nil && utils.IsCRDNotInstalledError(createErr) {
			return fmt.Errorf("gateway API CRDs not installed: UDPRoute CRD is required for UDP routing, install Gateway API experimental CRDs first (kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/experimental-install.yaml)")
		}
		return createErr
	} else if err != nil {
		if utils.IsCRDNotInstalledError(err) {
			return fmt.Errorf("gateway API CRDs not installed: UDPRoute CRD is required for UDP routing, install Gateway API experimental CRDs first (kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/latest/download/experimental-install.yaml)")
		}
		return fmt.Errorf("failed to get UDPRoute: %w", err)
	}

	// Update existing route
	log.V(1).Info("Updating UDPRoute", "name", route.Name)
	route.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, route)
}

// deleteHTTPRouteIfExists deletes an HTTPRoute if it exists
func (r *GatewayReconciler) deleteHTTPRouteIfExists(ctx context.Context, name, namespace string) error {
	log := logf.FromContext(ctx)

	route := &gatewayv1.HTTPRoute{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, route)
	if err != nil {
		if errors.IsNotFound(err) || utils.IsCRDNotInstalledError(err) {
			// HTTPRoute doesn't exist or CRD not installed - nothing to delete
			return nil
		}
		return fmt.Errorf("failed to get HTTPRoute for deletion: %w", err)
	}

	log.Info("Deleting HTTPRoute", "name", name)
	return r.Delete(ctx, route)
}

// deleteTCPRouteIfExists deletes a TCPRoute if it exists
func (r *GatewayReconciler) deleteTCPRouteIfExists(ctx context.Context, name, namespace string) error {
	log := logf.FromContext(ctx)

	route := &gatewayv1alpha2.TCPRoute{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, route)
	if err != nil {
		if errors.IsNotFound(err) || utils.IsCRDNotInstalledError(err) {
			// TCPRoute doesn't exist or CRD not installed - nothing to delete
			return nil
		}
		return fmt.Errorf("failed to get TCPRoute for deletion: %w", err)
	}

	log.Info("Deleting TCPRoute", "name", name)
	return r.Delete(ctx, route)
}

// deleteUDPRouteIfExists deletes a UDPRoute if it exists
func (r *GatewayReconciler) deleteUDPRouteIfExists(ctx context.Context, name, namespace string) error {
	log := logf.FromContext(ctx)

	route := &gatewayv1alpha2.UDPRoute{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, route)
	if err != nil {
		if errors.IsNotFound(err) || utils.IsCRDNotInstalledError(err) {
			// UDPRoute doesn't exist or CRD not installed - nothing to delete
			return nil
		}
		return fmt.Errorf("failed to get UDPRoute for deletion: %w", err)
	}

	log.Info("Deleting UDPRoute", "name", name)
	return r.Delete(ctx, route)
}
