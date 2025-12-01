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
	"net"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/deployments"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/secrets"
	osservices "github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/services"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// DashboardReconciler handles reconciliation of OpenSearch Dashboard
type DashboardReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// NewDashboardReconciler creates a new DashboardReconciler
func NewDashboardReconciler(c client.Client, scheme *runtime.Scheme) *DashboardReconciler {
	return &DashboardReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithRecorder sets the event recorder for the reconciler
func (r *DashboardReconciler) WithRecorder(recorder record.EventRecorder) *DashboardReconciler {
	r.Recorder = recorder
	return r
}

// Reconcile reconciles the OpenSearch Dashboard
func (r *DashboardReconciler) Reconcile(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Reconcile Secrets
	if err := r.reconcileSecrets(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard secrets: %w", err)
	}

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard configmap: %w", err)
	}

	// Reconcile Service
	if err := r.reconcileService(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard service: %w", err)
	}

	// Reconcile Deployment
	if err := r.reconcileDeployment(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard deployment: %w", err)
	}

	log.Info("Dashboard reconciliation completed")
	return nil
}

// reconcileSecrets reconciles dashboard secrets
func (r *DashboardReconciler) reconcileSecrets(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if certificates already exist
	certsSecretName := fmt.Sprintf("%s-dashboard-certs", cluster.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: certsSecretName, Namespace: cluster.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		// Get CA from indexer certificates
		indexerCertsSecret := &corev1.Secret{}
		indexerCertsName := fmt.Sprintf("%s-indexer-certs", cluster.Name)
		if err := r.Get(ctx, types.NamespacedName{Name: indexerCertsName, Namespace: cluster.Namespace}, indexerCertsSecret); err != nil {
			return fmt.Errorf("failed to get indexer certificates (required for dashboard): %w", err)
		}

		caCertPEM, ok := indexerCertsSecret.Data[constants.SecretKeyCACert]
		if !ok {
			return fmt.Errorf("CA certificate not found in indexer secrets")
		}

		// Parse the CA to sign dashboard certificate
		// We need the CA private key which might be stored separately or we generate a new CA
		// For simplicity, we'll generate dashboard-specific certs using the same approach
		certs, err := r.generateDashboardCertificates(ctx, cluster, caCertPEM)
		if err != nil {
			return fmt.Errorf("failed to generate dashboard certificates: %w", err)
		}

		certsBuilder := secrets.NewDashboardCertsSecretBuilder(cluster.Name, cluster.Namespace)
		certsBuilder.WithCACert(certs.caCert).
			WithDashboardCert(certs.dashboardCert).
			WithDashboardKey(certs.dashboardKey)

		certsSecret := certsBuilder.Build()
		if err := controllerutil.SetControllerReference(cluster, certsSecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for dashboard certs: %w", err)
		}

		log.Info("Creating Dashboard certificates secret", "name", certsSecret.Name)
		if err := r.Create(ctx, certsSecret); err != nil {
			return fmt.Errorf("failed to create dashboard certs secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get dashboard certs secret: %w", err)
	}

	return nil
}

// dashboardCertificates holds all generated certificates for the dashboard
type dashboardCertificates struct {
	caCert        []byte
	dashboardCert []byte
	dashboardKey  []byte
}

// generateDashboardCertificates generates certificates for the dashboard
// This generates a self-signed certificate for the dashboard HTTPS server.
// The CA for connecting to OpenSearch comes from the indexer-certs secret.
func (r *DashboardReconciler) generateDashboardCertificates(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, indexerCACert []byte) (*dashboardCertificates, error) {
	log := logf.FromContext(ctx)

	// Generate a self-signed CA for dashboard's HTTPS server certificate
	// This is separate from the indexer CA (which is used for OpenSearch connection)
	caConfig := certificates.DefaultCAConfig(fmt.Sprintf("%s-dashboard-ca", cluster.Name))
	ca, err := certificates.GenerateCA(caConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	log.V(1).Info("Generated CA certificate for dashboard HTTPS server")

	// Generate dashboard certificate with SANs
	dashboardConfig := certificates.DefaultDashboardCertConfig()
	dashboardConfig.DNSNames = certificates.GenerateDashboardSANs(cluster.Name, cluster.Namespace)
	dashboardConfig.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	dashboardCert, err := certificates.GenerateDashboardCert(dashboardConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dashboard certificate: %w", err)
	}
	log.V(1).Info("Generated dashboard certificate", "sans", dashboardConfig.DNSNames)

	// Return the dashboard's own CA for its HTTPS server
	// The indexer CA is mounted separately via indexer-certs volume
	return &dashboardCertificates{
		caCert:        ca.CertificatePEM, // Dashboard's own CA for HTTPS server
		dashboardCert: dashboardCert.CertificatePEM,
		dashboardKey:  dashboardCert.PrivateKeyPEM,
	}, nil
}

// reconcileConfigMap reconciles the dashboard ConfigMap
func (r *DashboardReconciler) reconcileConfigMap(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Build dashboard configuration (already generates opensearch_dashboards.yml)
	configBuilder := configmaps.NewDashboardConfigMapBuilder(cluster.Name, cluster.Namespace)

	// Pass wazuhPlugin configuration if defined
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.WazuhPlugin != nil {
		configBuilder.WithWazuhPlugin(cluster.Spec.Dashboard.WazuhPlugin)

		// Resolve credentials from secrets for API endpoints
		resolvedCredentials, err := r.resolveAPIEndpointCredentials(ctx, cluster.Namespace, cluster.Spec.Dashboard.WazuhPlugin)
		if err != nil {
			log.Error(err, "Failed to resolve API endpoint credentials from secrets")
			// Continue without resolved credentials - will fall back to inline values
		} else if len(resolvedCredentials) > 0 {
			configBuilder.WithResolvedCredentials(resolvedCredentials)
		}
	}

	configMap := configBuilder.Build()

	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard configmap: %w", err)
	}

	return r.createOrUpdate(ctx, configMap)
}

// getConfigHash retrieves the current config hash from the dashboard ConfigMap
func (r *DashboardReconciler) getConfigHash(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) string {
	configMapName := fmt.Sprintf("%s-dashboard-config", cluster.Name)
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: cluster.Namespace}, configMap)
	if err != nil {
		return ""
	}
	return patch.ComputeConfigHash(configMap.Data)
}

// resolveAPIEndpointCredentials resolves credentials from secret references for API endpoints
// Returns a map with keys "endpointID:username" and "endpointID:password"
func (r *DashboardReconciler) resolveAPIEndpointCredentials(ctx context.Context, namespace string, wazuhPlugin *wazuhv1alpha1.WazuhPluginConfig) (map[string]string, error) {
	resolvedCredentials := make(map[string]string)

	if wazuhPlugin == nil {
		return resolvedCredentials, nil
	}

	// Resolve credentials for explicit API endpoints
	for _, endpoint := range wazuhPlugin.APIEndpoints {
		if endpoint.CredentialsSecretRef != nil && endpoint.CredentialsSecretRef.SecretName != "" {
			secret := &corev1.Secret{}
			secretName := endpoint.CredentialsSecretRef.SecretName

			err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret)
			if err != nil {
				return nil, fmt.Errorf("failed to get secret %s for endpoint %s: %w", secretName, endpoint.ID, err)
			}

			// Get username key (default: "username")
			usernameKey := endpoint.CredentialsSecretRef.UsernameKey
			if usernameKey == "" {
				usernameKey = "username"
			}
			if usernameBytes, ok := secret.Data[usernameKey]; ok {
				resolvedCredentials[endpoint.ID+":username"] = string(usernameBytes)
			}

			// Get password key (default: "password")
			passwordKey := endpoint.CredentialsSecretRef.PasswordKey
			if passwordKey == "" {
				passwordKey = "password"
			}
			if passwordBytes, ok := secret.Data[passwordKey]; ok {
				resolvedCredentials[endpoint.ID+":password"] = string(passwordBytes)
			}
		}
	}

	// Resolve credentials for default API endpoint (when no explicit endpoints defined)
	if len(wazuhPlugin.APIEndpoints) == 0 && wazuhPlugin.DefaultAPIEndpoint != nil && wazuhPlugin.DefaultAPIEndpoint.CredentialsSecret != nil {
		secretRef := wazuhPlugin.DefaultAPIEndpoint.CredentialsSecret
		if secretRef.SecretName != "" {
			secret := &corev1.Secret{}
			err := r.Get(ctx, types.NamespacedName{Name: secretRef.SecretName, Namespace: namespace}, secret)
			if err != nil {
				return nil, fmt.Errorf("failed to get secret %s for default API endpoint: %w", secretRef.SecretName, err)
			}

			// Get username key (default: "username")
			usernameKey := secretRef.UsernameKey
			if usernameKey == "" {
				usernameKey = "username"
			}
			if usernameBytes, ok := secret.Data[usernameKey]; ok {
				resolvedCredentials["default:username"] = string(usernameBytes)
			}

			// Get password key (default: "password")
			passwordKey := secretRef.PasswordKey
			if passwordKey == "" {
				passwordKey = "password"
			}
			if passwordBytes, ok := secret.Data[passwordKey]; ok {
				resolvedCredentials["default:password"] = string(passwordBytes)
			}
		}
	}

	return resolvedCredentials, nil
}

// reconcileService reconciles the dashboard service
func (r *DashboardReconciler) reconcileService(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	serviceBuilder := osservices.NewDashboardServiceBuilder(cluster.Name, cluster.Namespace)
	service := serviceBuilder.Build()

	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard service: %w", err)
	}

	return r.createOrUpdate(ctx, service)
}

// reconcileDeployment reconciles the dashboard Deployment
func (r *DashboardReconciler) reconcileDeployment(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) error {
	return r.reconcileDeploymentWithCertHash(ctx, cluster, "")
}

// reconcileDeploymentWithCertHash reconciles the dashboard Deployment with an optional certificate hash
// When the cert hash changes, the deployment will be updated which triggers a pod rollout
func (r *DashboardReconciler) reconcileDeploymentWithCertHash(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	deployBuilder := deployments.NewDashboardDeploymentBuilder(cluster.Name, cluster.Namespace)

	// Set version from cluster spec
	if cluster.Spec.Version != "" {
		deployBuilder.WithVersion(cluster.Spec.Version)
	}

	if cluster.Spec.Dashboard.Replicas > 0 {
		deployBuilder.WithReplicas(cluster.Spec.Dashboard.Replicas)
	}
	if cluster.Spec.Dashboard.Resources != nil {
		deployBuilder.WithResources(cluster.Spec.Dashboard.Resources)
	}

	// Set cert hash to trigger pod restart on cert renewal
	if certHash != "" {
		deployBuilder.WithCertHash(certHash)
	}

	deployment := deployBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, deployment, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard deployment: %w", err)
	}

	found := &appsv1.Deployment{}
	err := r.Get(ctx, types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Dashboard Deployment", "name", deployment.Name, "certHash", utils.ShortHash(certHash))
		if err := r.Create(ctx, deployment); err != nil {
			return fmt.Errorf("failed to create dashboard deployment: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get dashboard deployment: %w", err)
	}

	// Check if update is needed (cert hash changed)
	existingCertHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
	}

	// Update if cert hash changed (including from empty to non-empty)
	needsUpdate := false
	if certHash != existingCertHash {
		if certHash != "" {
			log.Info("Updating Dashboard Deployment due to certificate hash change",
				"name", deployment.Name,
				"oldHash", utils.ShortHash(existingCertHash),
				"newHash", utils.ShortHash(certHash))
			needsUpdate = true
		}
	}

	if needsUpdate {
		deployment.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, deployment); err != nil {
			return fmt.Errorf("failed to update dashboard deployment: %w", err)
		}

		// Wait for the deployment to be ready after update (graceful rollout)
		// This ensures new pods are healthy before the reconcile completes
		log.Info("Waiting for Dashboard deployment to be ready after certificate renewal",
			"name", deployment.Name,
			"timeout", utils.DefaultRolloutTimeout)

		waiter := utils.NewRolloutWaiter(r.Client)
		result := waiter.WaitForDeploymentReadyWithResult(ctx, deployment.Namespace, deployment.Name)
		if result.TimedOut {
			log.Error(result.Error, "Timeout waiting for Dashboard deployment to be ready",
				"name", deployment.Name,
				"timeout", utils.DefaultRolloutTimeout)
			// Don't fail the reconcile on timeout - the deployment strategy ensures
			// maxUnavailable=0, so old pods are kept until new ones are ready
			return nil
		}
		if result.Error != nil {
			return fmt.Errorf("error waiting for dashboard deployment to be ready: %w", result.Error)
		}

		log.Info("Dashboard deployment is ready after certificate renewal", "name", deployment.Name)
	}

	return nil
}

// ReconcileWithCertHash reconciles the OpenSearch Dashboard with certificate hash for pod restart
// DEPRECATED: Use ReconcileNonBlocking for non-blocking rollouts
func (r *DashboardReconciler) ReconcileWithCertHash(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	// Reconcile Secrets
	if err := r.reconcileSecrets(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard secrets: %w", err)
	}

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard configmap: %w", err)
	}

	// Reconcile Service
	if err := r.reconcileService(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard service: %w", err)
	}

	// Reconcile Deployment with cert hash
	if err := r.reconcileDeploymentWithCertHash(ctx, cluster, certHash); err != nil {
		return fmt.Errorf("failed to reconcile dashboard deployment: %w", err)
	}

	log.Info("Dashboard reconciliation completed")
	return nil
}

// DashboardReconcileResult contains the result of dashboard reconciliation
type DashboardReconcileResult struct {
	// PendingRollout contains a rollout that was initiated but not yet complete
	PendingRollout *utils.PendingRollout
	// Error if any occurred during reconciliation
	Error error
}

// ReconcileNonBlocking reconciles the OpenSearch Dashboard without blocking on rollouts
// Returns a pending rollout that should be tracked and monitored by the caller
func (r *DashboardReconciler) ReconcileNonBlocking(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) DashboardReconcileResult {
	log := logf.FromContext(ctx)

	// Reconcile Secrets
	if err := r.reconcileSecrets(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard secrets: %w", err)}
	}

	// Reconcile ConfigMap
	if err := r.reconcileConfigMap(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard configmap: %w", err)}
	}

	// Reconcile Service
	if err := r.reconcileService(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard service: %w", err)}
	}

	// Reconcile Deployment with cert hash (non-blocking)
	pendingRollout, err := r.reconcileDeploymentNonBlocking(ctx, cluster, certHash)
	if err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard deployment: %w", err)}
	}

	log.Info("Dashboard reconciliation completed (non-blocking)", "hasPendingRollout", pendingRollout != nil)
	return DashboardReconcileResult{PendingRollout: pendingRollout}
}

// reconcileDeploymentNonBlocking reconciles the dashboard Deployment without blocking on rollout
// Returns a PendingRollout if a rollout was initiated, nil otherwise
func (r *DashboardReconciler) reconcileDeploymentNonBlocking(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, certHash string) (*utils.PendingRollout, error) {
	log := logf.FromContext(ctx)

	// Extract spec values for hash computation
	replicas := cluster.Spec.Dashboard.Replicas
	version := cluster.Spec.Version
	resources := cluster.Spec.Dashboard.Resources
	image := "" // Will use default from builder

	// Compute spec hash for change detection
	specHash, err := patch.ComputeDashboardSpecHash(replicas, version, resources, image)
	if err != nil {
		log.Error(err, "Failed to compute dashboard spec hash, continuing without spec tracking")
		specHash = ""
	}

	// Compute config hash from ConfigMap for change detection
	configHash := r.getConfigHash(ctx, cluster)

	deployBuilder := deployments.NewDashboardDeploymentBuilder(cluster.Name, cluster.Namespace)

	if cluster.Spec.Version != "" {
		deployBuilder.WithVersion(cluster.Spec.Version)
	}

	if cluster.Spec.Dashboard.Replicas > 0 {
		deployBuilder.WithReplicas(cluster.Spec.Dashboard.Replicas)
	}
	if cluster.Spec.Dashboard.Resources != nil {
		deployBuilder.WithResources(cluster.Spec.Dashboard.Resources)
	}

	if certHash != "" {
		deployBuilder.WithCertHash(certHash)
	}

	// Set spec hash for change detection
	if specHash != "" {
		deployBuilder.WithSpecHash(specHash)
	}

	// Set config hash to trigger pod restart on config changes
	if configHash != "" {
		deployBuilder.WithConfigHash(configHash)
	}

	deployment := deployBuilder.Build()
	if err := controllerutil.SetControllerReference(cluster, deployment, r.Scheme); err != nil {
		return nil, fmt.Errorf("failed to set controller reference for dashboard deployment: %w", err)
	}

	found := &appsv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Dashboard Deployment", "name", deployment.Name, "certHash", utils.ShortHash(certHash), "specHash", patch.ShortHash(specHash))
		if err := r.Create(ctx, deployment); err != nil {
			return nil, fmt.Errorf("failed to create dashboard deployment: %w", err)
		}
		// New Deployment - return pending rollout to track initial readiness
		return &utils.PendingRollout{
			Component: "dashboard",
			Namespace: deployment.Namespace,
			Name:      deployment.Name,
			Type:      utils.RolloutTypeDeployment,
			StartTime: time.Now(),
			Reason:    "initial-creation",
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get dashboard deployment: %w", err)
	}

	// Check if update is needed
	needsUpdate := false
	updateReason := ""

	// Get existing hashes from annotations
	existingCertHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
	}
	existingSpecHash := ""
	if found.Annotations != nil {
		existingSpecHash = found.Annotations[constants.AnnotationSpecHash]
	}

	// Check spec hash (version, resources, replicas changes)
	if specHash != "" && specHash != existingSpecHash {
		log.Info("Dashboard spec changed",
			"name", deployment.Name,
			"oldSpecHash", patch.ShortHash(existingSpecHash),
			"newSpecHash", patch.ShortHash(specHash))
		needsUpdate = true
		updateReason = "spec-change"

		// Emit Kubernetes event for spec change
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "SpecChanged",
				fmt.Sprintf("Dashboard spec changed (version=%s, replicas=%d)", version, replicas))
		}
	}

	// Check cert hash (requires pod restart)
	if certHash != "" && certHash != existingCertHash {
		log.Info("Dashboard certificate hash changed",
			"name", deployment.Name,
			"oldHash", utils.ShortHash(existingCertHash),
			"newHash", utils.ShortHash(certHash))
		needsUpdate = true
		if updateReason == "" {
			updateReason = "certificate-renewal"
		} else {
			updateReason = updateReason + ",certificate-renewal"
		}
	}

	// Check config hash (ConfigMap content changes)
	existingConfigHash := ""
	if found.Spec.Template.Annotations != nil {
		existingConfigHash = found.Spec.Template.Annotations[constants.AnnotationConfigHash]
	}

	if configHash != "" && configHash != existingConfigHash {
		log.Info("Dashboard ConfigMap hash changed",
			"name", deployment.Name,
			"oldConfigHash", patch.ShortHash(existingConfigHash),
			"newConfigHash", patch.ShortHash(configHash))
		needsUpdate = true
		if updateReason == "" {
			updateReason = "config-change"
		} else {
			updateReason = updateReason + ",config-change"
		}

		// Emit event for config change detection
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, "ConfigChanged",
				fmt.Sprintf("Dashboard ConfigMap changed, pods will restart (Deployment %s)", deployment.Name))
		}
	}

	if needsUpdate {
		log.Info("Updating Dashboard Deployment (non-blocking)",
			"name", deployment.Name,
			"reason", updateReason)

		deployment.SetResourceVersion(found.GetResourceVersion())
		if err := r.Update(ctx, deployment); err != nil {
			return nil, fmt.Errorf("failed to update dashboard deployment: %w", err)
		}

		// Return pending rollout instead of waiting
		return &utils.PendingRollout{
			Component: "dashboard",
			Namespace: deployment.Namespace,
			Name:      deployment.Name,
			Type:      utils.RolloutTypeDeployment,
			StartTime: time.Now(),
			Reason:    updateReason,
		}, nil
	}

	return nil, nil
}

// GetStatus gets the dashboard status
func (r *DashboardReconciler) GetStatus(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*wazuhv1alpha1.ComponentStatus, error) {
	dep := &appsv1.Deployment{}
	name := fmt.Sprintf("%s-dashboard", cluster.Name)

	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, dep); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return &wazuhv1alpha1.ComponentStatus{
		Replicas:      dep.Status.Replicas,
		ReadyReplicas: dep.Status.ReadyReplicas,
		Phase:         getDeploymentPhase(dep),
	}, nil
}

// createOrUpdate creates or updates a resource
func (r *DashboardReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	key := types.NamespacedName{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}

	existing := obj.DeepCopyObject().(client.Object)

	err := r.Get(ctx, key, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating resource", "kind", obj.GetObjectKind().GroupVersionKind().Kind, "name", obj.GetName())
		return r.Create(ctx, obj)
	} else if err != nil {
		return err
	}

	// Preserve immutable fields for Services
	if svc, ok := obj.(*corev1.Service); ok {
		existingSvc := existing.(*corev1.Service)
		svc.Spec.ClusterIP = existingSvc.Spec.ClusterIP
		svc.Spec.ClusterIPs = existingSvc.Spec.ClusterIPs
	}

	log.V(1).Info("Updating resource", "kind", obj.GetObjectKind().GroupVersionKind().Kind, "name", obj.GetName())
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

// getDeploymentPhase returns the phase of a Deployment
func getDeploymentPhase(dep *appsv1.Deployment) string {
	if dep.Status.ReadyReplicas == 0 {
		return "Starting"
	}
	if dep.Status.ReadyReplicas < dep.Status.Replicas {
		return "Degraded"
	}
	if dep.Status.UpdatedReplicas < dep.Status.Replicas {
		return "Updating"
	}
	return "Ready"
}

// ReconcileStandalone reconciles a standalone OpenSearchDashboard resource
func (r *DashboardReconciler) ReconcileStandalone(ctx context.Context, dashboard *wazuhv1alpha1.OpenSearchDashboard) error {
	log := logf.FromContext(ctx)

	// Check if certificates exist, generate if needed
	certsSecretName := fmt.Sprintf("%s-certs", dashboard.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: certsSecretName, Namespace: dashboard.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		certs, err := r.generateStandaloneDashboardCertificates(ctx, dashboard)
		if err != nil {
			return fmt.Errorf("failed to generate certificates: %w", err)
		}

		certsBuilder := secrets.NewDashboardCertsSecretBuilder(dashboard.Name, dashboard.Namespace)
		certsBuilder.WithCACert(certs.caCert).
			WithDashboardCert(certs.dashboardCert).
			WithDashboardKey(certs.dashboardKey)

		certsSecret := certsBuilder.Build()
		if err := controllerutil.SetControllerReference(dashboard, certsSecret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference for certs: %w", err)
		}

		log.Info("Creating standalone dashboard certificates", "name", certsSecret.Name)
		if err := r.Create(ctx, certsSecret); err != nil {
			return fmt.Errorf("failed to create certs secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get certs secret: %w", err)
	}

	// Build ConfigMap
	configBuilder := configmaps.NewDashboardConfigMapBuilder(dashboard.Name, dashboard.Namespace)
	// Use IndexerRef to determine the indexer host
	if dashboard.Spec.IndexerRef != "" {
		indexerHost := fmt.Sprintf("%s-indexer.%s.svc.cluster.local", dashboard.Spec.IndexerRef, dashboard.Namespace)
		configBuilder.WithIndexerHost(indexerHost)
	}
	// Pass wazuhPlugin configuration if defined
	if dashboard.Spec.WazuhPlugin != nil {
		configBuilder.WithWazuhPlugin(dashboard.Spec.WazuhPlugin)

		// Resolve credentials from secrets for API endpoints
		resolvedCredentials, err := r.resolveAPIEndpointCredentials(ctx, dashboard.Namespace, dashboard.Spec.WazuhPlugin)
		if err != nil {
			log.Error(err, "Failed to resolve API endpoint credentials from secrets")
			// Continue without resolved credentials - will fall back to inline values
		} else if len(resolvedCredentials) > 0 {
			configBuilder.WithResolvedCredentials(resolvedCredentials)
		}
	}
	configMap := configBuilder.Build()

	if err := controllerutil.SetControllerReference(dashboard, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return fmt.Errorf("failed to reconcile configmap: %w", err)
	}

	// Build Service
	serviceBuilder := osservices.NewDashboardServiceBuilder(dashboard.Name, dashboard.Namespace)
	service := serviceBuilder.Build()
	if err := controllerutil.SetControllerReference(dashboard, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for service: %w", err)
	}
	if err := r.createOrUpdate(ctx, service); err != nil {
		return fmt.Errorf("failed to reconcile service: %w", err)
	}

	// Build Deployment
	deployBuilder := deployments.NewDashboardDeploymentBuilder(dashboard.Name, dashboard.Namespace)
	if dashboard.Spec.Version != "" {
		deployBuilder.WithVersion(dashboard.Spec.Version)
	}
	if dashboard.Spec.Replicas > 0 {
		deployBuilder.WithReplicas(dashboard.Spec.Replicas)
	}
	if dashboard.Spec.Resources != nil {
		deployBuilder.WithResources(dashboard.Spec.Resources)
	}

	deploy := deployBuilder.Build()
	if err := controllerutil.SetControllerReference(dashboard, deploy, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for deployment: %w", err)
	}

	foundDeploy := &appsv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Name: deploy.Name, Namespace: deploy.Namespace}, foundDeploy)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating standalone Dashboard Deployment", "name", deploy.Name)
		if err := r.Create(ctx, deploy); err != nil {
			return fmt.Errorf("failed to create deployment: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get deployment: %w", err)
	}

	log.Info("Standalone dashboard reconciliation completed", "name", dashboard.Name)
	return nil
}

// generateStandaloneDashboardCertificates generates certificates for standalone dashboard
func (r *DashboardReconciler) generateStandaloneDashboardCertificates(ctx context.Context, dashboard *wazuhv1alpha1.OpenSearchDashboard) (*dashboardCertificates, error) {
	log := logf.FromContext(ctx)

	// Generate CA
	caConfig := certificates.DefaultCAConfig(fmt.Sprintf("%s-ca", dashboard.Name))
	ca, err := certificates.GenerateCA(caConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	log.V(1).Info("Generated CA certificate for standalone dashboard")

	dashboardConfig := certificates.DefaultDashboardCertConfig()
	dashboardConfig.DNSNames = certificates.GenerateDashboardSANs(dashboard.Name, dashboard.Namespace)
	dashboardConfig.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	dashboardCert, err := certificates.GenerateDashboardCert(dashboardConfig, ca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dashboard certificate: %w", err)
	}

	return &dashboardCertificates{
		caCert:        ca.CertificatePEM,
		dashboardCert: dashboardCert.CertificatePEM,
		dashboardKey:  dashboardCert.PrivateKeyPEM,
	}, nil
}
