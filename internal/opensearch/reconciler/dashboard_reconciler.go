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
	"net"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/certificates"
	opensearchcerts "github.com/MaximeWewer/wazuh-operator/internal/certificates/opensearch"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/configmaps"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/deployments"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/hpa"
	osservices "github.com/MaximeWewer/wazuh-operator/internal/opensearch/builder/services"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/patch"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/pdb"
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
func (r *DashboardReconciler) Reconcile(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
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

	// Reconcile PodDisruptionBudget
	if err := r.reconcilePDB(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard PDB: %w", err)
	}

	// Reconcile HorizontalPodAutoscaler
	if err := r.reconcileHPA(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard HPA: %w", err)
	}

	log.Info("Dashboard reconciliation completed")
	return nil
}

// reconcileSecrets reconciles dashboard secrets
func (r *DashboardReconciler) reconcileSecrets(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Check if certificates already exist
	certsSecretName := constants.DashboardCertsName(cluster.Name)
	found := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: certsSecretName, Namespace: cluster.Namespace}, found)

	if err != nil && errors.IsNotFound(err) {
		// Get CA from indexer certificates
		indexerCertsSecret := &corev1.Secret{}
		indexerCertsName := constants.IndexerCertsName(cluster.Name)
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

		certsBuilder := opensearchcerts.NewDashboardCertsSecretBuilder(cluster.Name, cluster.Namespace)
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
func (r *DashboardReconciler) generateDashboardCertificates(ctx context.Context, cluster *wazuhv1.WazuhCluster, _ []byte) (*dashboardCertificates, error) {
	log := logf.FromContext(ctx)

	// Generate a self-signed CA for dashboard's HTTPS server certificate
	// This is separate from the indexer CA (which is used for OpenSearch connection)
	caConfig := certificates.DefaultCAConfig(constants.DashboardCAName(cluster.Name))
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
func (r *DashboardReconciler) reconcileConfigMap(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
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

	configMap, err := configBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build dashboard configmap: %w", err)
	}

	if err := controllerutil.SetControllerReference(cluster, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return err
	}

	// Reconcile the wazuh.yml Secret (credentials stored in a Secret, not a ConfigMap)
	wazuhSecret := configBuilder.BuildWazuhConfigSecret()
	if err := controllerutil.SetControllerReference(cluster, wazuhSecret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard wazuh config secret: %w", err)
	}

	return r.createOrUpdate(ctx, wazuhSecret)
}

// getConfigHash retrieves the current config hash from the dashboard ConfigMap
func (r *DashboardReconciler) getConfigHash(ctx context.Context, cluster *wazuhv1.WazuhCluster) string {
	configMapName := constants.DashboardConfigName(cluster.Name)
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: cluster.Namespace}, configMap)
	if err != nil {
		return ""
	}
	return patch.ComputeConfigHash(configMap.Data)
}

// resolveAPIEndpointCredentials resolves credentials from secret references for API endpoints
// Returns a map with keys "endpointID:username" and "endpointID:password"
func (r *DashboardReconciler) resolveAPIEndpointCredentials(ctx context.Context, namespace string, wazuhPlugin *wazuhv1.WazuhPluginConfig) (map[string]string, error) {
	resolvedCredentials := make(map[string]string)

	if wazuhPlugin == nil {
		return resolvedCredentials, nil
	}

	// Resolve credentials for explicit API endpoints
	for _, endpoint := range wazuhPlugin.APIEndpoints {
		if endpoint.CredentialsSecretRef == nil || endpoint.CredentialsSecretRef.SecretName == "" {
			continue
		}

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
func (r *DashboardReconciler) reconcileService(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	serviceBuilder := osservices.NewDashboardServiceBuilder(cluster.Name, cluster.Namespace)
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.Service != nil && len(cluster.Spec.Dashboard.Service.Annotations) > 0 {
		serviceBuilder.WithAnnotations(cluster.Spec.Dashboard.Service.Annotations)
	}
	service := serviceBuilder.Build()

	if err := controllerutil.SetControllerReference(cluster, service, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard service: %w", err)
	}

	return r.createOrUpdate(ctx, service)
}

// reconcileDeployment reconciles the dashboard Deployment
func (r *DashboardReconciler) reconcileDeployment(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	return r.reconcileDeploymentWithCertHash(ctx, cluster, "")
}

// reconcileDeploymentWithCertHash reconciles the dashboard Deployment with an optional certificate hash
// When the cert hash changes, the deployment will be updated which triggers a pod rollout
func (r *DashboardReconciler) reconcileDeploymentWithCertHash(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) error {
	log := logf.FromContext(ctx)

	deployBuilder := deployments.NewDashboardDeploymentBuilder(cluster.Name, cluster.Namespace)

	// Set version from cluster spec
	if cluster.Spec.Version != "" {
		deployBuilder.WithVersion(cluster.Spec.Version)
	}

	if cluster.Spec.Dashboard != nil {
		if cluster.Spec.Dashboard.Replicas > 0 {
			deployBuilder.WithReplicas(cluster.Spec.Dashboard.Replicas)
		}
		if cluster.Spec.Dashboard.Resources != nil {
			deployBuilder.WithResources(cluster.Spec.Dashboard.Resources)
		}
		if len(cluster.Spec.Dashboard.Annotations) > 0 {
			deployBuilder.WithAnnotations(cluster.Spec.Dashboard.Annotations)
		}
		if len(cluster.Spec.Dashboard.PodAnnotations) > 0 {
			deployBuilder.WithPodAnnotations(cluster.Spec.Dashboard.PodAnnotations)
		}
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

	// Check if update is needed (cert hash changed or replicas changed)
	existingCertHash := ""
	if found.Spec.Template.Annotations != nil {
		existingCertHash = found.Spec.Template.Annotations[constants.AnnotationCertHash]
	}

	// Update if cert hash changed (including from empty to non-empty)
	needsUpdate := false
	certHashChanged := false
	if certHash != existingCertHash {
		if certHash != "" {
			log.Info("Updating Dashboard Deployment due to certificate hash change",
				"name", deployment.Name,
				"oldHash", utils.ShortHash(existingCertHash),
				"newHash", utils.ShortHash(certHash))
			needsUpdate = true
			certHashChanged = true
		}
	}

	// Check if replicas changed
	var desiredReplicas int32
	if cluster.Spec.Dashboard != nil {
		desiredReplicas = cluster.Spec.Dashboard.Replicas
	}
	if found.Spec.Replicas != nil && *found.Spec.Replicas != desiredReplicas {
		log.Info("Updating Dashboard Deployment due to replica count change",
			"name", deployment.Name,
			"oldReplicas", *found.Spec.Replicas,
			"newReplicas", desiredReplicas)
		needsUpdate = true
	}

	if needsUpdate {
		if err := r.updateDeploymentWithRetry(ctx, deployment); err != nil {
			recreated, recErr := utils.RecreateDeploymentOnError(ctx, r.Client, r.Recorder, deployment, found, err)
			if recErr != nil {
				return fmt.Errorf("failed to update dashboard deployment: %w", recErr)
			}
			if !recreated {
				return fmt.Errorf("failed to update dashboard deployment: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted Deployment %s/%s due to immutable field change; re-creation on next reconciliation", deployment.Namespace, deployment.Name))
			}
			return fmt.Errorf("deployment %s/%s deleted for immutable field recreation", deployment.Namespace, deployment.Name)
		}

		// Only wait for rollout on cert hash changes (pod restart required)
		// Replica changes don't need rollout wait - Kubernetes handles scaling
		if certHashChanged {
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
	}

	return nil
}

// reconcilePDB reconciles the PodDisruptionBudget for dashboard pods
func (r *DashboardReconciler) reconcilePDB(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	pdbName := pdb.GetPDBName(cluster.Name)

	// Check if PDB should exist
	if !pdb.ShouldCreatePDB(cluster) {
		// If PDB should not exist, delete it if it does
		existing := &policyv1.PodDisruptionBudget{}
		err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, existing)
		if err == nil {
			log.Info("Deleting Dashboard PDB (no longer needed)", "name", pdbName)
			if err := r.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete dashboard PDB: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get dashboard PDB: %w", err)
		}
		return nil
	}

	// Build the PDB
	builder := pdb.NewDashboardPDBBuilder(cluster)
	dashboardPDB := builder.Build()

	if err := controllerutil.SetControllerReference(cluster, dashboardPDB, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard PDB: %w", err)
	}

	// Check if PDB exists
	existing := &policyv1.PodDisruptionBudget{}
	err := r.Get(ctx, types.NamespacedName{Name: pdbName, Namespace: cluster.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Dashboard PDB", "name", pdbName)
		if err := r.Create(ctx, dashboardPDB); err != nil {
			return fmt.Errorf("failed to create dashboard PDB: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get dashboard PDB: %w", err)
	}

	// Update PDB if needed
	dashboardPDB.SetResourceVersion(existing.GetResourceVersion())
	log.V(1).Info("Updating Dashboard PDB", "name", pdbName)
	if err := r.Update(ctx, dashboardPDB); err != nil {
		return fmt.Errorf("failed to update dashboard PDB: %w", err)
	}

	return nil
}

// reconcileHPA reconciles the HorizontalPodAutoscaler for dashboard
func (r *DashboardReconciler) reconcileHPA(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	hpaName := cluster.Name + "-dashboard"

	// Check if HPA should be enabled
	hpaEnabled := cluster.Spec.Dashboard != nil &&
		cluster.Spec.Dashboard.HPA != nil &&
		cluster.Spec.Dashboard.HPA.Enabled

	if !hpaEnabled {
		// If HPA should not exist, delete it if it does
		existing := &autoscalingv2.HorizontalPodAutoscaler{}
		err := r.Get(ctx, types.NamespacedName{Name: hpaName, Namespace: cluster.Namespace}, existing)
		if err == nil {
			log.Info("Deleting Dashboard HPA (no longer needed)", "name", hpaName)
			if err := r.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
				return fmt.Errorf("failed to delete dashboard HPA: %w", err)
			}
		} else if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get dashboard HPA: %w", err)
		}
		return nil
	}

	// Build the HPA
	builder := hpa.NewDashboardHPABuilder(cluster.Name, cluster.Namespace).
		WithSpec(cluster.Spec.Dashboard.HPA)

	dashboardHPA := builder.Build()
	if dashboardHPA == nil {
		return nil
	}

	if err := controllerutil.SetControllerReference(cluster, dashboardHPA, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for dashboard HPA: %w", err)
	}

	// Check if HPA exists
	existing := &autoscalingv2.HorizontalPodAutoscaler{}
	err := r.Get(ctx, types.NamespacedName{Name: hpaName, Namespace: cluster.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Dashboard HPA", "name", hpaName,
			"minReplicas", *dashboardHPA.Spec.MinReplicas,
			"maxReplicas", dashboardHPA.Spec.MaxReplicas)
		if err := r.Create(ctx, dashboardHPA); err != nil {
			return fmt.Errorf("failed to create dashboard HPA: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get dashboard HPA: %w", err)
	}

	// Update HPA if needed
	dashboardHPA.SetResourceVersion(existing.GetResourceVersion())
	log.V(1).Info("Updating Dashboard HPA", "name", hpaName)
	if err := r.Update(ctx, dashboardHPA); err != nil {
		return fmt.Errorf("failed to update dashboard HPA: %w", err)
	}

	return nil
}

// ReconcileWithCertHash reconciles the OpenSearch Dashboard with certificate hash for pod restart.
//
// Deprecated: Use ReconcileNonBlocking for non-blocking rollouts.
func (r *DashboardReconciler) ReconcileWithCertHash(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) error {
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

	// Reconcile PodDisruptionBudget
	if err := r.reconcilePDB(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard PDB: %w", err)
	}

	// Reconcile HorizontalPodAutoscaler
	if err := r.reconcileHPA(ctx, cluster); err != nil {
		return fmt.Errorf("failed to reconcile dashboard HPA: %w", err)
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
func (r *DashboardReconciler) ReconcileNonBlocking(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) DashboardReconcileResult {
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

	// Reconcile PodDisruptionBudget
	if err := r.reconcilePDB(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard PDB: %w", err)}
	}

	// Reconcile HorizontalPodAutoscaler
	if err := r.reconcileHPA(ctx, cluster); err != nil {
		return DashboardReconcileResult{Error: fmt.Errorf("failed to reconcile dashboard HPA: %w", err)}
	}

	log.Info("Dashboard reconciliation completed (non-blocking)", "hasPendingRollout", pendingRollout != nil)
	return DashboardReconcileResult{PendingRollout: pendingRollout}
}

// reconcileDeploymentNonBlocking reconciles the dashboard Deployment without blocking on rollout
// Returns a PendingRollout if a rollout was initiated, nil otherwise
func (r *DashboardReconciler) reconcileDeploymentNonBlocking(ctx context.Context, cluster *wazuhv1.WazuhCluster, certHash string) (*utils.PendingRollout, error) {
	log := logf.FromContext(ctx)

	// Extract spec values for hash computation
	var (
		replicas       int32
		version        = cluster.Spec.Version
		resources      *corev1.ResourceRequirements
		image          string
		nodeSelector   map[string]string
		tolerations    []corev1.Toleration
		affinity       *corev1.Affinity
		env            []corev1.EnvVar
		envFrom        []corev1.EnvFromSource
		annotations    map[string]string
		podAnnotations map[string]string
	)

	if cluster.Spec.Dashboard != nil {
		replicas = cluster.Spec.Dashboard.Replicas
		resources = cluster.Spec.Dashboard.Resources
		nodeSelector = cluster.Spec.Dashboard.NodeSelector
		tolerations = cluster.Spec.Dashboard.Tolerations
		affinity = cluster.Spec.Dashboard.Affinity
		env = cluster.Spec.Dashboard.Env
		envFrom = cluster.Spec.Dashboard.EnvFrom
		annotations = cluster.Spec.Dashboard.Annotations
		podAnnotations = cluster.Spec.Dashboard.PodAnnotations
	}

	// Compute spec hash for change detection (includes all configurable fields)
	specHash, err := patch.ComputeDashboardSpecHashFull(patch.DashboardSpecInput{
		Replicas:       replicas,
		Version:        version,
		Resources:      resources,
		Image:          image,
		NodeSelector:   nodeSelector,
		Tolerations:    tolerations,
		Affinity:       affinity,
		Env:            env,
		EnvFrom:        envFrom,
		Annotations:    annotations,
		PodAnnotations: podAnnotations,
	})
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

	if replicas > 0 {
		deployBuilder.WithReplicas(replicas)
	}
	if resources != nil {
		deployBuilder.WithResources(resources)
	}
	if nodeSelector != nil {
		deployBuilder.WithNodeSelector(nodeSelector)
	}
	if tolerations != nil {
		deployBuilder.WithTolerations(tolerations)
	}
	if affinity != nil {
		deployBuilder.WithAffinity(affinity)
	}
	if len(env) > 0 {
		deployBuilder.WithEnv(env)
	}
	if len(envFrom) > 0 {
		deployBuilder.WithEnvFrom(envFrom)
	}
	if len(annotations) > 0 {
		deployBuilder.WithAnnotations(annotations)
	}
	if len(podAnnotations) > 0 {
		deployBuilder.WithPodAnnotations(podAnnotations)
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
		log.Info("Creating Dashboard Deployment", "name", deployment.Name, "certHash", utils.ShortHash(certHash), "specHash", utils.ShortHash(specHash))
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
			"oldSpecHash", utils.ShortHash(existingSpecHash),
			"newSpecHash", utils.ShortHash(specHash))
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
			updateReason += ",certificate-renewal"
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
			"oldConfigHash", utils.ShortHash(existingConfigHash),
			"newConfigHash", utils.ShortHash(configHash))
		needsUpdate = true
		if updateReason == "" {
			updateReason = "config-change"
		} else {
			updateReason += ",config-change"
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

		if err := r.updateDeploymentWithRetry(ctx, deployment); err != nil {
			recreated, recErr := utils.RecreateDeploymentOnError(ctx, r.Client, r.Recorder, deployment, found, err)
			if recErr != nil {
				return nil, fmt.Errorf("failed to update dashboard deployment: %w", recErr)
			}
			if !recreated {
				return nil, fmt.Errorf("failed to update dashboard deployment: %w", err)
			}
			// Workload deleted for recreation; emit event and requeue
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
					fmt.Sprintf("Deleted Deployment %s/%s due to immutable field change; re-creation on next reconciliation", deployment.Namespace, deployment.Name))
			}
			return nil, fmt.Errorf("deployment %s/%s deleted for immutable field recreation", deployment.Namespace, deployment.Name)
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
func (r *DashboardReconciler) GetStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*wazuhv1.ComponentStatus, error) {
	dep := &appsv1.Deployment{}
	name := constants.DashboardName(cluster.Name)

	if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: cluster.Namespace}, dep); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	// Get desired replicas from the spec
	var desiredReplicas int32
	if cluster.Spec.Dashboard != nil {
		desiredReplicas = cluster.Spec.Dashboard.Replicas
	}

	return &wazuhv1.ComponentStatus{
		Replicas:        dep.Status.Replicas,
		ReadyReplicas:   dep.Status.ReadyReplicas,
		DesiredReplicas: desiredReplicas,
		Phase:           getDeploymentPhase(dep),
	}, nil
}

// createOrUpdate creates or updates a resource
func (r *DashboardReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	key := types.NamespacedName{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}

	existing, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("failed to deep copy object")
	}

	err := r.Get(ctx, key, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating resource", "kind", obj.GetObjectKind().GroupVersionKind().Kind, "name", obj.GetName())
		return r.Create(ctx, obj)
	} else if err != nil {
		return err
	}

	// Preserve immutable fields for Services
	if svc, ok := obj.(*corev1.Service); ok {
		if existingSvc, ok := existing.(*corev1.Service); ok {
			svc.Spec.ClusterIP = existingSvc.Spec.ClusterIP
			svc.Spec.ClusterIPs = existingSvc.Spec.ClusterIPs
		}
	}

	log.V(1).Info("Updating resource", "kind", obj.GetObjectKind().GroupVersionKind().Kind, "name", obj.GetName())
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

// updateDeploymentWithRetry updates a Deployment with retry-on-conflict, always using the latest resourceVersion.
func (r *DashboardReconciler) updateDeploymentWithRetry(ctx context.Context, desired *appsv1.Deployment) error {
	return utils.RetryOnConflict(ctx, func() error {
		current := &appsv1.Deployment{}
		if err := r.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: desired.Namespace}, current); err != nil {
			return err
		}
		desired.SetResourceVersion(current.GetResourceVersion())
		return r.Update(ctx, desired)
	})
}

// getDeploymentPhase returns the phase of a Deployment
func getDeploymentPhase(dep *appsv1.Deployment) wazuhv1.ComponentStatusPhase {
	if dep.Status.ReadyReplicas == 0 {
		return wazuhv1.ComponentStatusPhaseStarting
	}
	if dep.Status.ReadyReplicas < dep.Status.Replicas {
		return wazuhv1.ComponentStatusPhaseDegraded
	}
	if dep.Status.UpdatedReplicas < dep.Status.Replicas {
		return wazuhv1.ComponentStatusPhaseScaling
	}
	return wazuhv1.ComponentStatusPhaseReady
}

// ReconcileStandalone reconciles a standalone OpenSearchDashboard resource
func (r *DashboardReconciler) ReconcileStandalone(ctx context.Context, dashboard *wazuhv1.OpenSearchDashboard) error {
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

		certsBuilder := opensearchcerts.NewDashboardCertsSecretBuilder(dashboard.Name, dashboard.Namespace)
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
		indexerHost := constants.IndexerServiceFQDN(dashboard.Spec.IndexerRef, dashboard.Namespace)
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
	configMap, err := configBuilder.Build()
	if err != nil {
		return fmt.Errorf("failed to build dashboard configmap: %w", err)
	}

	if err := controllerutil.SetControllerReference(dashboard, configMap, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for configmap: %w", err)
	}

	if err := r.createOrUpdate(ctx, configMap); err != nil {
		return fmt.Errorf("failed to reconcile configmap: %w", err)
	}

	// Build wazuh.yml Secret (credentials stored in Secret, not ConfigMap)
	wazuhSecret := configBuilder.BuildWazuhConfigSecret()
	if err := controllerutil.SetControllerReference(dashboard, wazuhSecret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference for wazuh config secret: %w", err)
	}
	if err := r.createOrUpdate(ctx, wazuhSecret); err != nil {
		return fmt.Errorf("failed to reconcile wazuh config secret: %w", err)
	}

	// Build Service
	serviceBuilder := osservices.NewDashboardServiceBuilder(dashboard.Name, dashboard.Namespace)
	if dashboard.Spec.Service != nil && len(dashboard.Spec.Service.Annotations) > 0 {
		serviceBuilder.WithAnnotations(dashboard.Spec.Service.Annotations)
	}
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
	if len(dashboard.Spec.Annotations) > 0 {
		deployBuilder.WithAnnotations(dashboard.Spec.Annotations)
	}
	if len(dashboard.Spec.PodAnnotations) > 0 {
		deployBuilder.WithPodAnnotations(dashboard.Spec.PodAnnotations)
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
	} else {
		needsUpdate := false
		if utils.HashMap(deploy.Annotations) != utils.HashMap(foundDeploy.Annotations) {
			log.Info("Updating standalone Dashboard Deployment due to annotation change", "name", deploy.Name)
			needsUpdate = true
		}
		if utils.HashMap(deploy.Spec.Template.Annotations) != utils.HashMap(foundDeploy.Spec.Template.Annotations) {
			log.Info("Updating standalone Dashboard Deployment due to pod annotation change", "name", deploy.Name)
			needsUpdate = true
		}
		if needsUpdate {
			if err := r.updateDeploymentWithRetry(ctx, deploy); err != nil {
				recreated, recErr := utils.RecreateDeploymentOnError(ctx, r.Client, r.Recorder, deploy, foundDeploy, err)
				if recErr != nil {
					return fmt.Errorf("failed to update deployment: %w", recErr)
				}
				if !recreated {
					return fmt.Errorf("failed to update deployment: %w", err)
				}
				// Workload deleted for recreation; emit event and requeue
				if r.Recorder != nil {
					r.Recorder.Event(dashboard, corev1.EventTypeWarning, constants.EventReasonWorkloadRecreating,
						fmt.Sprintf("Deleted Deployment %s/%s due to immutable field change; re-creation on next reconciliation", deploy.Namespace, deploy.Name))
				}
				return fmt.Errorf("deployment %s/%s deleted for immutable field recreation", deploy.Namespace, deploy.Name)
			}
		}
	}

	log.Info("Standalone dashboard reconciliation completed", "name", dashboard.Name)
	return nil
}

// generateStandaloneDashboardCertificates generates certificates for standalone dashboard
func (r *DashboardReconciler) generateStandaloneDashboardCertificates(ctx context.Context, dashboard *wazuhv1.OpenSearchDashboard) (*dashboardCertificates, error) {
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
