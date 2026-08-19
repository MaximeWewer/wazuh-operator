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

package v1

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var wazuhclusterlog = logf.Log.WithName("wazuhcluster-webhook")

// SetupWazuhClusterWebhookWithManager registers the webhook for WazuhCluster in the manager.
func SetupWazuhClusterWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &WazuhCluster{}).
		WithValidator(&WazuhClusterCustomValidator{}).
		WithDefaulter(&WazuhClusterCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-resources-wazuh-com-v1-wazuhcluster,mutating=true,failurePolicy=fail,sideEffects=None,groups=resources.wazuh.com,resources=wazuhclusters,verbs=create;update,versions=v1,name=mwazuhcluster.kb.io,admissionReviewVersions=v1

// WazuhClusterCustomDefaulter handles defaulting for WazuhCluster
type WazuhClusterCustomDefaulter struct{}

var _ admission.Defaulter[*WazuhCluster] = &WazuhClusterCustomDefaulter{}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the type.
func (d *WazuhClusterCustomDefaulter) Default(_ context.Context, cluster *WazuhCluster) error {
	wazuhclusterlog.Info("defaulting", "name", cluster.Name, "namespace", cluster.Namespace)

	// Default TLS enabled if not set
	if cluster.Spec.TLS == nil {
		cluster.Spec.TLS = &TLSConfig{}
	}
	if cluster.Spec.TLS.Enabled == nil {
		enabled := true
		cluster.Spec.TLS.Enabled = &enabled
	}

	// Default indexer replicas in simple mode
	if cluster.Spec.Indexer != nil && !cluster.Spec.Indexer.IsAdvancedMode() && cluster.Spec.Indexer.Replicas == 0 {
		cluster.Spec.Indexer.Replicas = 3
	}

	// Default dashboard replicas
	if cluster.Spec.Dashboard != nil && cluster.Spec.Dashboard.Replicas == 0 {
		cluster.Spec.Dashboard.Replicas = 1
	}

	return nil
}

// +kubebuilder:webhook:path=/validate-resources-wazuh-com-v1-wazuhcluster,mutating=false,failurePolicy=fail,sideEffects=None,groups=resources.wazuh.com,resources=wazuhclusters,verbs=create;update;delete,versions=v1,name=vwazuhcluster.kb.io,admissionReviewVersions=v1

// WazuhClusterCustomValidator handles validation for WazuhCluster
type WazuhClusterCustomValidator struct{}

var _ admission.Validator[*WazuhCluster] = &WazuhClusterCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *WazuhClusterCustomValidator) ValidateCreate(_ context.Context, cluster *WazuhCluster) (admission.Warnings, error) {
	wazuhclusterlog.Info("validate create", "name", cluster.Name, "namespace", cluster.Namespace)

	return v.validateWazuhCluster(cluster)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *WazuhClusterCustomValidator) ValidateUpdate(_ context.Context, oldCluster, newCluster *WazuhCluster) (admission.Warnings, error) {
	wazuhclusterlog.Info("validate update", "name", newCluster.Name, "namespace", newCluster.Namespace)

	// Validate the new spec
	warnings, err := v.validateWazuhCluster(newCluster)
	if err != nil {
		return warnings, err
	}

	// Validate update-specific rules
	updateWarnings, updateErr := v.validateUpdate(oldCluster, newCluster)
	warnings = append(warnings, updateWarnings...)

	return warnings, updateErr
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type.
func (v *WazuhClusterCustomValidator) ValidateDelete(_ context.Context, cluster *WazuhCluster) (admission.Warnings, error) {
	wazuhclusterlog.Info("validate delete", "name", cluster.Name, "namespace", cluster.Namespace)

	// No special delete validation currently
	return nil, nil
}

// validateWazuhCluster validates the WazuhCluster spec
func (v *WazuhClusterCustomValidator) validateWazuhCluster(cluster *WazuhCluster) (admission.Warnings, error) {
	var allErrors []string
	var warnings admission.Warnings

	// Validate version format
	if err := validateVersion(cluster.Spec.Version); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("spec.version: %s", err.Error()))
	}

	// Validate inline components
	errs, warns := v.validateInlineMode(cluster)
	allErrors = append(allErrors, errs...)
	warnings = append(warnings, warns...)

	// Validate TLS configuration
	if cluster.Spec.TLS != nil {
		errs := validateTLSConfig(cluster.Spec.TLS)
		allErrors = append(allErrors, errs...)
	}

	// Validate drain configuration
	if cluster.Spec.Drain != nil {
		errs := validateDrainConfig(cluster.Spec.Drain)
		allErrors = append(allErrors, errs...)
	}

	if len(allErrors) > 0 {
		return warnings, fmt.Errorf("validation failed: %v", allErrors)
	}

	return warnings, nil
}

// validateInlineMode validates inline component specifications
func (v *WazuhClusterCustomValidator) validateInlineMode(cluster *WazuhCluster) ([]string, admission.Warnings) {
	var errors []string
	var warnings admission.Warnings

	// Validate manager
	if cluster.Spec.Manager != nil {
		errs, warns := validateManagerSpec(cluster.Spec.Manager)
		errors = append(errors, errs...)
		warnings = append(warnings, warns...)
	}

	// Validate indexer
	if cluster.Spec.Indexer != nil {
		errs, warns := validateIndexerSpec(cluster.Spec.Indexer)
		errors = append(errors, errs...)
		warnings = append(warnings, warns...)
	}

	// Validate dashboard
	if cluster.Spec.Dashboard != nil {
		errs := validateDashboardSpec(cluster.Spec.Dashboard)
		errors = append(errors, errs...)
	}

	return errors, warnings
}

// validateUpdate validates update-specific rules
func (v *WazuhClusterCustomValidator) validateUpdate(oldCluster, newCluster *WazuhCluster) (admission.Warnings, error) {
	var warnings admission.Warnings

	// Prevent indexer topology mode transition (simple <-> advanced)
	if oldCluster.Spec.Indexer != nil && newCluster.Spec.Indexer != nil {
		if oldCluster.Spec.Indexer.IsSimpleMode() && newCluster.Spec.Indexer.IsAdvancedMode() {
			return warnings, fmt.Errorf("spec.indexer: cannot transition from simple mode to advanced mode; create a new cluster for the desired topology")
		}
		if oldCluster.Spec.Indexer.IsAdvancedMode() && newCluster.Spec.Indexer.IsSimpleMode() {
			return warnings, fmt.Errorf("spec.indexer: cannot transition from advanced mode to simple mode; create a new cluster for the desired topology")
		}
	}

	// Warn about scale-down operations
	if oldCluster.Spec.Indexer != nil && newCluster.Spec.Indexer != nil {
		if oldCluster.Spec.Indexer.GetTotalReplicas() > newCluster.Spec.Indexer.GetTotalReplicas() {
			warnings = append(warnings, "scaling down indexer replicas will trigger shard relocation")
		}
	}

	// Warn when the manager per-path PVC layout changes: adding/removing a path or changing a
	// storageClass/accessMode recreates the manager StatefulSet (downtime); removing a path
	// orphans its PVC.
	if oldCluster.Spec.Manager != nil && newCluster.Spec.Manager != nil {
		warnings = append(warnings, volumeClaimsChangeWarnings(oldCluster.Spec.Manager.Master.VolumeClaims, newCluster.Spec.Manager.Master.VolumeClaims, "master")...)
		warnings = append(warnings, volumeClaimsChangeWarnings(oldCluster.Spec.Manager.Workers.VolumeClaims, newCluster.Spec.Manager.Workers.VolumeClaims, "workers")...)
	}

	return warnings, nil
}

// volumeClaimsChangeWarnings warns about per-path PVC layout changes that recreate the
// manager StatefulSet or orphan a PVC.
func volumeClaimsChangeWarnings(oldVCs, newVCs []ManagerVolumeClaim, role string) admission.Warnings {
	var warnings admission.Warnings
	oldByPath := make(map[string]ManagerVolumeClaim, len(oldVCs))
	for _, vc := range oldVCs {
		oldByPath[vc.Path] = vc
	}
	newByPath := make(map[string]ManagerVolumeClaim, len(newVCs))
	for _, vc := range newVCs {
		newByPath[vc.Path] = vc
	}
	for p, nv := range newByPath {
		ov, ok := oldByPath[p]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("spec.manager.%s.volumeClaims: adding %q recreates the manager StatefulSet (downtime)", role, p))
			continue
		}
		if !stringPtrEqual(ov.StorageClass, nv.StorageClass) || ov.AccessMode != nv.AccessMode {
			warnings = append(warnings, fmt.Sprintf("spec.manager.%s.volumeClaims: changing storageClass/accessMode of %q recreates the manager StatefulSet (downtime)", role, p))
		}
	}
	for p := range oldByPath {
		if _, ok := newByPath[p]; !ok {
			warnings = append(warnings, fmt.Sprintf("spec.manager.%s.volumeClaims: removing %q recreates the manager StatefulSet and orphans its PVC (data becomes unreachable)", role, p))
		}
	}
	return warnings
}

// stringPtrEqual reports whether two *string values are equal (nil == nil).
func stringPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// versionRegex validates semver format
var versionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// validateVersion validates version format
func validateVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version is required")
	}
	if !versionRegex.MatchString(version) {
		return fmt.Errorf("version must be in semver format (e.g., 4.9.0)")
	}
	return nil
}

// validateManagerSpec validates manager specification
func validateManagerSpec(spec *WazuhManagerClusterSpec) ([]string, admission.Warnings) {
	var errors []string
	var warnings admission.Warnings

	// Validate worker replicas
	if spec.Workers.Replicas != nil && *spec.Workers.Replicas < 0 {
		errors = append(errors, "spec.manager.workers.replicas: cannot be negative")
	}

	// Warn about non-HA configuration
	if !spec.IsHA() {
		warnings = append(warnings, "manager cluster has fewer than 3 nodes; consider adding workers for high availability")
	}

	// Validate log rotation schedule if enabled
	if spec.LogRotation != nil && spec.LogRotation.Enabled {
		if spec.LogRotation.RetentionDays != nil && *spec.LogRotation.RetentionDays < 1 {
			errors = append(errors, "spec.manager.logRotation.retentionDays: must be at least 1")
		}
	}

	// Validate GatewayAPI/Ingress mutual exclusion for master
	masterGatewayErrors := validateGatewayAPIConfig(spec.Master.GatewayAPI, spec.Master.Ingress, "spec.manager.master")
	errors = append(errors, masterGatewayErrors...)

	// Validate GatewayAPI/Ingress mutual exclusion for workers
	workerGatewayErrors := validateGatewayAPIConfig(spec.Workers.GatewayAPI, spec.Workers.Ingress, "spec.manager.workers")
	errors = append(errors, workerGatewayErrors...)

	// Validate per-path dedicated PVC declarations
	mErrs, mWarns := validateManagerVolumeClaims(spec.Master.VolumeClaims, "spec.manager.master.volumeClaims")
	errors = append(errors, mErrs...)
	warnings = append(warnings, mWarns...)
	wErrs, wWarns := validateManagerVolumeClaims(spec.Workers.VolumeClaims, "spec.manager.workers.volumeClaims")
	errors = append(errors, wErrs...)
	warnings = append(warnings, wWarns...)

	return errors, warnings
}

// validateManagerVolumeClaims validates the per-path dedicated PVC declarations: absolute,
// clean paths under /var/ossec, unique, a derived PVC name within the 63-char limit, a valid
// positive size, and a supported access mode. It also warns about layouts that are risky
// (RWX on SQLite paths) or partially unsupported (splitting etc / api/configuration).
func validateManagerVolumeClaims(vcs []ManagerVolumeClaim, prefix string) ([]string, admission.Warnings) {
	var errs []string
	var warnings admission.Warnings
	seen := make(map[string]bool)
	for i := range vcs {
		vc := vcs[i]
		field := fmt.Sprintf("%s[%d]", prefix, i)

		if !strings.HasPrefix(vc.Path, "/var/ossec/") || path.Clean(vc.Path) != vc.Path || vc.Path == "/var/ossec" {
			errs = append(errs, fmt.Sprintf("%s.path: %q must be a clean absolute path under /var/ossec", field, vc.Path))
		}
		if seen[vc.Path] {
			errs = append(errs, fmt.Sprintf("%s.path: %q is declared more than once", field, vc.Path))
		}
		seen[vc.Path] = true
		// Conservative bound: derived name = "wazuh-data-" (11) + slug (<= len(rel)) <= 63.
		if rel := strings.TrimPrefix(vc.Path, "/var/ossec/"); len(rel) > 52 {
			errs = append(errs, fmt.Sprintf("%s.path: %q is too long; the derived PVC name would exceed 63 characters", field, vc.Path))
		}

		if q, err := resource.ParseQuantity(vc.Size); err != nil {
			errs = append(errs, fmt.Sprintf("%s.size: %q is not a valid quantity: %v", field, vc.Size, err))
		} else if q.Sign() <= 0 {
			errs = append(errs, fmt.Sprintf("%s.size: %q must be greater than zero", field, vc.Size))
		}

		switch vc.AccessMode {
		case "", corev1.ReadWriteOnce, corev1.ReadWriteMany, corev1.ReadWriteOncePod:
		default:
			errs = append(errs, fmt.Sprintf("%s.accessMode: %q is not supported", field, vc.AccessMode))
		}

		if vc.AccessMode == corev1.ReadWriteMany && (vc.Path == "/var/ossec/queue" || strings.HasPrefix(vc.Path, "/var/ossec/queue/db")) {
			warnings = append(warnings, fmt.Sprintf("%s: ReadWriteMany on a SQLite path (%s) risks database corruption; use ReadWriteOnce block storage", field, vc.Path))
		}
		if vc.Path == "/var/ossec/etc" {
			warnings = append(warnings, fmt.Sprintf("%s: splitting /var/ossec/etc moves client.keys onto a dedicated PVC; ensure it uses reliable storage", field))
		}
		if vc.Path == "/var/ossec/api/configuration" {
			warnings = append(warnings, fmt.Sprintf("%s: /var/ossec/api/configuration is seeded into the default wazuh-data volume; a dedicated PVC here is not seeded and is unsupported", field))
		}
	}
	return errs, warnings
}

// validateIndexerSpec validates indexer specification
func validateIndexerSpec(spec *WazuhIndexerClusterSpec) ([]string, admission.Warnings) {
	var errors []string
	var warnings admission.Warnings

	// Cannot have both replicas and nodePools
	if spec.Replicas > 0 && len(spec.NodePools) > 0 {
		errors = append(errors,
			"spec.indexer: replicas and nodePools are mutually exclusive")
		return errors, warnings
	}

	// Simple mode validation
	if spec.IsSimpleMode() {
		if spec.Replicas < 1 {
			errors = append(errors, "spec.indexer.replicas: must be at least 1")
		}
		if spec.Replicas < 3 {
			warnings = append(warnings, "indexer has fewer than 3 replicas; consider 3+ for high availability")
		}
	}

	// Advanced mode (nodePools) validation
	if spec.IsAdvancedMode() {
		poolErrors, poolWarnings := validateNodePools(spec.NodePools)
		errors = append(errors, poolErrors...)
		warnings = append(warnings, poolWarnings...)
	}

	// Validate GatewayAPI/Ingress mutual exclusion
	gatewayErrors := validateGatewayAPIConfig(spec.GatewayAPI, spec.Ingress, "spec.indexer")
	errors = append(errors, gatewayErrors...)

	return errors, warnings
}

// validateNodePools validates nodePool configurations
func validateNodePools(pools []IndexerNodePoolSpec) ([]string, admission.Warnings) {
	var errors []string
	var warnings admission.Warnings

	if len(pools) == 0 {
		errors = append(errors, "spec.indexer.nodePools: at least one nodePool must be defined")
		return errors, warnings
	}

	seenNames := make(map[string]bool)
	var clusterManagerCount int32
	var dataNodeCount int32
	hasClusterManagerRole := false
	hasDataRole := false

	nodePoolNameRegex := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

	for i, pool := range pools {
		prefix := fmt.Sprintf("spec.indexer.nodePools[%d]", i)

		// Validate name
		if pool.Name == "" {
			errors = append(errors, fmt.Sprintf("%s.name: is required", prefix))
		} else {
			if !nodePoolNameRegex.MatchString(pool.Name) {
				errors = append(errors, fmt.Sprintf("%s.name: must be DNS-compatible (lowercase alphanumeric with hyphens)", prefix))
			}
			if len(pool.Name) > 63 {
				errors = append(errors, fmt.Sprintf("%s.name: must be at most 63 characters", prefix))
			}
			if seenNames[pool.Name] {
				errors = append(errors, fmt.Sprintf("%s.name: duplicate name '%s'", prefix, pool.Name))
			}
			seenNames[pool.Name] = true
		}

		// Validate replicas
		if pool.Replicas < 0 {
			errors = append(errors, fmt.Sprintf("%s.replicas: cannot be negative", prefix))
		}

		// Track roles
		if pool.HasClusterManagerRole() {
			hasClusterManagerRole = true
			clusterManagerCount += pool.Replicas
		}
		if pool.HasDataRole() {
			hasDataRole = true
			dataNodeCount += pool.Replicas
		}

		// Warn about mixed roles
		if pool.HasClusterManagerRole() && pool.HasDataRole() {
			warnings = append(warnings, fmt.Sprintf("nodePool '%s' has both cluster_manager and data roles; consider separating for production", pool.Name))
		}
	}

	// Validate quorum
	if hasClusterManagerRole && clusterManagerCount < 3 {
		errors = append(errors, fmt.Sprintf("spec.indexer.nodePools: cluster_manager role requires at least 3 nodes for quorum; found %d", clusterManagerCount))
	}

	// Validate data nodes
	if hasDataRole && dataNodeCount < 1 {
		errors = append(errors, fmt.Sprintf("spec.indexer.nodePools: at least 1 data node is required; found %d", dataNodeCount))
	}

	// Warn if no data role
	if !hasDataRole {
		warnings = append(warnings, "no nodePool has the data role; cluster will not be able to store data")
	}

	return errors, warnings
}

// validateDashboardSpec validates dashboard specification
func validateDashboardSpec(spec *WazuhDashboardClusterSpec) []string {
	var errors []string

	if spec.Replicas < 1 {
		errors = append(errors, "spec.dashboard.replicas: must be at least 1")
	}

	// Validate GatewayAPI/Ingress mutual exclusion
	gatewayErrors := validateGatewayAPIConfig(spec.GatewayAPI, spec.Ingress, "spec.dashboard")
	errors = append(errors, gatewayErrors...)

	return errors
}

// validateTLSConfig validates TLS configuration
func validateTLSConfig(tls *TLSConfig) []string {
	var errors []string

	// Validate custom certs configuration
	if tls.CustomCerts != nil {
		if tls.CustomCerts.CASecretRef == nil {
			errors = append(errors, "spec.tls.customCerts.caSecretRef: is required when customCerts is configured")
		} else if tls.CustomCerts.CASecretRef.Name == "" {
			errors = append(errors, "spec.tls.customCerts.caSecretRef.name: cannot be empty")
		}
	}

	// Validate certificate config
	// Duration fields are validated by kubebuilder pattern annotation

	return errors
}

// validateDrainConfig validates drain configuration
func validateDrainConfig(drain *DrainConfiguration) []string {
	var errors []string

	// Validate indexer drain config
	if drain.Indexer != nil {
		if drain.Indexer.Timeout != nil && drain.Indexer.Timeout.Duration < 0 {
			errors = append(errors, "spec.drain.indexer.timeout: cannot be negative")
		}
		if drain.Indexer.HealthCheckInterval != nil && drain.Indexer.HealthCheckInterval.Duration < 0 {
			errors = append(errors, "spec.drain.indexer.healthCheckInterval: cannot be negative")
		}
	}

	// Validate manager drain config
	if drain.Manager != nil {
		if drain.Manager.Timeout != nil && drain.Manager.Timeout.Duration < 0 {
			errors = append(errors, "spec.drain.manager.timeout: cannot be negative")
		}
	}

	// Validate retry config
	if drain.Retry != nil {
		if drain.Retry.MaxAttempts < 0 {
			errors = append(errors, "spec.drain.retry.maxAttempts: cannot be negative")
		}
	}

	return errors
}

// validateGatewayAPIConfig validates GatewayAPI configuration and mutual exclusion with Ingress
func validateGatewayAPIConfig(gatewayAPI *GatewayAPISpec, ingress *IngressSpec, prefix string) []string {
	var errors []string

	// Check mutual exclusion: GatewayAPI and Ingress cannot both be enabled
	gatewayEnabled := gatewayAPI != nil && gatewayAPI.Enabled
	ingressEnabled := ingress != nil && ingress.Enabled

	if gatewayEnabled && ingressEnabled {
		errors = append(errors, fmt.Sprintf("%s: gatewayAPI and ingress are mutually exclusive; only one can be enabled", prefix))
	}

	// Validate GatewayAPI configuration if enabled
	if gatewayEnabled {
		if gatewayAPI.GatewayRef == nil {
			errors = append(errors, fmt.Sprintf("%s.gatewayAPI.gatewayRef: is required when gatewayAPI is enabled", prefix))
		} else if gatewayAPI.GatewayRef.Name == "" {
			errors = append(errors, fmt.Sprintf("%s.gatewayAPI.gatewayRef.name: cannot be empty", prefix))
		}
	}

	return errors
}
