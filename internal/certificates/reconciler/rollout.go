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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// RestartOrderStrategy defines the order in which pods should be restarted
type RestartOrderStrategy string

const (
	// RestartOrderSequential restarts pods one at a time, waiting for ready between each
	RestartOrderSequential RestartOrderStrategy = "sequential"
	// RestartOrderParallel restarts all pods at once (Kubernetes handles the rolling update)
	RestartOrderParallel RestartOrderStrategy = "parallel"
	// RestartOrderWorkersFirst restarts workers before master (for manager components)
	RestartOrderWorkersFirst RestartOrderStrategy = "workers-first"
)

// RollingRestartConfig contains configuration for triggering a rolling restart
type RollingRestartConfig struct {
	// Component is the component being restarted (indexer, manager-master, manager-workers, dashboard)
	Component string
	// CertType indicates which certificate triggered the restart
	CertType string
	// RestartOrder specifies the order in which pods should be restarted
	RestartOrder RestartOrderStrategy
	// WaitForReady if true, waits for each pod to be ready before proceeding (only for sequential)
	WaitForReady bool
	// Reason provides a human-readable reason for the restart
	Reason string
}

// RollingRestartResult contains the result of a rolling restart operation
type RollingRestartResult struct {
	// Triggered indicates if the restart was triggered
	Triggered bool
	// Component is the component that was restarted
	Component string
	// Timestamp is when the restart was triggered
	Timestamp time.Time
	// Reason is why the restart was triggered
	Reason string
	// Error contains any error that occurred
	Error error
}

// TriggerDeploymentRollingRestart triggers a rolling restart of a Deployment
// by updating the kubectl.kubernetes.io/restartedAt annotation on the pod template
func TriggerDeploymentRollingRestart(ctx context.Context, c client.Client, namespace, name string, config *RollingRestartConfig) (*RollingRestartResult, error) {
	log := logf.FromContext(ctx)
	result := &RollingRestartResult{
		Component: config.Component,
		Timestamp: time.Now(),
		Reason:    config.Reason,
	}

	// Get the deployment
	deployment := &appsv1.Deployment{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, deployment); err != nil {
		result.Error = fmt.Errorf("failed to get deployment %s: %w", name, err)
		return result, result.Error
	}

	// Check if replicas is 0 - skip restart if no pods
	if deployment.Spec.Replicas != nil && *deployment.Spec.Replicas == 0 {
		log.Info("Skipping rolling restart - deployment has 0 replicas",
			"deployment", name,
			"component", config.Component)
		result.Triggered = false
		result.Reason = "deployment has 0 replicas"
		return result, nil
	}

	// Initialize annotations if nil
	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = make(map[string]string)
	}

	// Set the restart annotation
	restartTime := result.Timestamp.Format(time.RFC3339)
	deployment.Spec.Template.Annotations[constants.AnnotationRestartedAt] = restartTime
	deployment.Spec.Template.Annotations[constants.AnnotationRollingRestartTriggered] = "true"

	// Add reason annotation if cert type is provided
	if config.CertType != "" {
		deployment.Spec.Template.Annotations[constants.AnnotationConfigChangeDetected] = config.CertType
	}

	// Update the deployment
	if err := c.Update(ctx, deployment); err != nil {
		result.Error = fmt.Errorf("failed to update deployment %s: %w", name, err)
		return result, result.Error
	}

	log.Info("Triggered rolling restart for deployment",
		"deployment", name,
		"component", config.Component,
		"reason", config.Reason,
		"restartedAt", restartTime)

	result.Triggered = true
	return result, nil
}

// TriggerStatefulSetRollingRestart triggers a rolling restart of a StatefulSet
// by updating the kubectl.kubernetes.io/restartedAt annotation on the pod template
func TriggerStatefulSetRollingRestart(ctx context.Context, c client.Client, namespace, name string, config *RollingRestartConfig) (*RollingRestartResult, error) {
	log := logf.FromContext(ctx)
	result := &RollingRestartResult{
		Component: config.Component,
		Timestamp: time.Now(),
		Reason:    config.Reason,
	}

	// Get the StatefulSet
	sts := &appsv1.StatefulSet{}
	if err := c.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, sts); err != nil {
		result.Error = fmt.Errorf("failed to get statefulset %s: %w", name, err)
		return result, result.Error
	}

	// Check if replicas is 0 - skip restart if no pods
	if sts.Spec.Replicas != nil && *sts.Spec.Replicas == 0 {
		log.Info("Skipping rolling restart - statefulset has 0 replicas",
			"statefulset", name,
			"component", config.Component)
		result.Triggered = false
		result.Reason = "statefulset has 0 replicas"
		return result, nil
	}

	// Initialize annotations if nil
	if sts.Spec.Template.Annotations == nil {
		sts.Spec.Template.Annotations = make(map[string]string)
	}

	// Set the restart annotation
	restartTime := result.Timestamp.Format(time.RFC3339)
	sts.Spec.Template.Annotations[constants.AnnotationRestartedAt] = restartTime
	sts.Spec.Template.Annotations[constants.AnnotationRollingRestartTriggered] = "true"

	// Add reason annotation if cert type is provided
	if config.CertType != "" {
		sts.Spec.Template.Annotations[constants.AnnotationConfigChangeDetected] = config.CertType
	}

	// Update the StatefulSet
	if err := c.Update(ctx, sts); err != nil {
		result.Error = fmt.Errorf("failed to update statefulset %s: %w", name, err)
		return result, result.Error
	}

	log.Info("Triggered rolling restart for statefulset",
		"statefulset", name,
		"component", config.Component,
		"reason", config.Reason,
		"restartedAt", restartTime)

	result.Triggered = true
	return result, nil
}

// CertRenewalRestartConfig contains configuration for certificate-triggered restarts
type CertRenewalRestartConfig struct {
	// ClusterName is the name of the WazuhCluster
	ClusterName string
	// Namespace is the namespace of the cluster
	Namespace string
	// CertType is the type of certificate that was renewed
	CertType string
	// TriggerIndexers if true, triggers restart of indexers
	TriggerIndexers bool
	// TriggerManagers if true, triggers restart of managers (master and workers)
	TriggerManagers bool
	// TriggerDashboard if true, triggers restart of dashboard
	TriggerDashboard bool
	// AllowHotReload if true, skip indexer restart for node cert (use hot reload instead)
	AllowHotReload bool
}

// CertRenewalRestartResult contains the results of all component restarts
type CertRenewalRestartResult struct {
	// IndexerResult is the result of indexer restart
	IndexerResult *RollingRestartResult
	// ManagerMasterResult is the result of manager master restart
	ManagerMasterResult *RollingRestartResult
	// ManagerWorkersResult is the result of manager workers restart
	ManagerWorkersResult *RollingRestartResult
	// DashboardResult is the result of dashboard restart
	DashboardResult *RollingRestartResult
	// TotalTriggered is the total number of components where restart was triggered
	TotalTriggered int
	// Errors contains any errors that occurred
	Errors []error
}

// TriggerCertRenewalRestarts triggers rolling restarts for the appropriate components
// based on which certificate was renewed
func TriggerCertRenewalRestarts(ctx context.Context, c client.Client, config *CertRenewalRestartConfig) *CertRenewalRestartResult {
	log := logf.FromContext(ctx)
	result := &CertRenewalRestartResult{}

	log.Info("Triggering certificate renewal restarts",
		"certType", config.CertType,
		"triggerIndexers", config.TriggerIndexers,
		"triggerManagers", config.TriggerManagers,
		"triggerDashboard", config.TriggerDashboard)

	// Trigger indexer restart if requested
	if config.TriggerIndexers && !config.AllowHotReload {
		restartConfig := &RollingRestartConfig{
			Component:    "indexer",
			CertType:     config.CertType,
			RestartOrder: RestartOrderSequential,
			WaitForReady: true,
			Reason:       fmt.Sprintf("certificate %s renewed", config.CertType),
		}
		indexerResult, err := TriggerStatefulSetRollingRestart(
			ctx, c, config.Namespace,
			constants.IndexerName(config.ClusterName),
			restartConfig)
		result.IndexerResult = indexerResult
		if err != nil {
			result.Errors = append(result.Errors, err)
		} else if indexerResult.Triggered {
			result.TotalTriggered++
		}
	}

	// Trigger manager restarts if requested
	if config.TriggerManagers {
		// Restart workers first, then master
		workersRestartConfig := &RollingRestartConfig{
			Component:    "manager-workers",
			CertType:     config.CertType,
			RestartOrder: RestartOrderParallel,
			Reason:       fmt.Sprintf("certificate %s renewed", config.CertType),
		}
		workersResult, err := TriggerStatefulSetRollingRestart(
			ctx, c, config.Namespace,
			constants.ManagerWorkerName(config.ClusterName),
			workersRestartConfig)
		result.ManagerWorkersResult = workersResult
		if err != nil {
			result.Errors = append(result.Errors, err)
		} else if workersResult.Triggered {
			result.TotalTriggered++
		}

		masterRestartConfig := &RollingRestartConfig{
			Component:    "manager-master",
			CertType:     config.CertType,
			RestartOrder: RestartOrderSequential,
			Reason:       fmt.Sprintf("certificate %s renewed", config.CertType),
		}
		masterResult, err := TriggerStatefulSetRollingRestart(
			ctx, c, config.Namespace,
			constants.ManagerMasterName(config.ClusterName),
			masterRestartConfig)
		result.ManagerMasterResult = masterResult
		if err != nil {
			result.Errors = append(result.Errors, err)
		} else if masterResult.Triggered {
			result.TotalTriggered++
		}
	}

	// Trigger dashboard restart if requested
	if config.TriggerDashboard {
		restartConfig := &RollingRestartConfig{
			Component:    "dashboard",
			CertType:     config.CertType,
			RestartOrder: RestartOrderParallel,
			Reason:       fmt.Sprintf("certificate %s renewed", config.CertType),
		}
		dashboardResult, err := TriggerDeploymentRollingRestart(
			ctx, c, config.Namespace,
			constants.DashboardName(config.ClusterName),
			restartConfig)
		result.DashboardResult = dashboardResult
		if err != nil {
			result.Errors = append(result.Errors, err)
		} else if dashboardResult.Triggered {
			result.TotalTriggered++
		}
	}

	log.Info("Certificate renewal restarts completed",
		"totalTriggered", result.TotalTriggered,
		"errors", len(result.Errors))

	return result
}

// GetRestartConfigForCertType returns the appropriate restart configuration
// based on which certificate type was renewed
func GetRestartConfigForCertType(certType string) *CertRenewalRestartConfig {
	switch certType {
	case constants.CertTypeCA:
		// CA renewal requires restarting ALL components
		return &CertRenewalRestartConfig{
			CertType:         certType,
			TriggerIndexers:  true,
			TriggerManagers:  true,
			TriggerDashboard: true,
			AllowHotReload:   false, // CA change requires full restart
		}
	case constants.CertTypeNode:
		// Node cert renewal only requires indexer restart (or hot reload)
		return &CertRenewalRestartConfig{
			CertType:         certType,
			TriggerIndexers:  true,
			TriggerManagers:  false,
			TriggerDashboard: false,
			AllowHotReload:   true, // Hot reload supported for node certs
		}
	case constants.CertTypeFilebeat:
		// Filebeat cert renewal requires manager restart (where filebeat runs)
		return &CertRenewalRestartConfig{
			CertType:         certType,
			TriggerIndexers:  false,
			TriggerManagers:  true,
			TriggerDashboard: false,
			AllowHotReload:   false,
		}
	case constants.CertTypeDashboard:
		// Dashboard cert renewal only requires dashboard restart
		return &CertRenewalRestartConfig{
			CertType:         certType,
			TriggerIndexers:  false,
			TriggerManagers:  false,
			TriggerDashboard: true,
			AllowHotReload:   false,
		}
	case constants.CertTypeAdmin:
		// Admin cert renewal does NOT require any restart
		// It's used for administrative operations, not mounted in pods
		return &CertRenewalRestartConfig{
			CertType:         certType,
			TriggerIndexers:  false,
			TriggerManagers:  false,
			TriggerDashboard: false,
			AllowHotReload:   false,
		}
	default:
		// Unknown cert type - trigger all restarts to be safe
		return &CertRenewalRestartConfig{
			CertType:         certType,
			TriggerIndexers:  true,
			TriggerManagers:  true,
			TriggerDashboard: true,
			AllowHotReload:   false,
		}
	}
}

// FilebeatCertRenewalResult contains the result of Filebeat certificate renewal handling
type FilebeatCertRenewalResult struct {
	// MasterRestarted indicates if the master was restarted
	MasterRestarted bool
	// WorkersRestarted indicates if workers were restarted
	WorkersRestarted bool
	// TotalRestarted is the total number of components restarted
	TotalRestarted int
	// Error contains any error that occurred
	Error error
}

// TriggerFilebeatCertificateRenewalRestart handles Filebeat certificate renewal
// by restarting all manager components (master and workers) that run Filebeat
func TriggerFilebeatCertificateRenewalRestart(ctx context.Context, c client.Client, namespace, clusterName string) (*FilebeatCertRenewalResult, error) {
	log := logf.FromContext(ctx)
	result := &FilebeatCertRenewalResult{}

	log.Info("Triggering Filebeat certificate renewal restart",
		"cluster", clusterName,
		"namespace", namespace)

	// Restart master first (it's single instance, quick restart)
	masterConfig := &RollingRestartConfig{
		Component:    "manager-master",
		CertType:     constants.CertTypeFilebeat,
		RestartOrder: RestartOrderSequential,
		WaitForReady: true,
		Reason:       "filebeat certificate renewed",
	}

	masterResult, err := TriggerStatefulSetRollingRestart(ctx, c, namespace,
		constants.ManagerMasterName(clusterName), masterConfig)
	if err != nil {
		log.Error(err, "Failed to restart manager master for Filebeat cert renewal")
		result.Error = err
		return result, err
	}

	if masterResult.Triggered {
		result.MasterRestarted = true
		result.TotalRestarted++
	}

	// Restart workers
	workersConfig := &RollingRestartConfig{
		Component:    "manager-workers",
		CertType:     constants.CertTypeFilebeat,
		RestartOrder: RestartOrderParallel,
		WaitForReady: false, // Workers can restart in parallel
		Reason:       "filebeat certificate renewed",
	}

	workersResult, err := TriggerStatefulSetRollingRestart(ctx, c, namespace,
		constants.ManagerWorkersName(clusterName), workersConfig)
	if err != nil {
		// Don't fail completely if workers fail - master may have 0 workers
		log.Info("Workers restart failed or skipped", "error", err)
	} else if workersResult.Triggered {
		result.WorkersRestarted = true
		result.TotalRestarted++
	}

	log.Info("Filebeat certificate renewal restart completed",
		"cluster", clusterName,
		"masterRestarted", result.MasterRestarted,
		"workersRestarted", result.WorkersRestarted)

	return result, nil
}

// AdminCertRenewalResult contains the result of Admin certificate renewal handling
type AdminCertRenewalResult struct {
	// Updated indicates if the admin cert was updated
	Updated bool
	// NoRestartRequired indicates that no restart is needed for admin certs
	NoRestartRequired bool
	// Message provides status information
	Message string
}

// TriggerAdminCertificateRenewalRestart handles Admin certificate renewal
// Admin certificates are used for administrative operations and do NOT require pod restarts
// This function is a no-op for restarts but logs the renewal for audit purposes
func TriggerAdminCertificateRenewalRestart(ctx context.Context, clusterName, namespace string) (*AdminCertRenewalResult, error) {
	log := logf.FromContext(ctx)

	result := &AdminCertRenewalResult{
		Updated:           true,
		NoRestartRequired: true,
		Message:           "Admin certificate renewed. No pod restarts required - admin cert is used for administrative operations only.",
	}

	log.Info("Admin certificate renewed - no restart required",
		"cluster", clusterName,
		"namespace", namespace,
		"reason", "admin certs are used for API operations, not mounted in pods")

	return result, nil
}

// DashboardCertRenewalResult contains the result of Dashboard certificate renewal handling
type DashboardCertRenewalResult struct {
	// Restarted indicates if the dashboard was restarted
	Restarted bool
	// Error contains any error that occurred
	Error error
}

// TriggerDashboardCertificateRenewalRestart handles Dashboard certificate renewal
// by restarting the dashboard deployment
func TriggerDashboardCertificateRenewalRestart(ctx context.Context, c client.Client, namespace, clusterName string) (*DashboardCertRenewalResult, error) {
	log := logf.FromContext(ctx)
	result := &DashboardCertRenewalResult{}

	log.Info("Triggering Dashboard certificate renewal restart",
		"cluster", clusterName,
		"namespace", namespace)

	config := &RollingRestartConfig{
		Component:    "dashboard",
		CertType:     constants.CertTypeDashboard,
		RestartOrder: RestartOrderParallel,
		Reason:       "dashboard certificate renewed",
	}

	restartResult, err := TriggerDeploymentRollingRestart(ctx, c, namespace,
		constants.DashboardName(clusterName), config)
	if err != nil {
		log.Error(err, "Failed to restart dashboard for cert renewal")
		result.Error = err
		return result, err
	}

	result.Restarted = restartResult.Triggered

	log.Info("Dashboard certificate renewal restart completed",
		"cluster", clusterName,
		"restarted", result.Restarted)

	return result, nil
}
