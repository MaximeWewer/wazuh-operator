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
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/builder/jobs"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// WazuhRestoreFinalizer is the finalizer for WazuhRestore resources
	WazuhRestoreFinalizer = "wazuhrestore.wazuh.com/finalizer"
)

// WazuhRestoreReconciler handles reconciliation of WazuhRestore resources
type WazuhRestoreReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// NewWazuhRestoreReconciler creates a new WazuhRestoreReconciler
func NewWazuhRestoreReconciler(c client.Client, scheme *runtime.Scheme) *WazuhRestoreReconciler {
	return &WazuhRestoreReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles a WazuhRestore resource
func (r *WazuhRestoreReconciler) Reconcile(ctx context.Context, restore *wazuhv1alpha1.WazuhRestore) error {
	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(restore, WazuhRestoreFinalizer) {
		controllerutil.AddFinalizer(restore, WazuhRestoreFinalizer)
		if err := r.Update(ctx, restore); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !restore.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, restore)
	}

	// Skip if already completed or failed
	if restore.Status.Phase == constants.WazuhRestorePhaseCompleted ||
		restore.Status.Phase == constants.WazuhRestorePhaseFailed {
		return nil
	}

	// Validate the referenced WazuhCluster exists
	cluster := &wazuhv1alpha1.WazuhCluster{}
	clusterKey := types.NamespacedName{
		Name:      restore.Spec.ClusterRef.Name,
		Namespace: restore.Namespace,
	}
	if err := r.Get(ctx, clusterKey, cluster); err != nil {
		if errors.IsNotFound(err) {
			return r.updateStatus(ctx, restore, constants.WazuhRestorePhaseFailed,
				fmt.Sprintf("WazuhCluster '%s' not found", restore.Spec.ClusterRef.Name))
		}
		return fmt.Errorf("failed to get WazuhCluster: %w", err)
	}

	// Validate source configuration
	if err := r.validateSource(ctx, restore); err != nil {
		return r.updateStatus(ctx, restore, constants.WazuhRestorePhaseFailed,
			fmt.Sprintf("Invalid source configuration: %v", err))
	}

	// Build RBAC resources
	builder := jobs.NewRestoreJobBuilder(restore)
	if err := r.reconcileRBAC(ctx, restore, builder); err != nil {
		return fmt.Errorf("failed to reconcile RBAC: %w", err)
	}

	// Create the restore Job
	if err := r.reconcileJob(ctx, restore, builder); err != nil {
		return fmt.Errorf("failed to reconcile Job: %w", err)
	}

	log.Info("Successfully reconciled WazuhRestore", "name", restore.Name, "phase", restore.Status.Phase)
	return nil
}

// validateSource validates the restore source configuration
func (r *WazuhRestoreReconciler) validateSource(ctx context.Context, restore *wazuhv1alpha1.WazuhRestore) error {
	if restore.Spec.Source.S3 == nil && restore.Spec.Source.WazuhBackupRef == nil {
		return fmt.Errorf("either s3 or wazuhBackupRef must be specified")
	}

	if restore.Spec.Source.S3 != nil {
		s3 := restore.Spec.Source.S3
		if s3.Bucket == "" {
			return fmt.Errorf("s3.bucket is required")
		}
		if s3.Key == "" {
			return fmt.Errorf("s3.key is required")
		}

		// Validate credentials secret exists
		credsSecret := &corev1.Secret{}
		credsKey := types.NamespacedName{
			Name:      s3.CredentialsSecret.Name,
			Namespace: restore.Namespace,
		}
		if err := r.Get(ctx, credsKey, credsSecret); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("credentials Secret '%s' not found", s3.CredentialsSecret.Name)
			}
			return fmt.Errorf("failed to get credentials Secret: %w", err)
		}
	}

	if restore.Spec.Source.WazuhBackupRef != nil {
		ref := restore.Spec.Source.WazuhBackupRef

		// Validate WazuhBackup exists
		backup := &wazuhv1alpha1.WazuhBackup{}
		backupKey := types.NamespacedName{
			Name:      ref.Name,
			Namespace: restore.Namespace,
		}
		if err := r.Get(ctx, backupKey, backup); err != nil {
			if errors.IsNotFound(err) {
				return fmt.Errorf("WazuhBackup '%s' not found", ref.Name)
			}
			return fmt.Errorf("failed to get WazuhBackup: %w", err)
		}

		// Check that backup has completed at least once
		if backup.Status.LastBackup == nil {
			return fmt.Errorf("WazuhBackup '%s' has no completed backups", ref.Name)
		}
	}

	return nil
}

// reconcileRBAC ensures ServiceAccount, Role, and RoleBinding exist
func (r *WazuhRestoreReconciler) reconcileRBAC(ctx context.Context, restore *wazuhv1alpha1.WazuhRestore, builder *jobs.RestoreJobBuilder) error {
	log := logf.FromContext(ctx)

	// Reconcile ServiceAccount
	sa := builder.BuildServiceAccount()
	if err := controllerutil.SetControllerReference(restore, sa, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on ServiceAccount: %w", err)
	}
	if err := r.createOrUpdate(ctx, sa); err != nil {
		return fmt.Errorf("failed to reconcile ServiceAccount: %w", err)
	}
	log.V(1).Info("Reconciled ServiceAccount", "name", sa.Name)

	// Reconcile Role
	role := builder.BuildRole()
	if err := controllerutil.SetControllerReference(restore, role, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on Role: %w", err)
	}
	if err := r.createOrUpdate(ctx, role); err != nil {
		return fmt.Errorf("failed to reconcile Role: %w", err)
	}
	log.V(1).Info("Reconciled Role", "name", role.Name)

	// Reconcile RoleBinding
	rb := builder.BuildRoleBinding()
	if err := controllerutil.SetControllerReference(restore, rb, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on RoleBinding: %w", err)
	}
	if err := r.createOrUpdate(ctx, rb); err != nil {
		return fmt.Errorf("failed to reconcile RoleBinding: %w", err)
	}
	log.V(1).Info("Reconciled RoleBinding", "name", rb.Name)

	return nil
}

// reconcileJob creates or monitors the restore Job
func (r *WazuhRestoreReconciler) reconcileJob(ctx context.Context, restore *wazuhv1alpha1.WazuhRestore, builder *jobs.RestoreJobBuilder) error {
	log := logf.FromContext(ctx)

	job := builder.BuildJob()
	if err := controllerutil.SetControllerReference(restore, job, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on Job: %w", err)
	}

	// Check if exists
	existing := &batchv1.Job{}
	err := r.Get(ctx, types.NamespacedName{Name: job.Name, Namespace: job.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			// Set start time and create new Job
			now := metav1.Now()
			restore.Status.StartTime = &now
			restore.Status.JobName = job.Name

			// Set source info
			if restore.Spec.Source.S3 != nil {
				restore.Status.SourceBackup = &wazuhv1alpha1.RestoreSourceInfo{
					Location: fmt.Sprintf("s3://%s/%s", restore.Spec.Source.S3.Bucket, restore.Spec.Source.S3.Key),
				}
			}

			if err := r.Create(ctx, job); err != nil {
				return fmt.Errorf("failed to create Job: %w", err)
			}
			log.Info("Created restore Job", "name", job.Name)
			return r.updateStatus(ctx, restore, constants.WazuhRestorePhaseRestoring, "Restore job created")
		}
		return err
	}

	// Job exists - check its status
	restore.Status.JobName = existing.Name

	if existing.Status.Succeeded > 0 {
		// Job completed successfully
		now := metav1.Now()
		restore.Status.EndTime = &now
		if restore.Status.StartTime != nil {
			duration := now.Sub(restore.Status.StartTime.Time)
			restore.Status.Duration = formatDuration(duration)
		}

		log.Info("Restore completed successfully", "name", restore.Name, "duration", restore.Status.Duration)
		return r.updateStatus(ctx, restore, constants.WazuhRestorePhaseCompleted, "Restore completed successfully")
	}

	if existing.Status.Failed > 0 {
		// Job failed
		now := metav1.Now()
		restore.Status.EndTime = &now
		if restore.Status.StartTime != nil {
			duration := now.Sub(restore.Status.StartTime.Time)
			restore.Status.Duration = formatDuration(duration)
		}

		log.Error(nil, "Restore job failed", "name", restore.Name)
		return r.updateStatus(ctx, restore, constants.WazuhRestorePhaseFailed, "Restore job failed")
	}

	// Job still running
	return r.updateStatus(ctx, restore, constants.WazuhRestorePhaseRestoring, "Restore in progress")
}

// createOrUpdate creates or updates a resource
func (r *WazuhRestoreReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
	existing := obj.DeepCopyObject().(client.Object)
	err := r.Get(ctx, types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			return r.Create(ctx, obj)
		}
		return err
	}

	// Update based on type
	switch o := obj.(type) {
	case *corev1.ServiceAccount:
		e := existing.(*corev1.ServiceAccount)
		e.Labels = o.Labels
		return r.Update(ctx, e)
	case *rbacv1.Role:
		e := existing.(*rbacv1.Role)
		e.Labels = o.Labels
		e.Rules = o.Rules
		return r.Update(ctx, e)
	case *rbacv1.RoleBinding:
		e := existing.(*rbacv1.RoleBinding)
		e.Labels = o.Labels
		e.RoleRef = o.RoleRef
		e.Subjects = o.Subjects
		return r.Update(ctx, e)
	}

	return nil
}

// handleDeletion handles cleanup when the WazuhRestore is deleted
func (r *WazuhRestoreReconciler) handleDeletion(ctx context.Context, restore *wazuhv1alpha1.WazuhRestore) error {
	log := logf.FromContext(ctx)

	log.Info("Handling deletion of WazuhRestore", "name", restore.Name)

	// Kubernetes garbage collection will handle owned resources
	controllerutil.RemoveFinalizer(restore, WazuhRestoreFinalizer)
	if err := r.Update(ctx, restore); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	log.Info("Successfully cleaned up WazuhRestore", "name", restore.Name)
	return nil
}

// updateStatus updates the WazuhRestore status
func (r *WazuhRestoreReconciler) updateStatus(ctx context.Context, restore *wazuhv1alpha1.WazuhRestore, phase, message string) error {
	restore.Status.Phase = phase
	restore.Status.Message = message
	restore.Status.ObservedGeneration = restore.Generation

	// Set condition
	conditionStatus := metav1.ConditionFalse
	reason := "RestoreInProgress"
	if phase == constants.WazuhRestorePhaseCompleted {
		conditionStatus = metav1.ConditionTrue
		reason = "RestoreComplete"
	} else if phase == constants.WazuhRestorePhaseFailed {
		reason = "RestoreFailed"
	}

	meta.SetStatusCondition(&restore.Status.Conditions, metav1.Condition{
		Type:               "RestoreComplete",
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: restore.Generation,
	})

	return r.Status().Update(ctx, restore)
}

// Delete handles cleanup when a WazuhRestore CRD is deleted (called by controller)
func (r *WazuhRestoreReconciler) Delete(ctx context.Context, restore *wazuhv1alpha1.WazuhRestore) error {
	return r.handleDeletion(ctx, restore)
}

// formatDuration formats duration into human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm%.0fs", d.Minutes(), d.Seconds()-d.Minutes()*60)
	}
	return fmt.Sprintf("%.0fh%.0fm", d.Hours(), d.Minutes()-d.Hours()*60)
}
