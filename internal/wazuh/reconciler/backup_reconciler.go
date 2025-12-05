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
	// WazuhBackupFinalizer is the finalizer for WazuhBackup resources
	WazuhBackupFinalizer = "wazuhbackup.wazuh.com/finalizer"
)

// BackupReconciler handles reconciliation of WazuhBackup resources
type BackupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// NewBackupReconciler creates a new BackupReconciler
func NewBackupReconciler(c client.Client, scheme *runtime.Scheme) *BackupReconciler {
	return &BackupReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// Reconcile reconciles a WazuhBackup resource
func (r *BackupReconciler) Reconcile(ctx context.Context, backup *wazuhv1alpha1.WazuhBackup) error {
	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(backup, WazuhBackupFinalizer) {
		controllerutil.AddFinalizer(backup, WazuhBackupFinalizer)
		if err := r.Update(ctx, backup); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !backup.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, backup)
	}

	// Validate the referenced WazuhCluster exists
	cluster := &wazuhv1alpha1.WazuhCluster{}
	clusterKey := types.NamespacedName{
		Name:      backup.Spec.ClusterRef.Name,
		Namespace: backup.Namespace,
	}
	if err := r.Get(ctx, clusterKey, cluster); err != nil {
		if errors.IsNotFound(err) {
			return r.updateStatus(ctx, backup, constants.WazuhBackupPhaseFailed,
				fmt.Sprintf("WazuhCluster '%s' not found", backup.Spec.ClusterRef.Name))
		}
		return fmt.Errorf("failed to get WazuhCluster: %w", err)
	}

	// Validate credentials secret exists
	credsSecret := &corev1.Secret{}
	credsKey := types.NamespacedName{
		Name:      backup.Spec.Storage.CredentialsSecret.Name,
		Namespace: backup.Namespace,
	}
	if err := r.Get(ctx, credsKey, credsSecret); err != nil {
		if errors.IsNotFound(err) {
			return r.updateStatus(ctx, backup, constants.WazuhBackupPhaseFailed,
				fmt.Sprintf("Credentials Secret '%s' not found", backup.Spec.Storage.CredentialsSecret.Name))
		}
		return fmt.Errorf("failed to get credentials Secret: %w", err)
	}

	// Build RBAC resources
	builder := jobs.NewBackupJobBuilder(backup)
	if err := r.reconcileRBAC(ctx, backup, builder); err != nil {
		return fmt.Errorf("failed to reconcile RBAC: %w", err)
	}

	// Reconcile Job or CronJob based on schedule
	if backup.IsScheduled() {
		if err := r.reconcileCronJob(ctx, backup, builder); err != nil {
			return fmt.Errorf("failed to reconcile CronJob: %w", err)
		}
	} else {
		if err := r.reconcileJob(ctx, backup, builder); err != nil {
			return fmt.Errorf("failed to reconcile Job: %w", err)
		}
	}

	// Update status
	phase := constants.WazuhBackupPhaseActive
	message := "Backup scheduled"
	if !backup.IsScheduled() {
		message = "One-shot backup job created"
	}
	if backup.Spec.Suspend {
		phase = constants.WazuhBackupPhaseSuspended
		message = "Backup suspended"
	}

	log.Info("Successfully reconciled WazuhBackup", "name", backup.Name, "phase", phase)
	return r.updateStatus(ctx, backup, phase, message)
}

// reconcileRBAC ensures ServiceAccount, Role, and RoleBinding exist
func (r *BackupReconciler) reconcileRBAC(ctx context.Context, backup *wazuhv1alpha1.WazuhBackup, builder *jobs.BackupJobBuilder) error {
	log := logf.FromContext(ctx)

	// Reconcile ServiceAccount
	sa := builder.BuildServiceAccount()
	if err := controllerutil.SetControllerReference(backup, sa, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on ServiceAccount: %w", err)
	}
	if err := r.createOrUpdate(ctx, sa); err != nil {
		return fmt.Errorf("failed to reconcile ServiceAccount: %w", err)
	}
	log.V(1).Info("Reconciled ServiceAccount", "name", sa.Name)

	// Reconcile Role
	role := builder.BuildRole()
	if err := controllerutil.SetControllerReference(backup, role, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on Role: %w", err)
	}
	if err := r.createOrUpdate(ctx, role); err != nil {
		return fmt.Errorf("failed to reconcile Role: %w", err)
	}
	log.V(1).Info("Reconciled Role", "name", role.Name)

	// Reconcile RoleBinding
	rb := builder.BuildRoleBinding()
	if err := controllerutil.SetControllerReference(backup, rb, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on RoleBinding: %w", err)
	}
	if err := r.createOrUpdate(ctx, rb); err != nil {
		return fmt.Errorf("failed to reconcile RoleBinding: %w", err)
	}
	log.V(1).Info("Reconciled RoleBinding", "name", rb.Name)

	return nil
}

// reconcileCronJob creates or updates the CronJob for scheduled backups
func (r *BackupReconciler) reconcileCronJob(ctx context.Context, backup *wazuhv1alpha1.WazuhBackup, builder *jobs.BackupJobBuilder) error {
	log := logf.FromContext(ctx)

	cronJob := builder.BuildCronJob()
	if err := controllerutil.SetControllerReference(backup, cronJob, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on CronJob: %w", err)
	}

	// Check if exists
	existing := &batchv1.CronJob{}
	err := r.Get(ctx, types.NamespacedName{Name: cronJob.Name, Namespace: cronJob.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			// Create new CronJob
			if err := r.Create(ctx, cronJob); err != nil {
				return fmt.Errorf("failed to create CronJob: %w", err)
			}
			log.Info("Created CronJob", "name", cronJob.Name)
			backup.Status.CronJobName = cronJob.Name
			return nil
		}
		return err
	}

	// Update existing CronJob
	existing.Spec = cronJob.Spec
	existing.Labels = cronJob.Labels
	if err := r.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update CronJob: %w", err)
	}
	log.Info("Updated CronJob", "name", cronJob.Name)
	backup.Status.CronJobName = cronJob.Name

	return nil
}

// reconcileJob creates the one-shot Job for immediate backup
func (r *BackupReconciler) reconcileJob(ctx context.Context, backup *wazuhv1alpha1.WazuhBackup, builder *jobs.BackupJobBuilder) error {
	log := logf.FromContext(ctx)

	job := builder.BuildJob()
	if err := controllerutil.SetControllerReference(backup, job, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference on Job: %w", err)
	}

	// Check if exists
	existing := &batchv1.Job{}
	err := r.Get(ctx, types.NamespacedName{Name: job.Name, Namespace: job.Namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			// Create new Job
			if err := r.Create(ctx, job); err != nil {
				return fmt.Errorf("failed to create Job: %w", err)
			}
			log.Info("Created Job", "name", job.Name)
			backup.Status.JobName = job.Name
			return nil
		}
		return err
	}

	// Job already exists - check its status
	backup.Status.JobName = existing.Name

	// Update backup status based on job status
	if existing.Status.Succeeded > 0 {
		// Job completed successfully
		now := metav1.Now()
		backup.Status.LastBackup = &wazuhv1alpha1.BackupInfo{
			Time:    now,
			Status:  constants.BackupStatusSuccess,
			Message: "Backup completed successfully",
		}
	} else if existing.Status.Failed > 0 {
		// Job failed
		now := metav1.Now()
		backup.Status.LastBackup = &wazuhv1alpha1.BackupInfo{
			Time:    now,
			Status:  constants.BackupStatusFailed,
			Message: "Backup job failed",
		}
	}

	return nil
}

// createOrUpdate creates or updates a resource
func (r *BackupReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
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

// handleDeletion handles cleanup when the WazuhBackup is deleted
func (r *BackupReconciler) handleDeletion(ctx context.Context, backup *wazuhv1alpha1.WazuhBackup) error {
	log := logf.FromContext(ctx)

	log.Info("Handling deletion of WazuhBackup", "name", backup.Name)

	// Kubernetes garbage collection will handle owned resources (Job, CronJob, RBAC)
	// Remove the finalizer
	controllerutil.RemoveFinalizer(backup, WazuhBackupFinalizer)
	if err := r.Update(ctx, backup); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	log.Info("Successfully cleaned up WazuhBackup", "name", backup.Name)
	return nil
}

// updateStatus updates the WazuhBackup status
func (r *BackupReconciler) updateStatus(ctx context.Context, backup *wazuhv1alpha1.WazuhBackup, phase, message string) error {
	backup.Status.Phase = phase
	backup.Status.Message = message
	backup.Status.ObservedGeneration = backup.Generation

	// Set condition
	conditionStatus := metav1.ConditionTrue
	reason := "BackupReady"
	if phase == constants.WazuhBackupPhaseFailed {
		conditionStatus = metav1.ConditionFalse
		reason = "BackupFailed"
	} else if phase == constants.WazuhBackupPhaseSuspended {
		conditionStatus = metav1.ConditionFalse
		reason = "BackupSuspended"
	} else if phase == constants.WazuhBackupPhasePending {
		conditionStatus = metav1.ConditionFalse
		reason = "BackupPending"
	}

	meta.SetStatusCondition(&backup.Status.Conditions, metav1.Condition{
		Type:               constants.ConditionTypeBackupScheduled,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: backup.Generation,
	})

	return r.Status().Update(ctx, backup)
}

// Delete handles cleanup when a WazuhBackup CRD is deleted (called by controller)
func (r *BackupReconciler) Delete(ctx context.Context, backup *wazuhv1alpha1.WazuhBackup) error {
	return r.handleDeletion(ctx, backup)
}
