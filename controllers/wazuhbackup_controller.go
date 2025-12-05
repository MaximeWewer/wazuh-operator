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

package controllers

import (
	"context"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// WazuhBackupReconciler reconciles a WazuhBackup object
type WazuhBackupReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Helper reconciler
	BackupReconciler *wazuhreconciler.BackupReconciler
}

// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhbackups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhbackups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resources.wazuh.com,resources=wazuhbackups/finalizers,verbs=update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete

// Reconcile is the main reconciliation loop for WazuhBackup
func (r *WazuhBackupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the WazuhBackup instance
	backup := &wazuhv1alpha1.WazuhBackup{}
	if err := r.Get(ctx, req.NamespacedName, backup); err != nil {
		if errors.IsNotFound(err) {
			log.Info("WazuhBackup resource not found, ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get WazuhBackup")
		return ctrl.Result{}, err
	}

	// Delegate to helper reconciler
	if err := r.BackupReconciler.Reconcile(ctx, backup); err != nil {
		log.Error(err, "Failed to reconcile WazuhBackup")
		// Requeue with backoff for transient errors
		return ctrl.Result{RequeueAfter: 30 * time.Second}, err
	}

	// Requeue periodically to check job status for one-shot backups
	if !backup.IsScheduled() && backup.Status.Phase != constants.WazuhBackupPhaseFailed {
		// Check job status periodically until completed
		if backup.Status.LastBackup == nil || backup.Status.LastBackup.Status == "" {
			log.Info("One-shot backup in progress, requeuing for status check", "name", backup.Name)
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
	}

	log.Info("Successfully reconciled WazuhBackup", "name", backup.Name, "phase", backup.Status.Phase)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *WazuhBackupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wazuhv1alpha1.WazuhBackup{}).
		Owns(&batchv1.Job{}).
		Owns(&batchv1.CronJob{}).
		Watches(
			&batchv1.Job{},
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &wazuhv1alpha1.WazuhBackup{}),
		).
		Named("wazuhbackup").
		Complete(r)
}
