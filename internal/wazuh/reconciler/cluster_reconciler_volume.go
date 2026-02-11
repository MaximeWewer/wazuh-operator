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

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/shared/storage"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// reconcileMasterVolumeExpansion handles PVC volume expansion for manager master pods
func (r *ClusterReconciler) reconcileMasterVolumeExpansion(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get requested storage size from spec
	requestedSize := constants.DefaultManagerStorageSize
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Master.StorageSize != "" {
		requestedSize = cluster.Spec.Manager.Master.StorageSize
	}

	// List all manager master PVCs
	pvcList, err := r.getManagerMasterPVCs(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to list manager master PVCs: %w", err)
	}

	if len(pvcList.Items) == 0 {
		log.V(1).Info("No manager master PVCs found, skipping volume expansion check")
		return nil
	}

	pvcsExpanded, pvcsPending, expansionNeeded, expansionError := r.processVolumeExpansion(ctx, cluster, pvcList, requestedSize, "manager-master")
	r.updateManagerMasterExpansionStatus(ctx, cluster, requestedSize, pvcsExpanded, pvcsPending, expansionError)

	if len(pvcsPending) == 0 && len(pvcsExpanded) > 0 && expansionNeeded {
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonVolumeExpansionCompleted,
				fmt.Sprintf("All manager master PVCs expanded successfully to %s", requestedSize))
		}
	}

	return nil
}

// reconcileWorkerVolumeExpansion handles PVC volume expansion for manager worker pods
func (r *ClusterReconciler) reconcileWorkerVolumeExpansion(ctx context.Context, cluster *wazuhv1.WazuhCluster) error {
	log := logf.FromContext(ctx)

	// Get requested storage size from spec
	requestedSize := constants.DefaultManagerStorageSize
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.StorageSize != "" {
		requestedSize = cluster.Spec.Manager.Workers.StorageSize
	}

	// List all manager worker PVCs
	pvcList, err := r.getManagerWorkerPVCs(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to list manager worker PVCs: %w", err)
	}

	if len(pvcList.Items) == 0 {
		log.V(1).Info("No manager worker PVCs found, skipping volume expansion check")
		return nil
	}

	pvcsExpanded, pvcsPending, expansionNeeded, expansionError := r.processVolumeExpansion(ctx, cluster, pvcList, requestedSize, "manager-worker")
	r.updateManagerWorkerExpansionStatus(ctx, cluster, requestedSize, pvcsExpanded, pvcsPending, expansionError)

	if len(pvcsPending) == 0 && len(pvcsExpanded) > 0 && expansionNeeded {
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonVolumeExpansionCompleted,
				fmt.Sprintf("All manager worker PVCs expanded successfully to %s", requestedSize))
		}
	}

	return nil
}

// processVolumeExpansion handles the common PVC expansion logic for a list of PVCs.
// Returns lists of expanded/pending PVCs, whether expansion was needed, and any error.
func (r *ClusterReconciler) processVolumeExpansion(ctx context.Context, cluster *wazuhv1.WazuhCluster, pvcList *corev1.PersistentVolumeClaimList, requestedSize, componentName string) (pvcsExpanded, pvcsPending []string, expansionNeeded bool, expansionError error) {
	log := logf.FromContext(ctx)

	for i := range pvcList.Items {
		pvc := &pvcList.Items[i]

		validationResult, err := storage.ValidateExpansion(ctx, r.Client, pvc, requestedSize)
		if err != nil {
			log.Error(err, "Failed to validate expansion for PVC", "pvc", pvc.Name)
			expansionError = err
			continue
		}

		if !validationResult.Valid {
			if validationResult.ErrorMessage != "" {
				isShrink, _ := storage.IsShrinkRequest(validationResult.CurrentSize.String(), requestedSize)
				if isShrink {
					if r.Recorder != nil {
						r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonStorageSizeDecreaseRejected,
							fmt.Sprintf("Cannot decrease storage size for PVC %s: Kubernetes does not support shrinking PVCs", pvc.Name))
					}
					log.Info("Storage size decrease rejected",
						"pvc", pvc.Name,
						"currentSize", validationResult.CurrentSize.String(),
						"requestedSize", requestedSize)
					continue
				}

				if !validationResult.StorageClassSupportsExpansion && validationResult.NeedsExpansion {
					if r.Recorder != nil {
						r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonStorageClassNotExpandable,
							fmt.Sprintf("StorageClass for PVC %s does not support volume expansion", pvc.Name))
					}
					log.Info("StorageClass does not support volume expansion",
						"pvc", pvc.Name,
						"error", validationResult.ErrorMessage)
					expansionError = fmt.Errorf("storage class does not support expansion: %s", validationResult.ErrorMessage)
					continue
				}
			}
			continue
		}

		if !validationResult.NeedsExpansion {
			pvcsExpanded = append(pvcsExpanded, pvc.Name)
			continue
		}

		expansionNeeded = true
		pvcsPending = append(pvcsPending, pvc.Name)

		condition := storage.GetPVCExpansionCondition(pvc)
		if !condition.IsComplete {
			log.V(1).Info("PVC expansion already in progress",
				"pvc", pvc.Name,
				"phase", condition.Phase,
				"message", condition.Message)
			continue
		}

		if len(pvcsPending) == 1 && len(pvcsExpanded) == 0 {
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonVolumeExpansionStarted,
					fmt.Sprintf("Starting volume expansion for %s PVCs to %s", componentName, requestedSize))
			}
		}

		log.Info("Expanding PVC",
			"component", componentName,
			"pvc", pvc.Name,
			"currentSize", validationResult.CurrentSize.String(),
			"requestedSize", requestedSize)

		if err := storage.ExpandPVC(ctx, r.Client, pvc, requestedSize); err != nil {
			log.Error(err, "Failed to expand PVC", "pvc", pvc.Name)
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonVolumeExpansionFailed,
					fmt.Sprintf("Failed to expand PVC %s: %v", pvc.Name, err))
			}
			expansionError = err
			continue
		}

		log.Info("PVC expansion initiated",
			"pvc", pvc.Name,
			"newSize", requestedSize)
	}

	return pvcsExpanded, pvcsPending, expansionNeeded, expansionError
}

// getManagerMasterPVCs lists all PVCs belonging to the manager master StatefulSet
func (r *ClusterReconciler) getManagerMasterPVCs(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*corev1.PersistentVolumeClaimList, error) {
	pvcList := &corev1.PersistentVolumeClaimList{}

	listOpts := []client.ListOption{
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels{
			constants.LabelInstance:  cluster.Name,
			constants.LabelComponent: constants.ComponentManagerMaster,
		},
	}

	if err := r.List(ctx, pvcList, listOpts...); err != nil {
		return nil, fmt.Errorf("failed to list manager master PVCs: %w", err)
	}

	return pvcList, nil
}

// getManagerWorkerPVCs lists all PVCs belonging to the manager workers StatefulSet
func (r *ClusterReconciler) getManagerWorkerPVCs(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*corev1.PersistentVolumeClaimList, error) {
	pvcList := &corev1.PersistentVolumeClaimList{}

	listOpts := []client.ListOption{
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels{
			constants.LabelInstance:  cluster.Name,
			constants.LabelComponent: constants.ComponentManagerWorker,
		},
	}

	if err := r.List(ctx, pvcList, listOpts...); err != nil {
		return nil, fmt.Errorf("failed to list manager worker PVCs: %w", err)
	}

	return pvcList, nil
}

// updateManagerMasterExpansionStatus updates the manager master expansion status
func (r *ClusterReconciler) updateManagerMasterExpansionStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster, requestedSize string, pvcsExpanded, pvcsPending []string, expansionError error) {
	log := logf.FromContext(ctx)

	if cluster.Status.VolumeExpansion == nil {
		cluster.Status.VolumeExpansion = &wazuhv1.VolumeExpansionStatus{}
	}

	var update storage.ExpansionStatusUpdate

	currentSize := requestedSize
	if len(pvcsExpanded) == 0 && len(pvcsPending) > 0 {
		pvcList, err := r.getManagerMasterPVCs(ctx, cluster)
		if err == nil && len(pvcList.Items) > 0 {
			currentSize = storage.GetPVCStorageSize(&pvcList.Items[0])
		}
	}

	if expansionError != nil {
		update = storage.CreateFailedStatus(requestedSize, currentSize, expansionError.Error(), pvcsExpanded, pvcsPending)
	} else if len(pvcsPending) > 0 {
		if len(pvcsExpanded) > 0 {
			update = storage.CreateInProgressStatus(requestedSize, currentSize, pvcsExpanded, pvcsPending)
		} else {
			update = storage.CreatePendingStatus(requestedSize, currentSize, pvcsPending)
		}
	} else if len(pvcsExpanded) > 0 {
		update = storage.CreateCompletedStatus(requestedSize, pvcsExpanded)
	} else {
		cluster.Status.VolumeExpansion.ManagerMasterExpansion = nil
		return
	}

	cluster.Status.VolumeExpansion.ManagerMasterExpansion = storage.UpdateComponentExpansionStatus(
		cluster.Status.VolumeExpansion.ManagerMasterExpansion,
		update,
	)

	log.V(1).Info("Updated manager master expansion status",
		"phase", update.Phase,
		"pvcsExpanded", len(pvcsExpanded),
		"pvcsPending", len(pvcsPending))
}

// updateManagerWorkerExpansionStatus updates the manager worker expansion status
func (r *ClusterReconciler) updateManagerWorkerExpansionStatus(ctx context.Context, cluster *wazuhv1.WazuhCluster, requestedSize string, pvcsExpanded, pvcsPending []string, expansionError error) {
	log := logf.FromContext(ctx)

	if cluster.Status.VolumeExpansion == nil {
		cluster.Status.VolumeExpansion = &wazuhv1.VolumeExpansionStatus{}
	}

	var update storage.ExpansionStatusUpdate

	currentSize := requestedSize
	if len(pvcsExpanded) == 0 && len(pvcsPending) > 0 {
		pvcList, err := r.getManagerWorkerPVCs(ctx, cluster)
		if err == nil && len(pvcList.Items) > 0 {
			currentSize = storage.GetPVCStorageSize(&pvcList.Items[0])
		}
	}

	if expansionError != nil {
		update = storage.CreateFailedStatus(requestedSize, currentSize, expansionError.Error(), pvcsExpanded, pvcsPending)
	} else if len(pvcsPending) > 0 {
		if len(pvcsExpanded) > 0 {
			update = storage.CreateInProgressStatus(requestedSize, currentSize, pvcsExpanded, pvcsPending)
		} else {
			update = storage.CreatePendingStatus(requestedSize, currentSize, pvcsPending)
		}
	} else if len(pvcsExpanded) > 0 {
		update = storage.CreateCompletedStatus(requestedSize, pvcsExpanded)
	} else {
		cluster.Status.VolumeExpansion.ManagerWorkersExpansion = nil
		return
	}

	cluster.Status.VolumeExpansion.ManagerWorkersExpansion = storage.UpdateComponentExpansionStatus(
		cluster.Status.VolumeExpansion.ManagerWorkersExpansion,
		update,
	)

	log.V(1).Info("Updated manager worker expansion status",
		"phase", update.Phase,
		"pvcsExpanded", len(pvcsExpanded),
		"pvcsPending", len(pvcsPending))
}
