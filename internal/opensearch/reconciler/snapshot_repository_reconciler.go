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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// SnapshotRepositoryFinalizer is the finalizer for snapshot repositories
	SnapshotRepositoryFinalizer = "opensearchsnapshotrepository.resources.wazuh.com/finalizer"
)

// SnapshotRepositoryReconciler handles reconciliation of OpenSearch snapshot repositories
type SnapshotRepositoryReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	APIClient *api.Client
}

// NewSnapshotRepositoryReconciler creates a new SnapshotRepositoryReconciler
func NewSnapshotRepositoryReconciler(c client.Client, scheme *runtime.Scheme) *SnapshotRepositoryReconciler {
	return &SnapshotRepositoryReconciler{
		Client: c,
		Scheme: scheme,
	}
}

// WithAPIClient sets the OpenSearch API client
func (r *SnapshotRepositoryReconciler) WithAPIClient(apiClient *api.Client) *SnapshotRepositoryReconciler {
	r.APIClient = apiClient
	return r
}

// Reconcile reconciles an OpenSearch snapshot repository
func (r *SnapshotRepositoryReconciler) Reconcile(ctx context.Context, repo *wazuhv1alpha1.OpenSearchSnapshotRepository) error {
	log := logf.FromContext(ctx)

	// Handle finalizer
	if !controllerutil.ContainsFinalizer(repo, SnapshotRepositoryFinalizer) {
		controllerutil.AddFinalizer(repo, SnapshotRepositoryFinalizer)
		if err := r.Update(ctx, repo); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	// Check if being deleted
	if !repo.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, repo)
	}

	if r.APIClient == nil {
		return r.updateStatus(ctx, repo, constants.RepositoryPhasePending, "Waiting for OpenSearch API client", false)
	}

	// Create Snapshots API client
	snapshotsAPI := api.NewSnapshotsAPI(r.APIClient)

	// Check if repository exists
	existingRepo, err := snapshotsAPI.GetRepository(ctx, repo.Name)
	if err != nil {
		if updateErr := r.updateStatus(ctx, repo, constants.RepositoryPhaseFailed, fmt.Sprintf("Failed to check repository: %v", err), false); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to check repository existence: %w", err)
	}

	// Build repository settings
	repoSettings, err := r.buildRepositorySettings(ctx, repo)
	if err != nil {
		if updateErr := r.updateStatus(ctx, repo, constants.RepositoryPhaseFailed, fmt.Sprintf("Failed to build settings: %v", err), false); updateErr != nil {
			log.Error(updateErr, "Failed to update status")
		}
		return fmt.Errorf("failed to build repository settings: %w", err)
	}

	osRepo := api.Repository{
		Type:     repo.Spec.Type,
		Settings: repoSettings,
	}

	if existingRepo == nil {
		// Create new repository
		log.Info("Creating snapshot repository", "name", repo.Name, "type", repo.Spec.Type)
		if err := r.updateStatus(ctx, repo, constants.RepositoryPhaseCreating, "Creating repository", false); err != nil {
			log.Error(err, "Failed to update status")
		}

		if err := snapshotsAPI.CreateRepository(ctx, repo.Name, osRepo); err != nil {
			if updateErr := r.updateStatus(ctx, repo, constants.RepositoryPhaseFailed, fmt.Sprintf("Failed to create repository: %v", err), false); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to create repository: %w", err)
		}
	} else {
		// Update existing repository
		log.Info("Updating snapshot repository", "name", repo.Name)
		if err := snapshotsAPI.UpdateRepository(ctx, repo.Name, osRepo); err != nil {
			if updateErr := r.updateStatus(ctx, repo, constants.RepositoryPhaseFailed, fmt.Sprintf("Failed to update repository: %v", err), false); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("failed to update repository: %w", err)
		}
	}

	// Verify repository if enabled
	verified := false
	if repo.Spec.Verify {
		if err := r.updateStatus(ctx, repo, constants.RepositoryPhaseVerifying, "Verifying repository", false); err != nil {
			log.Error(err, "Failed to update status")
		}

		_, err := snapshotsAPI.VerifyRepository(ctx, repo.Name)
		if err != nil {
			if updateErr := r.updateStatus(ctx, repo, constants.RepositoryPhaseFailed, fmt.Sprintf("Repository verification failed: %v", err), false); updateErr != nil {
				log.Error(updateErr, "Failed to update status")
			}
			return fmt.Errorf("repository verification failed: %w", err)
		}
		verified = true
		log.Info("Repository verification succeeded", "name", repo.Name)
	}

	// Get snapshot count
	snapshotCount := int32(0)
	if snapshots, err := snapshotsAPI.ListSnapshots(ctx, repo.Name); err == nil && snapshots != nil {
		snapshotCount = int32(len(snapshots.Snapshots))
	}

	// Update status to Ready
	repo.Status.Phase = constants.RepositoryPhaseReady
	repo.Status.Message = "Repository is ready"
	repo.Status.Verified = verified
	repo.Status.SnapshotCount = snapshotCount
	repo.Status.ObservedGeneration = repo.Generation
	now := metav1.Now()
	repo.Status.LastSyncTime = &now
	if verified {
		repo.Status.LastVerifiedTime = &now
	}

	// Set condition
	meta.SetStatusCondition(&repo.Status.Conditions, metav1.Condition{
		Type:               constants.ConditionTypeRepositoryReady,
		Status:             metav1.ConditionTrue,
		Reason:             "RepositoryReady",
		Message:            "Repository is ready and verified",
		ObservedGeneration: repo.Generation,
	})

	if err := r.Status().Update(ctx, repo); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("Snapshot repository reconciliation completed", "name", repo.Name, "verified", verified, "snapshots", snapshotCount)
	return nil
}

// handleDeletion handles repository cleanup on deletion
func (r *SnapshotRepositoryReconciler) handleDeletion(ctx context.Context, repo *wazuhv1alpha1.OpenSearchSnapshotRepository) error {
	log := logf.FromContext(ctx)

	if r.APIClient != nil {
		snapshotsAPI := api.NewSnapshotsAPI(r.APIClient)

		// Check if repository has snapshots
		if snapshots, err := snapshotsAPI.ListSnapshots(ctx, repo.Name); err == nil && snapshots != nil && len(snapshots.Snapshots) > 0 {
			log.Info("Repository has snapshots, they will remain in storage", "name", repo.Name, "count", len(snapshots.Snapshots))
		}

		// Delete the repository from OpenSearch
		if err := snapshotsAPI.DeleteRepository(ctx, repo.Name); err != nil {
			log.Error(err, "Failed to delete repository from OpenSearch", "name", repo.Name)
			// Continue with finalizer removal even if deletion fails
		} else {
			log.Info("Deleted repository from OpenSearch", "name", repo.Name)
		}
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(repo, SnapshotRepositoryFinalizer)
	if err := r.Update(ctx, repo); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	return nil
}

// buildRepositorySettings builds the OpenSearch repository settings from the CRD spec
func (r *SnapshotRepositoryReconciler) buildRepositorySettings(ctx context.Context, repo *wazuhv1alpha1.OpenSearchSnapshotRepository) (map[string]interface{}, error) {
	settings := make(map[string]interface{})

	spec := repo.Spec.Settings

	// Common settings
	if spec.Bucket != "" {
		settings["bucket"] = spec.Bucket
	}
	if spec.BasePath != "" {
		settings["base_path"] = spec.BasePath
	}
	if spec.Compress {
		settings["compress"] = true
	}
	if spec.ChunkSize != "" {
		settings["chunk_size"] = spec.ChunkSize
	}
	if spec.MaxRestoreBytesPerSec != "" {
		settings["max_restore_bytes_per_sec"] = spec.MaxRestoreBytesPerSec
	}
	if spec.MaxSnapshotBytesPerSec != "" {
		settings["max_snapshot_bytes_per_sec"] = spec.MaxSnapshotBytesPerSec
	}
	if spec.ReadOnly {
		settings["readonly"] = true
	}

	// Type-specific settings
	switch repo.Spec.Type {
	case constants.RepositoryTypeS3:
		if spec.Region != "" {
			settings["region"] = spec.Region
		}
		if spec.Endpoint != "" {
			settings["endpoint"] = spec.Endpoint
		}
		if spec.PathStyleAccess {
			settings["path_style_access"] = true
		}
		if spec.ServerSideEncryption {
			settings["server_side_encryption"] = true
		}
		if spec.StorageClass != "" {
			settings["storage_class"] = spec.StorageClass
		}
		if spec.CannedACL != "" {
			settings["canned_acl"] = spec.CannedACL
		}

	case constants.RepositoryTypeFS:
		if spec.Location != "" {
			settings["location"] = spec.Location
		}

	case constants.RepositoryTypeAzure:
		if spec.Container != "" {
			settings["container"] = spec.Container
		}
	}

	// Load credentials from Secret if specified
	if spec.CredentialsSecret != nil {
		accessKey, secretKey, err := r.loadCredentials(ctx, repo.Namespace, spec.CredentialsSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to load credentials: %w", err)
		}

		// Set credentials based on repository type
		switch repo.Spec.Type {
		case constants.RepositoryTypeS3:
			settings["access_key"] = accessKey
			settings["secret_key"] = secretKey
		case constants.RepositoryTypeAzure:
			settings["account"] = accessKey
			settings["key"] = secretKey
		}
	}

	return settings, nil
}

// loadCredentials loads credentials from a Kubernetes Secret
func (r *SnapshotRepositoryReconciler) loadCredentials(ctx context.Context, namespace string, ref *wazuhv1alpha1.RepositoryCredentialsRef) (string, string, error) {
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: namespace}, secret); err != nil {
		return "", "", fmt.Errorf("failed to get credentials secret %s: %w", ref.Name, err)
	}

	accessKeyKey := ref.AccessKeyKey
	if accessKeyKey == "" {
		accessKeyKey = constants.DefaultAccessKeyKey
	}
	secretKeyKey := ref.SecretKeyKey
	if secretKeyKey == "" {
		secretKeyKey = constants.DefaultSecretKeyKey
	}

	accessKey, ok := secret.Data[accessKeyKey]
	if !ok {
		return "", "", fmt.Errorf("access key not found in secret %s (key: %s)", ref.Name, accessKeyKey)
	}

	secretKey, ok := secret.Data[secretKeyKey]
	if !ok {
		return "", "", fmt.Errorf("secret key not found in secret %s (key: %s)", ref.Name, secretKeyKey)
	}

	return string(accessKey), string(secretKey), nil
}

// updateStatus updates the repository status
func (r *SnapshotRepositoryReconciler) updateStatus(ctx context.Context, repo *wazuhv1alpha1.OpenSearchSnapshotRepository, phase, message string, verified bool) error {
	repo.Status.Phase = phase
	repo.Status.Message = message
	repo.Status.Verified = verified
	now := metav1.Now()
	repo.Status.LastSyncTime = &now

	return r.Status().Update(ctx, repo)
}

// Delete handles cleanup when a snapshot repository is deleted (called by controller)
func (r *SnapshotRepositoryReconciler) Delete(ctx context.Context, repo *wazuhv1alpha1.OpenSearchSnapshotRepository) error {
	return r.handleDeletion(ctx, repo)
}
