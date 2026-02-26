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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

const (
	// AgentGroupFinalizer is the finalizer for WazuhAgentGroup resources
	AgentGroupFinalizer = "wazuhagentgroup.resources.wazuh.com/finalizer"

	// Condition types for agent groups
	ConditionTypeGroupSynced = "GroupSynced"
)

// AgentGroupReconciler handles reconciliation of Wazuh Agent Groups
type AgentGroupReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// NewAgentGroupReconciler creates a new AgentGroupReconciler
func NewAgentGroupReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *AgentGroupReconciler {
	return &AgentGroupReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: recorder,
	}
}

// Reconcile reconciles the WazuhAgentGroup
func (r *AgentGroupReconciler) Reconcile(ctx context.Context, group *wazuhv1.WazuhAgentGroup) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "AgentGroupReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", group.Name),
			attribute.String("resource.namespace", group.Namespace),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)

	// Initialize status if needed
	if group.Status.Phase == "" {
		group.Status.Phase = wazuhv1.AgentGroupPhasePending
	}

	groupName := group.ResolveGroupName()

	// Verify referenced cluster exists
	cluster := &wazuhv1.WazuhCluster{}
	clusterNamespace := group.Spec.ClusterRef.Namespace
	if clusterNamespace == "" {
		clusterNamespace = group.Namespace
	}
	clusterKey := types.NamespacedName{Name: group.Spec.ClusterRef.Name, Namespace: clusterNamespace}
	if err := r.Get(ctx, clusterKey, cluster); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Referenced WazuhCluster not found", "cluster", clusterKey)
			r.setCondition(group, ConditionTypeReady, metav1.ConditionFalse, "ClusterNotFound",
				fmt.Sprintf("Referenced WazuhCluster %s not found", clusterKey))
			group.Status.Phase = wazuhv1.AgentGroupPhasePending
			if r.Recorder != nil {
				r.Recorder.Event(group, corev1.EventTypeWarning, "ClusterNotFound",
					fmt.Sprintf("Referenced WazuhCluster %s not found", clusterKey))
			}
			return r.updateStatus(ctx, group)
		}
		return fmt.Errorf("failed to get referenced WazuhCluster %s: %w", clusterKey, err)
	}

	// Build Wazuh API client
	apiClient, err := r.buildAPIClient(ctx, cluster)
	if err != nil {
		group.Status.Phase = wazuhv1.AgentGroupPhasePending
		r.setCondition(group, ConditionTypeReady, metav1.ConditionFalse, "APIUnavailable",
			fmt.Sprintf("Wazuh API unavailable: %v", err))
		group.Status.Message = fmt.Sprintf("Wazuh API unavailable: %v", err)
		_ = r.updateStatus(ctx, group)
		return &WazuhAPIUnavailableError{Err: err}
	}

	// Check API health
	if !apiClient.IsHealthy(ctx) {
		group.Status.Phase = wazuhv1.AgentGroupPhasePending
		r.setCondition(group, ConditionTypeReady, metav1.ConditionFalse, "APIUnavailable",
			"Wazuh API is not healthy")
		group.Status.Message = "Wazuh API is not healthy"
		_ = r.updateStatus(ctx, group)
		return &WazuhAPIUnavailableError{Err: fmt.Errorf("wazuh API health check failed")}
	}

	// Check if group exists
	groupInfo, err := apiClient.GetGroup(ctx, groupName)
	if err != nil {
		// Treat errors as API unavailable
		group.Status.Phase = wazuhv1.AgentGroupPhasePending
		r.setCondition(group, ConditionTypeReady, metav1.ConditionFalse, "APIError",
			fmt.Sprintf("Failed to query group: %v", err))
		group.Status.Message = fmt.Sprintf("Failed to query group: %v", err)
		_ = r.updateStatus(ctx, group)
		return &WazuhAPIUnavailableError{Err: err}
	}

	// Create group if it doesn't exist
	if groupInfo == nil {
		log.Info("Creating agent group", "group", groupName)
		if err := apiClient.CreateGroup(ctx, groupName); err != nil {
			group.Status.Phase = wazuhv1.AgentGroupPhaseFailed
			r.setCondition(group, ConditionTypeGroupSynced, metav1.ConditionFalse, "CreateFailed",
				fmt.Sprintf("Failed to create group: %v", err))
			r.setCondition(group, ConditionTypeReady, metav1.ConditionFalse, "CreateFailed",
				"Failed to create agent group")
			group.Status.Message = fmt.Sprintf("Failed to create group: %v", err)
			if r.Recorder != nil {
				r.Recorder.Event(group, corev1.EventTypeWarning, "CreateFailed", err.Error())
			}
			return r.updateStatus(ctx, group)
		}
		if r.Recorder != nil {
			r.Recorder.Event(group, corev1.EventTypeNormal, "GroupCreated",
				fmt.Sprintf("Agent group %s created", groupName))
		}
	}

	// Push agent.conf if specified
	if group.Spec.AgentConf != "" {
		specHash := computeSpecHash(group)
		if specHash != group.Status.LastAppliedHash {
			log.Info("Updating agent group configuration", "group", groupName)
			if err := apiClient.UpdateGroupConfiguration(ctx, groupName, group.Spec.AgentConf); err != nil {
				group.Status.Phase = wazuhv1.AgentGroupPhaseFailed
				r.setCondition(group, ConditionTypeGroupSynced, metav1.ConditionFalse, "ConfigUpdateFailed",
					fmt.Sprintf("Failed to update group configuration: %v", err))
				r.setCondition(group, ConditionTypeReady, metav1.ConditionFalse, "ConfigUpdateFailed",
					"Failed to update agent.conf")
				group.Status.Message = fmt.Sprintf("Failed to update configuration: %v", err)
				if r.Recorder != nil {
					r.Recorder.Event(group, corev1.EventTypeWarning, "ConfigUpdateFailed", err.Error())
				}
				return r.updateStatus(ctx, group)
			}
			group.Status.LastAppliedHash = specHash
			if r.Recorder != nil {
				r.Recorder.Event(group, corev1.EventTypeNormal, "ConfigUpdated",
					fmt.Sprintf("Agent group %s configuration updated", groupName))
			}
		}
	}

	// Reconcile files ConfigMap
	if err := r.reconcileFilesConfigMap(ctx, group); err != nil {
		log.Error(err, "Failed to reconcile agent group files ConfigMap")
		group.Status.Phase = wazuhv1.AgentGroupPhaseFailed
		r.setCondition(group, ConditionTypeReady, metav1.ConditionFalse, "FilesConfigMapFailed",
			fmt.Sprintf("Failed to reconcile files ConfigMap: %v", err))
		group.Status.Message = fmt.Sprintf("Failed to reconcile files ConfigMap: %v", err)
		return r.updateStatus(ctx, group)
	}

	// Refresh group info to get agent count (best-effort)
	groupInfo, err = apiClient.GetGroup(ctx, groupName)
	if err == nil && groupInfo != nil {
		group.Status.AgentCount = groupInfo.Count
	}

	// Set ready
	group.Status.Phase = wazuhv1.AgentGroupPhaseReady
	r.setCondition(group, ConditionTypeGroupSynced, metav1.ConditionTrue, "Synced",
		fmt.Sprintf("Agent group %s is synced", groupName))
	r.setCondition(group, ConditionTypeReady, metav1.ConditionTrue, "Ready",
		fmt.Sprintf("Agent group %s is ready", groupName))
	group.Status.ObservedGeneration = group.Generation
	now := metav1.Now()
	group.Status.LastSyncTime = &now
	group.Status.Message = ""

	if r.Recorder != nil {
		r.Recorder.Event(group, corev1.EventTypeNormal, "Synced",
			fmt.Sprintf("Agent group %s synced successfully", groupName))
	}

	if err := r.updateStatus(ctx, group); err != nil {
		return fmt.Errorf("failed to update agent group status: %w", err)
	}

	// Record metrics
	metrics.RecordReconciliation("WazuhAgentGroup", group.Namespace, "success", 0)

	log.Info("Agent group reconciliation completed", "name", group.Name, "group", groupName)
	return nil
}

// Delete handles cleanup when an agent group is deleted
func (r *AgentGroupReconciler) Delete(ctx context.Context, group *wazuhv1.WazuhAgentGroup) error {
	log := logf.FromContext(ctx)
	groupName := group.ResolveGroupName()

	// The "default" group cannot be deleted from Wazuh
	if groupName == "default" {
		log.Info("Skipping deletion of default agent group")
		if r.Recorder != nil {
			r.Recorder.Event(group, corev1.EventTypeNormal, "DeleteSkipped",
				"Default agent group cannot be deleted from Wazuh")
		}
		return nil
	}

	// Resolve cluster and build API client (best-effort)
	cluster := &wazuhv1.WazuhCluster{}
	clusterNamespace := group.Spec.ClusterRef.Namespace
	if clusterNamespace == "" {
		clusterNamespace = group.Namespace
	}
	clusterKey := types.NamespacedName{Name: group.Spec.ClusterRef.Name, Namespace: clusterNamespace}
	if err := r.Get(ctx, clusterKey, cluster); err != nil {
		log.Info("Referenced WazuhCluster not found during deletion, skipping API cleanup", "cluster", clusterKey)
		return nil
	}

	apiClient, err := r.buildAPIClient(ctx, cluster)
	if err != nil {
		log.Info("Wazuh API unavailable during deletion, skipping API cleanup", "error", err)
		return nil
	}

	if err := apiClient.DeleteGroup(ctx, groupName); err != nil {
		log.Error(err, "Failed to delete agent group from Wazuh API, proceeding with finalizer removal", "group", groupName)
	} else {
		log.Info("Agent group deleted from Wazuh API", "group", groupName)
	}

	if r.Recorder != nil {
		r.Recorder.Event(group, corev1.EventTypeNormal, "GroupDeleted",
			fmt.Sprintf("Agent group %s deleted", groupName))
	}

	return nil
}

// buildAPIClient creates a Wazuh API client for the given cluster
func (r *AgentGroupReconciler) buildAPIClient(ctx context.Context, cluster *wazuhv1.WazuhCluster) (*adapters.WazuhAPIAdapter, error) {
	masterServiceName := cluster.Name + "-manager-master"
	baseURL := fmt.Sprintf("https://%s:%d",
		dns.ServiceFQDN(masterServiceName, cluster.Namespace), constants.PortManagerAPI)

	username, password, err := r.getWazuhAPICredentials(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to get Wazuh API credentials: %w", err)
	}

	return adapters.NewWazuhAPIAdapter(adapters.WazuhAPIConfig{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		Insecure: true,
	}), nil
}

// getWazuhAPICredentials retrieves the Wazuh API credentials from the cluster
func (r *AgentGroupReconciler) getWazuhAPICredentials(ctx context.Context, cluster *wazuhv1.WazuhCluster) (string, string, error) {
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.APICredentials != nil {
		secretName := cluster.Spec.Manager.APICredentials.GetSecretName()
		if secretName != "" {
			secret := &corev1.Secret{}
			if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cluster.Namespace}, secret); err != nil {
				return "", "", fmt.Errorf("failed to get API credentials secret: %w", err)
			}
			usernameKey := cluster.Spec.Manager.APICredentials.UsernameKey
			if usernameKey == "" {
				usernameKey = "username"
			}
			passwordKey := cluster.Spec.Manager.APICredentials.PasswordKey
			if passwordKey == "" {
				passwordKey = "password"
			}
			return string(secret.Data[usernameKey]), string(secret.Data[passwordKey]), nil
		}
	}

	defaultSecretName := constants.APICredentialsName(cluster.Name)
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: defaultSecretName, Namespace: cluster.Namespace}, secret); err != nil {
		if errors.IsNotFound(err) {
			return constants.DefaultWazuhAPIUsername, "wazuh", nil
		}
		return "", "", fmt.Errorf("failed to get default API credentials secret: %w", err)
	}

	return string(secret.Data[constants.SecretKeyAPIUsername]), string(secret.Data[constants.SecretKeyAPIPassword]), nil
}

// setCondition sets a status condition on the agent group
func (r *AgentGroupReconciler) setCondition(group *wazuhv1.WazuhAgentGroup, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&group.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: group.Generation,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})
}

// updateStatus updates the agent group status
func (r *AgentGroupReconciler) updateStatus(ctx context.Context, group *wazuhv1.WazuhAgentGroup) error {
	return r.Status().Update(ctx, group)
}

// computeSpecHash computes a hash of the spec for drift detection
func computeSpecHash(group *wazuhv1.WazuhAgentGroup) string {
	h := sha256.New()
	h.Write([]byte(group.ResolveGroupName()))
	h.Write([]byte(group.Spec.AgentConf))
	h.Write([]byte(group.Spec.Description))
	// Include files in hash for drift detection
	if len(group.Spec.Files) > 0 {
		keys := make([]string, 0, len(group.Spec.Files))
		for k := range group.Spec.Files {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte(group.Spec.Files[k]))
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// agentGroupFilesConfigMapName returns the ConfigMap name for agent group files
func agentGroupFilesConfigMapName(crName string) string {
	return crName + "-agentgroup-files"
}

// reconcileFilesConfigMap creates/updates a ConfigMap for agent group files
func (r *AgentGroupReconciler) reconcileFilesConfigMap(ctx context.Context, group *wazuhv1.WazuhAgentGroup) error {
	log := logf.FromContext(ctx)
	cmName := agentGroupFilesConfigMapName(group.Name)
	cmKey := types.NamespacedName{Name: cmName, Namespace: group.Namespace}

	// If files is empty, delete ConfigMap if it exists
	if len(group.Spec.Files) == 0 {
		existing := &corev1.ConfigMap{}
		if err := r.Get(ctx, cmKey, existing); err != nil {
			if errors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("failed to check for existing files ConfigMap: %w", err)
		}
		log.Info("Deleting agent group files ConfigMap (files removed from spec)", "configMap", cmName)
		return r.Client.Delete(ctx, existing)
	}

	clusterName := group.Spec.ClusterRef.Name

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: group.Namespace,
			Labels: map[string]string{
				constants.LabelManagedBy:                   constants.OperatorName,
				"resources.wazuh.com/agentgroup":           group.Name,
				"resources.wazuh.com/cluster":              clusterName,
			},
		},
		Data: group.Spec.Files,
	}

	// Set owner reference for garbage collection
	if err := controllerutil.SetControllerReference(group, desired, r.Scheme); err != nil {
		return fmt.Errorf("failed to set owner reference on files ConfigMap: %w", err)
	}

	existing := &corev1.ConfigMap{}
	if err := r.Get(ctx, cmKey, existing); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Creating agent group files ConfigMap", "configMap", cmName)
			return r.Create(ctx, desired)
		}
		return fmt.Errorf("failed to get files ConfigMap: %w", err)
	}

	// Update if data changed
	existing.Data = desired.Data
	existing.Labels = desired.Labels
	return r.Update(ctx, existing)
}

// AgentGroupFileInfo holds information about agent group files for mounting to manager pods
type AgentGroupFileInfo struct {
	ConfigMapName string
	GroupName     string
	FileNames     []string
}

// GetAgentGroupFilesForCluster returns file ConfigMap references for all agent groups in a cluster
// This is used by the WazuhCluster reconciler to mount agent group file ConfigMaps to manager pods
func (r *AgentGroupReconciler) GetAgentGroupFilesForCluster(ctx context.Context, clusterName, namespace string) ([]AgentGroupFileInfo, string, error) {
	groupList := &wazuhv1.WazuhAgentGroupList{}
	if err := r.List(ctx, groupList, client.InNamespace(namespace)); err != nil {
		return nil, "", fmt.Errorf("failed to list agent groups: %w", err)
	}

	var fileInfos []AgentGroupFileInfo
	var allContents []string

	for _, group := range groupList.Items {
		// Match cluster reference
		clusterNamespace := group.Spec.ClusterRef.Namespace
		if clusterNamespace == "" {
			clusterNamespace = group.Namespace
		}
		if group.Spec.ClusterRef.Name != clusterName || clusterNamespace != namespace {
			continue
		}
		// Skip groups without files
		if len(group.Spec.Files) == 0 {
			continue
		}

		fileNames := make([]string, 0, len(group.Spec.Files))
		for k := range group.Spec.Files {
			fileNames = append(fileNames, k)
		}
		sort.Strings(fileNames)

		fileInfos = append(fileInfos, AgentGroupFileInfo{
			ConfigMapName: agentGroupFilesConfigMapName(group.Name),
			GroupName:     group.ResolveGroupName(),
			FileNames:     fileNames,
		})

		// Collect file contents for hash computation
		for _, fn := range fileNames {
			allContents = append(allContents, group.Spec.Files[fn])
		}
	}

	// Sort for consistent ordering
	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].GroupName < fileInfos[j].GroupName
	})
	sort.Strings(allContents)

	// Compute combined hash
	h := sha256.New()
	for _, content := range allContents {
		h.Write([]byte(content))
	}
	hash := hex.EncodeToString(h.Sum(nil))[:16]

	return fileInfos, hash, nil
}
