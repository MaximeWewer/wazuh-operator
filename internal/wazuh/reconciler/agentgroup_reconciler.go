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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/metrics"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/dns"
)

const (
	// AgentGroupFinalizer is the finalizer for WazuhAgentGroup resources
	AgentGroupFinalizer = "wazuhagentgroup.resources.wazuh.com/finalizer"

	// Condition types for agent groups
	ConditionTypeGroupSynced = "GroupSynced"

	// Labels used to identify ConfigMaps owned by a WazuhAgentGroup CR.
	// Cross-namespace owner references are forbidden by Kubernetes, so
	// cleanup is handled via finalizer + label selector instead.
	labelAgentGroupCROwnerName      = "resources.wazuh.com/agentgroup-cr"
	labelAgentGroupCROwnerNamespace = "resources.wazuh.com/agentgroup-cr-namespace"
	labelAgentGroupCluster          = "resources.wazuh.com/cluster"
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

// Reconcile reconciles the WazuhAgentGroup across all target clusters.
// Each ClusterRef is processed independently; failure on one cluster does
// not block others. The aggregate Status.Phase reflects the worst case.
func (r *AgentGroupReconciler) Reconcile(ctx context.Context, group *wazuhv1.WazuhAgentGroup) (err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "AgentGroupReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", group.Name),
			attribute.String("resource.namespace", group.Namespace),
			attribute.Int("resource.clusterRefs", len(group.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)
	groupName := group.ResolveGroupName()

	if group.Status.Phase == "" {
		group.Status.Phase = wazuhv1.AgentGroupPhasePending
	}

	// Index existing per-cluster statuses by (name,namespace) for in-place updates.
	existingByKey := make(map[string]wazuhv1.AgentGroupClusterStatus, len(group.Status.ClusterStatuses))
	for _, s := range group.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.AgentGroupClusterStatus, 0, len(group.Spec.ClusterRefs))
	anyAPIUnavailable := false
	anyFailed := false
	allReady := true

	for _, ref := range group.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		clusterErr := r.reconcileForCluster(ctx, group, groupName, ref, &st)
		if clusterErr != nil {
			if IsAPIUnavailable(clusterErr) {
				anyAPIUnavailable = true
			} else {
				anyFailed = true
			}
			log.Error(clusterErr, "Failed to reconcile agent group on cluster",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace)
		}
		if st.Phase != wazuhv1.AgentGroupPhaseReady {
			allReady = false
		}
		newStatuses = append(newStatuses, st)
	}

	sort.Slice(newStatuses, func(i, j int) bool {
		if newStatuses[i].Namespace != newStatuses[j].Namespace {
			return newStatuses[i].Namespace < newStatuses[j].Namespace
		}
		return newStatuses[i].Name < newStatuses[j].Name
	})
	group.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		group.Status.Phase = wazuhv1.AgentGroupPhaseFailed
		r.setCondition(group, ConditionTypeReady, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to sync")
		group.Status.Message = "One or more target clusters failed to sync"
	case anyAPIUnavailable:
		group.Status.Phase = wazuhv1.AgentGroupPhasePending
		r.setCondition(group, ConditionTypeReady, metav1.ConditionFalse, "APIUnavailable",
			"One or more Wazuh APIs are unavailable")
		group.Status.Message = "Waiting for Wazuh API availability on one or more clusters"
	case allReady:
		group.Status.Phase = wazuhv1.AgentGroupPhaseReady
		r.setCondition(group, ConditionTypeGroupSynced, metav1.ConditionTrue, "Synced",
			fmt.Sprintf("Agent group %s synced on all target clusters", groupName))
		r.setCondition(group, ConditionTypeReady, metav1.ConditionTrue, "Ready",
			fmt.Sprintf("Agent group %s is ready on all target clusters", groupName))
		group.Status.Message = ""
	default:
		group.Status.Phase = wazuhv1.AgentGroupPhasePending
	}

	group.Status.ObservedGeneration = group.Generation

	if err := r.updateStatus(ctx, group); err != nil {
		return fmt.Errorf("failed to update agent group status: %w", err)
	}

	metrics.RecordReconciliation("WazuhAgentGroup", group.Namespace, "success", 0)

	if anyAPIUnavailable && !anyFailed {
		// Surface API-unavailability so the controller requeues with backoff
		return &WazuhAPIUnavailableError{Err: fmt.Errorf("one or more wazuh APIs unavailable")}
	}
	if anyFailed {
		return fmt.Errorf("one or more target clusters failed to sync")
	}
	log.Info("Agent group reconciliation completed", "name", group.Name, "group", groupName)
	return nil
}

// reconcileForCluster reconciles the agent group on a single target cluster.
// Per-cluster status is mutated in place. Returns an error so the caller can
// classify it (API-unavailable vs. failure) for aggregate status.
func (r *AgentGroupReconciler) reconcileForCluster(
	ctx context.Context,
	group *wazuhv1.WazuhAgentGroup,
	groupName string,
	ref wazuhv1.WazuhClusterRef,
	st *wazuhv1.AgentGroupClusterStatus,
) error {
	log := logf.FromContext(ctx).WithValues("cluster", ref.Name, "clusterNamespace", ref.Namespace)

	cluster := &wazuhv1.WazuhCluster{}
	clusterKeyNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterKeyNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.AgentGroupPhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterKeyNN)
			if r.Recorder != nil {
				r.Recorder.Event(group, corev1.EventTypeWarning, "ClusterNotFound", st.Message)
			}
			return nil
		}
		st.Phase = wazuhv1.AgentGroupPhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	apiClient, err := r.buildAPIClient(ctx, cluster)
	if err != nil {
		st.Phase = wazuhv1.AgentGroupPhasePending
		st.Message = fmt.Sprintf("Wazuh API unavailable: %v", err)
		return &WazuhAPIUnavailableError{Err: err}
	}

	if !apiClient.IsHealthy(ctx) {
		st.Phase = wazuhv1.AgentGroupPhasePending
		st.Message = "Wazuh API is not healthy"
		return &WazuhAPIUnavailableError{Err: fmt.Errorf("wazuh API health check failed")}
	}

	groupInfo, err := apiClient.GetGroup(ctx, groupName)
	if err != nil {
		st.Phase = wazuhv1.AgentGroupPhasePending
		st.Message = fmt.Sprintf("Failed to query group: %v", err)
		return &WazuhAPIUnavailableError{Err: err}
	}

	if groupInfo == nil {
		log.Info("Creating agent group", "group", groupName)
		if err := apiClient.CreateGroup(ctx, groupName); err != nil {
			st.Phase = wazuhv1.AgentGroupPhaseFailed
			st.Message = fmt.Sprintf("Failed to create group: %v", err)
			if r.Recorder != nil {
				r.Recorder.Event(group, corev1.EventTypeWarning, "CreateFailed", err.Error())
			}
			return err
		}
		if r.Recorder != nil {
			r.Recorder.Event(group, corev1.EventTypeNormal, "GroupCreated",
				fmt.Sprintf("Agent group %s created on %s/%s", groupName, ref.Namespace, ref.Name))
		}
	}

	if group.Spec.AgentConf != "" {
		specHash := computeSpecHash(group)
		if specHash != st.LastAppliedHash {
			log.Info("Updating agent group configuration", "group", groupName)
			if err := apiClient.UpdateGroupConfiguration(ctx, groupName, group.Spec.AgentConf); err != nil {
				st.Phase = wazuhv1.AgentGroupPhaseFailed
				st.Message = fmt.Sprintf("Failed to update configuration: %v", err)
				if r.Recorder != nil {
					r.Recorder.Event(group, corev1.EventTypeWarning, "ConfigUpdateFailed", err.Error())
				}
				return err
			}
			st.LastAppliedHash = specHash
			if r.Recorder != nil {
				r.Recorder.Event(group, corev1.EventTypeNormal, "ConfigUpdated",
					fmt.Sprintf("Agent group %s configuration updated on %s/%s", groupName, ref.Namespace, ref.Name))
			}
		}
	}

	if err := r.reconcileFilesConfigMap(ctx, group, ref); err != nil {
		st.Phase = wazuhv1.AgentGroupPhaseFailed
		st.Message = fmt.Sprintf("Failed to reconcile files ConfigMap: %v", err)
		return err
	}

	groupInfo, err = apiClient.GetGroup(ctx, groupName)
	if err == nil && groupInfo != nil {
		st.AgentCount = groupInfo.Count
	}

	wasReady := st.Phase == wazuhv1.AgentGroupPhaseReady
	st.Phase = wazuhv1.AgentGroupPhaseReady
	st.Message = ""
	if !wasReady {
		now := metav1.Now()
		st.LastSyncTime = &now
		if r.Recorder != nil {
			r.Recorder.Event(group, corev1.EventTypeNormal, "Synced",
				fmt.Sprintf("Agent group %s synced on %s/%s", groupName, ref.Namespace, ref.Name))
		}
	}
	return nil
}

// Delete handles cleanup when an agent group is deleted.
// Iterates every target cluster: deletes the group via API (best-effort) and
// removes the file ConfigMap in the cluster's namespace.
func (r *AgentGroupReconciler) Delete(ctx context.Context, group *wazuhv1.WazuhAgentGroup) error {
	log := logf.FromContext(ctx)
	groupName := group.ResolveGroupName()

	var cleanupErrs []string
	for _, ref := range group.Spec.ClusterRefs {
		// Delete the group via the Manager API. Failures are propagated (see below) so the
		// finalizer is kept and the delete is retried, instead of silently leaking the group.
		if groupName != "default" {
			cluster := &wazuhv1.WazuhCluster{}
			clusterKeyNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
			if err := r.Get(ctx, clusterKeyNN, cluster); err != nil {
				if errors.IsNotFound(err) {
					// The cluster itself is gone, so the group went with it: nothing to delete.
					log.Info("Cluster not found during delete, skipping API cleanup", "cluster", clusterKeyNN)
				} else {
					cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s: get cluster: %v", clusterKeyNN, err))
				}
			} else if apiClient, err := r.buildAPIClient(ctx, cluster); err != nil {
				// API temporarily unavailable: retry rather than leak the group.
				cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s: build API client: %v", clusterKeyNN, err))
			} else if err := apiClient.DeleteGroup(ctx, groupName); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Sprintf("%s: delete group %q: %v", clusterKeyNN, groupName, err))
			} else {
				log.Info("Agent group deleted from Wazuh API",
					"cluster", clusterKeyNN, "group", groupName)
			}
		} else {
			log.Info("Skipping deletion of default agent group from Wazuh API")
		}

		// Delete file ConfigMap in cluster's namespace (cross-NS, no ownerRef).
		cmName := agentGroupFilesConfigMapName(group.Namespace, group.Name)
		cm := &corev1.ConfigMap{}
		err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, cm)
		if err == nil {
			if err := r.Client.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete agent group files ConfigMap",
					"configMap", cmName, "namespace", ref.Namespace)
			}
		} else if !errors.IsNotFound(err) {
			log.Error(err, "Failed to lookup agent group files ConfigMap",
				"configMap", cmName, "namespace", ref.Namespace)
		}
	}

	if len(cleanupErrs) > 0 {
		// Keep the finalizer and retry: the group must actually be removed from Wazuh, not
		// silently leaked when the API is unavailable or the delete fails.
		return fmt.Errorf("agent group %q cleanup incomplete, will retry: %s", groupName, strings.Join(cleanupErrs, "; "))
	}

	if r.Recorder != nil {
		r.Recorder.Event(group, corev1.EventTypeNormal, "GroupDeleted",
			fmt.Sprintf("Agent group %s deleted on all target clusters", groupName))
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

// setCondition sets a status condition on the agent group.
// meta.SetStatusCondition preserves LastTransitionTime when status is unchanged.
func (r *AgentGroupReconciler) setCondition(group *wazuhv1.WazuhAgentGroup, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&group.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: group.Generation,
		Reason:             reason,
		Message:            message,
	})
}

// updateStatus updates the agent group status with retry on conflict.
// Skips the write when the status is unchanged.
func (r *AgentGroupReconciler) updateStatus(ctx context.Context, group *wazuhv1.WazuhAgentGroup) error {
	desiredStatus := group.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhAgentGroup{}
		if err := r.Get(ctx, types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		group.Status = latest.Status
		return nil
	})
}

// computeSpecHash computes a hash of the spec for drift detection
func computeSpecHash(group *wazuhv1.WazuhAgentGroup) string {
	h := sha256.New()
	h.Write([]byte(group.ResolveGroupName()))
	h.Write([]byte(group.Spec.AgentConf))
	h.Write([]byte(group.Spec.Description))
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

// agentGroupFilesConfigMapName returns the ConfigMap name for an agent group's files.
// The CR namespace is included so two groups with the same name in different
// namespaces don't collide when projecting onto the same target cluster.
func agentGroupFilesConfigMapName(crNamespace, crName string) string {
	return fmt.Sprintf("%s-%s-agentgroup-files", crNamespace, crName)
}

func clusterKey(name, namespace string) string {
	return namespace + "/" + name
}

// reconcileFilesConfigMap creates/updates the file ConfigMap for one target cluster.
// The ConfigMap lives in the target cluster's namespace; cleanup is finalizer-driven
// because cross-namespace owner references are forbidden.
func (r *AgentGroupReconciler) reconcileFilesConfigMap(
	ctx context.Context,
	group *wazuhv1.WazuhAgentGroup,
	ref wazuhv1.WazuhClusterRef,
) error {
	log := logf.FromContext(ctx)
	cmName := agentGroupFilesConfigMapName(group.Namespace, group.Name)
	cmKey := types.NamespacedName{Name: cmName, Namespace: ref.Namespace}

	if len(group.Spec.Files) == 0 {
		existing := &corev1.ConfigMap{}
		if err := r.Get(ctx, cmKey, existing); err != nil {
			if errors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("failed to check for existing files ConfigMap: %w", err)
		}
		log.Info("Deleting agent group files ConfigMap (files removed from spec)",
			"configMap", cmName, "namespace", ref.Namespace)
		return r.Client.Delete(ctx, existing)
	}

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: ref.Namespace,
			Labels: map[string]string{
				constants.LabelManagedBy:        constants.OperatorName,
				labelAgentGroupCROwnerName:      group.Name,
				labelAgentGroupCROwnerNamespace: group.Namespace,
				labelAgentGroupCluster:          ref.Name,
			},
		},
		Data: group.Spec.Files,
	}

	existing := &corev1.ConfigMap{}
	if err := r.Get(ctx, cmKey, existing); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Creating agent group files ConfigMap",
				"configMap", cmName, "namespace", ref.Namespace)
			return r.Create(ctx, desired)
		}
		return fmt.Errorf("failed to get files ConfigMap: %w", err)
	}

	if !mapsEqual(existing.Data, desired.Data) || !mapsEqual(existing.Labels, desired.Labels) {
		log.Info("Updating agent group files ConfigMap",
			"configMap", cmName, "namespace", ref.Namespace)
		existing.Data = desired.Data
		existing.Labels = desired.Labels
		return r.Update(ctx, existing)
	}
	return nil
}

// mapsEqual returns true if both maps have the same keys and values.
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func mapsEqualBytes(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		bv, ok := b[k]
		if !ok || !bytes.Equal(v, bv) {
			return false
		}
	}
	return true
}

// preserveServiceDefaults copies all server-assigned and server-defaulted
// fields from the existing Service into the desired Service so that
// apiequality.Semantic.DeepEqual does not report false diffs.
func preserveServiceDefaults(desired, existing *corev1.Service) {
	desired.Spec.ClusterIP = existing.Spec.ClusterIP
	desired.Spec.ClusterIPs = existing.Spec.ClusterIPs

	if desired.Spec.IPFamilyPolicy == nil {
		desired.Spec.IPFamilyPolicy = existing.Spec.IPFamilyPolicy
	}
	if desired.Spec.IPFamilies == nil {
		desired.Spec.IPFamilies = existing.Spec.IPFamilies
	}
	if desired.Spec.InternalTrafficPolicy == nil {
		desired.Spec.InternalTrafficPolicy = existing.Spec.InternalTrafficPolicy
	}
	if desired.Spec.ExternalTrafficPolicy == "" {
		desired.Spec.ExternalTrafficPolicy = existing.Spec.ExternalTrafficPolicy
	}
	if desired.Spec.SessionAffinity == "" {
		desired.Spec.SessionAffinity = existing.Spec.SessionAffinity
	}
	if desired.Spec.HealthCheckNodePort == 0 {
		desired.Spec.HealthCheckNodePort = existing.Spec.HealthCheckNodePort
	}
	if desired.Spec.AllocateLoadBalancerNodePorts == nil {
		desired.Spec.AllocateLoadBalancerNodePorts = existing.Spec.AllocateLoadBalancerNodePorts
	}

	for i := range desired.Spec.Ports {
		if desired.Spec.Ports[i].NodePort == 0 {
			for _, ep := range existing.Spec.Ports {
				if ep.Port == desired.Spec.Ports[i].Port && ep.Protocol == desired.Spec.Ports[i].Protocol {
					desired.Spec.Ports[i].NodePort = ep.NodePort
					break
				}
			}
		}
	}
}

// AgentGroupFileInfo holds information about agent group files for mounting to manager pods
type AgentGroupFileInfo struct {
	ConfigMapName string
	GroupName     string
	FileNames     []string
}

// GetAgentGroupFilesForCluster returns file ConfigMap references for all agent groups
// targeting a given cluster. Lists across all namespaces (cross-NS support).
func (r *AgentGroupReconciler) GetAgentGroupFilesForCluster(ctx context.Context, clusterName, namespace string) ([]AgentGroupFileInfo, string, error) {
	groupList := &wazuhv1.WazuhAgentGroupList{}
	if err := r.List(ctx, groupList); err != nil {
		return nil, "", fmt.Errorf("failed to list agent groups: %w", err)
	}

	var fileInfos []AgentGroupFileInfo
	var allContents []string

	for _, group := range groupList.Items {
		// Match if any clusterRef points to this cluster
		matched := false
		for _, ref := range group.Spec.ClusterRefs {
			if ref.Name == clusterName && ref.Namespace == namespace {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if len(group.Spec.Files) == 0 {
			continue
		}

		fileNames := make([]string, 0, len(group.Spec.Files))
		for k := range group.Spec.Files {
			fileNames = append(fileNames, k)
		}
		sort.Strings(fileNames)

		fileInfos = append(fileInfos, AgentGroupFileInfo{
			ConfigMapName: agentGroupFilesConfigMapName(group.Namespace, group.Name),
			GroupName:     group.ResolveGroupName(),
			FileNames:     fileNames,
		})

		for _, fn := range fileNames {
			allContents = append(allContents, group.Spec.Files[fn])
		}
	}

	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].GroupName < fileInfos[j].GroupName
	})
	sort.Strings(allContents)

	h := sha256.New()
	for _, content := range allContents {
		h.Write([]byte(content))
	}
	hash := hex.EncodeToString(h.Sum(nil))[:16]

	return fileInfos, hash, nil
}
