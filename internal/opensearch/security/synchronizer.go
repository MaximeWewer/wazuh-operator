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

package security

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1alpha1 "github.com/MaximeWewer/wazuh-operator/api/v1alpha1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/opensearch/api"
)

// SyncResult holds the results of a security synchronization operation
type SyncResult struct {
	UsersCreated        int
	UsersUpdated        int
	UsersFailed         int
	RolesCreated        int
	RolesUpdated        int
	RolesFailed         int
	MappingsCreated     int
	MappingsUpdated     int
	MappingsFailed      int
	TenantsCreated      int
	TenantsUpdated      int
	TenantsFailed       int
	ActionGroupsCreated int
	ActionGroupsUpdated int
	ActionGroupsFailed  int
	Errors              []error
}

// HasErrors returns true if any errors occurred during sync
func (r *SyncResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// TotalSynced returns the total number of successfully synced resources
func (r *SyncResult) TotalSynced() int {
	return r.UsersCreated + r.UsersUpdated +
		r.RolesCreated + r.RolesUpdated +
		r.MappingsCreated + r.MappingsUpdated +
		r.TenantsCreated + r.TenantsUpdated +
		r.ActionGroupsCreated + r.ActionGroupsUpdated
}

// SecurityConfigSynchronizer synchronizes security CRDs to OpenSearch
type SecurityConfigSynchronizer struct {
	k8sClient     client.Client
	clientFactory *OpenSearchClientFactory
	recorder      record.EventRecorder
}

// NewSecurityConfigSynchronizer creates a new SecurityConfigSynchronizer
func NewSecurityConfigSynchronizer(k8sClient client.Client, factory *OpenSearchClientFactory, recorder record.EventRecorder) *SecurityConfigSynchronizer {
	return &SecurityConfigSynchronizer{
		k8sClient:     k8sClient,
		clientFactory: factory,
		recorder:      recorder,
	}
}

// SyncAllForCluster syncs all security CRDs for a cluster
func (s *SecurityConfigSynchronizer) SyncAllForCluster(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster) (*SyncResult, error) {
	logger := log.FromContext(ctx).WithValues("cluster", cluster.Name)
	result := &SyncResult{}

	// Get OpenSearch client
	osClient, err := s.clientFactory.GetClientForCluster(ctx, cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenSearch client: %w", err)
	}

	// Check if security is initialized
	checker := NewSecurityInitializationChecker(osClient)
	initialized, err := checker.CheckInitialized(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check security initialization: %w", err)
	}
	if !initialized {
		return nil, fmt.Errorf("security not initialized, cannot sync")
	}

	logger.Info("Starting security CRD synchronization")

	// Sync users
	if err := s.SyncUsers(ctx, cluster, osClient, result); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("users sync error: %w", err))
	}

	// Sync roles
	if err := s.SyncRoles(ctx, cluster, osClient, result); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("roles sync error: %w", err))
	}

	// Sync role mappings
	if err := s.SyncRoleMappings(ctx, cluster, osClient, result); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("role mappings sync error: %w", err))
	}

	// Sync tenants
	if err := s.SyncTenants(ctx, cluster, osClient, result); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("tenants sync error: %w", err))
	}

	// Sync action groups
	if err := s.SyncActionGroups(ctx, cluster, osClient, result); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("action groups sync error: %w", err))
	}

	logger.Info("Security CRD synchronization completed",
		"totalSynced", result.TotalSynced(),
		"errors", len(result.Errors))

	return result, nil
}

// SyncUsers syncs all OpenSearchUser CRDs for a cluster
func (s *SecurityConfigSynchronizer) SyncUsers(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, osClient *api.Client, result *SyncResult) error {
	logger := log.FromContext(ctx).WithValues("cluster", cluster.Name, "resourceType", "user")

	// List all users for this cluster
	var userList wazuhv1alpha1.OpenSearchUserList
	if err := s.k8sClient.List(ctx, &userList, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("failed to list OpenSearchUser CRDs: %w", err)
	}

	for _, user := range userList.Items {
		if user.Spec.ClusterRef.Name != cluster.Name {
			continue
		}

		logger.V(1).Info("Syncing user", "user", user.Name)

		// Build the user request
		secUser, err := s.buildSecurityUser(ctx, &user)
		if err != nil {
			logger.Error(err, "Failed to build security user", "user", user.Name)
			result.UsersFailed++
			result.Errors = append(result.Errors, fmt.Errorf("user %s: %w", user.Name, err))
			s.updateUserStatus(ctx, &user, "Failed", err.Error())
			continue
		}

		// Create or update the user in OpenSearch
		if err := s.createOrUpdateUser(ctx, osClient, user.Name, secUser); err != nil {
			logger.Error(err, "Failed to sync user", "user", user.Name)
			result.UsersFailed++
			result.Errors = append(result.Errors, fmt.Errorf("user %s: %w", user.Name, err))
			s.updateUserStatus(ctx, &user, "Failed", err.Error())
			continue
		}

		// Update status to Ready
		s.updateUserStatus(ctx, &user, "Ready", "User synced successfully")
		result.UsersUpdated++ // We use updated since create/update is idempotent
	}

	return nil
}

// buildSecurityUser builds an adapters.SecurityUser from an OpenSearchUser CRD
func (s *SecurityConfigSynchronizer) buildSecurityUser(ctx context.Context, user *wazuhv1alpha1.OpenSearchUser) (*adapters.SecurityUser, error) {
	secUser := &adapters.SecurityUser{
		BackendRoles:            user.Spec.BackendRoles,
		Attributes:              user.Spec.Attributes,
		Description:             user.Spec.Description,
		OpendistroSecurityRoles: user.Spec.OpenSearchRoles,
	}

	// Get password or hash
	if user.Spec.Hash != "" {
		secUser.Hash = user.Spec.Hash
	} else if user.Spec.PasswordSecret != nil {
		// Get password from secret and OpenSearch will hash it
		credManager := NewCredentialManager(s.k8sClient, s.recorder)
		password, err := credManager.GetPasswordFromCRD(ctx, user)
		if err != nil {
			return nil, fmt.Errorf("failed to get password: %w", err)
		}
		secUser.Password = password
	} else {
		return nil, fmt.Errorf("user %s has no password or hash configured", user.Name)
	}

	return secUser, nil
}

// createOrUpdateUser creates or updates a user in OpenSearch
func (s *SecurityConfigSynchronizer) createOrUpdateUser(ctx context.Context, osClient *api.Client, username string, user *adapters.SecurityUser) error {
	// The OpenSearch API is idempotent - PUT will create or update
	resp, err := osClient.Put(ctx, "/_plugins/_security/api/internalusers/"+username, user)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("failed to create/update user: HTTP %d", resp.StatusCode)
	}

	return nil
}

// updateUserStatus updates the status of an OpenSearchUser CRD
func (s *SecurityConfigSynchronizer) updateUserStatus(ctx context.Context, user *wazuhv1alpha1.OpenSearchUser, phase, message string) {
	user.Status.Phase = phase
	user.Status.Message = message
	user.Status.LastSyncTime = &metav1.Time{Time: time.Now()}
	user.Status.ObservedGeneration = user.Generation

	if err := s.k8sClient.Status().Update(ctx, user); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update user status", "user", user.Name)
	}
}

// SyncRoles syncs all OpenSearchRole CRDs for a cluster
func (s *SecurityConfigSynchronizer) SyncRoles(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, osClient *api.Client, result *SyncResult) error {
	logger := log.FromContext(ctx).WithValues("cluster", cluster.Name, "resourceType", "role")

	// List all roles for this cluster
	var roleList wazuhv1alpha1.OpenSearchRoleList
	if err := s.k8sClient.List(ctx, &roleList, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("failed to list OpenSearchRole CRDs: %w", err)
	}

	for _, role := range roleList.Items {
		if role.Spec.ClusterRef.Name != cluster.Name {
			continue
		}

		logger.V(1).Info("Syncing role", "role", role.Name)

		// Build the role request
		secRole := s.buildSecurityRole(&role)

		// Create or update the role in OpenSearch
		resp, err := osClient.Put(ctx, "/_plugins/_security/api/roles/"+role.Name, secRole)
		if err != nil {
			logger.Error(err, "Failed to sync role", "role", role.Name)
			result.RolesFailed++
			result.Errors = append(result.Errors, fmt.Errorf("role %s: %w", role.Name, err))
			s.updateRoleStatus(ctx, &role, "Failed", err.Error())
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			result.RolesFailed++
			s.updateRoleStatus(ctx, &role, "Failed", fmt.Sprintf("HTTP %d", resp.StatusCode))
			continue
		}

		s.updateRoleStatus(ctx, &role, "Ready", "Role synced successfully")
		result.RolesUpdated++
	}

	return nil
}

// buildSecurityRole builds an adapters.SecurityRole from an OpenSearchRole CRD
func (s *SecurityConfigSynchronizer) buildSecurityRole(role *wazuhv1alpha1.OpenSearchRole) *adapters.SecurityRole {
	secRole := &adapters.SecurityRole{
		Description:        role.Spec.Description,
		ClusterPermissions: role.Spec.ClusterPermissions,
	}

	// Convert index permissions
	for _, ip := range role.Spec.IndexPermissions {
		secRole.IndexPermissions = append(secRole.IndexPermissions, adapters.IndexPermission{
			IndexPatterns:  ip.IndexPatterns,
			AllowedActions: ip.AllowedActions,
		})
	}

	// Convert tenant permissions
	for _, tp := range role.Spec.TenantPermissions {
		secRole.TenantPermissions = append(secRole.TenantPermissions, adapters.TenantPermission{
			TenantPatterns: tp.TenantPatterns,
			AllowedActions: tp.AllowedActions,
		})
	}

	return secRole
}

// updateRoleStatus updates the status of an OpenSearchRole CRD
func (s *SecurityConfigSynchronizer) updateRoleStatus(ctx context.Context, role *wazuhv1alpha1.OpenSearchRole, phase, message string) {
	role.Status.Phase = phase
	role.Status.Message = message
	role.Status.LastSyncTime = &metav1.Time{Time: time.Now()}
	role.Status.ObservedGeneration = role.Generation

	if err := s.k8sClient.Status().Update(ctx, role); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update role status", "role", role.Name)
	}
}

// SyncRoleMappings syncs all OpenSearchRoleMapping CRDs for a cluster
func (s *SecurityConfigSynchronizer) SyncRoleMappings(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, osClient *api.Client, result *SyncResult) error {
	logger := log.FromContext(ctx).WithValues("cluster", cluster.Name, "resourceType", "rolemapping")

	// List all role mappings for this cluster
	var mappingList wazuhv1alpha1.OpenSearchRoleMappingList
	if err := s.k8sClient.List(ctx, &mappingList, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("failed to list OpenSearchRoleMapping CRDs: %w", err)
	}

	for _, mapping := range mappingList.Items {
		if mapping.Spec.ClusterRef.Name != cluster.Name {
			continue
		}

		logger.V(1).Info("Syncing role mapping", "mapping", mapping.Name)

		// Build the mapping request
		reqBody := map[string]interface{}{
			"backend_roles": mapping.Spec.BackendRoles,
			"hosts":         mapping.Spec.Hosts,
			"users":         mapping.Spec.Users,
		}

		// Create or update the role mapping in OpenSearch
		resp, err := osClient.Put(ctx, "/_plugins/_security/api/rolesmapping/"+mapping.Name, reqBody)
		if err != nil {
			logger.Error(err, "Failed to sync role mapping", "mapping", mapping.Name)
			result.MappingsFailed++
			result.Errors = append(result.Errors, fmt.Errorf("mapping %s: %w", mapping.Name, err))
			s.updateRoleMappingStatus(ctx, &mapping, "Failed", err.Error())
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			result.MappingsFailed++
			s.updateRoleMappingStatus(ctx, &mapping, "Failed", fmt.Sprintf("HTTP %d", resp.StatusCode))
			continue
		}

		s.updateRoleMappingStatus(ctx, &mapping, "Ready", "Role mapping synced successfully")
		result.MappingsUpdated++
	}

	return nil
}

// updateRoleMappingStatus updates the status of an OpenSearchRoleMapping CRD
func (s *SecurityConfigSynchronizer) updateRoleMappingStatus(ctx context.Context, mapping *wazuhv1alpha1.OpenSearchRoleMapping, phase, message string) {
	mapping.Status.Phase = phase
	mapping.Status.Message = message
	mapping.Status.LastSyncTime = &metav1.Time{Time: time.Now()}
	mapping.Status.ObservedGeneration = mapping.Generation

	if err := s.k8sClient.Status().Update(ctx, mapping); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update role mapping status", "mapping", mapping.Name)
	}
}

// SyncTenants syncs all OpenSearchTenant CRDs for a cluster
func (s *SecurityConfigSynchronizer) SyncTenants(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, osClient *api.Client, result *SyncResult) error {
	logger := log.FromContext(ctx).WithValues("cluster", cluster.Name, "resourceType", "tenant")

	// List all tenants for this cluster
	var tenantList wazuhv1alpha1.OpenSearchTenantList
	if err := s.k8sClient.List(ctx, &tenantList, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("failed to list OpenSearchTenant CRDs: %w", err)
	}

	for _, tenant := range tenantList.Items {
		if tenant.Spec.ClusterRef.Name != cluster.Name {
			continue
		}

		logger.V(1).Info("Syncing tenant", "tenant", tenant.Name)

		// Build the tenant request
		reqBody := map[string]interface{}{
			"description": tenant.Spec.Description,
		}

		// Create or update the tenant in OpenSearch
		resp, err := osClient.Put(ctx, "/_plugins/_security/api/tenants/"+tenant.Name, reqBody)
		if err != nil {
			logger.Error(err, "Failed to sync tenant", "tenant", tenant.Name)
			result.TenantsFailed++
			result.Errors = append(result.Errors, fmt.Errorf("tenant %s: %w", tenant.Name, err))
			s.updateTenantStatus(ctx, &tenant, "Failed", err.Error())
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			result.TenantsFailed++
			s.updateTenantStatus(ctx, &tenant, "Failed", fmt.Sprintf("HTTP %d", resp.StatusCode))
			continue
		}

		s.updateTenantStatus(ctx, &tenant, "Ready", "Tenant synced successfully")
		result.TenantsUpdated++
	}

	return nil
}

// updateTenantStatus updates the status of an OpenSearchTenant CRD
func (s *SecurityConfigSynchronizer) updateTenantStatus(ctx context.Context, tenant *wazuhv1alpha1.OpenSearchTenant, phase, message string) {
	tenant.Status.Phase = phase
	tenant.Status.Message = message
	tenant.Status.LastSyncTime = &metav1.Time{Time: time.Now()}
	tenant.Status.ObservedGeneration = tenant.Generation

	if err := s.k8sClient.Status().Update(ctx, tenant); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update tenant status", "tenant", tenant.Name)
	}
}

// SyncActionGroups syncs all OpenSearchActionGroup CRDs for a cluster
func (s *SecurityConfigSynchronizer) SyncActionGroups(ctx context.Context, cluster *wazuhv1alpha1.WazuhCluster, osClient *api.Client, result *SyncResult) error {
	logger := log.FromContext(ctx).WithValues("cluster", cluster.Name, "resourceType", "actiongroup")

	// List all action groups for this cluster
	var actionGroupList wazuhv1alpha1.OpenSearchActionGroupList
	if err := s.k8sClient.List(ctx, &actionGroupList, client.InNamespace(cluster.Namespace)); err != nil {
		return fmt.Errorf("failed to list OpenSearchActionGroup CRDs: %w", err)
	}

	for _, ag := range actionGroupList.Items {
		if ag.Spec.ClusterRef.Name != cluster.Name {
			continue
		}

		logger.V(1).Info("Syncing action group", "actionGroup", ag.Name)

		// Build the action group request
		reqBody := map[string]interface{}{
			"allowed_actions": ag.Spec.AllowedActions,
		}

		// Create or update the action group in OpenSearch
		resp, err := osClient.Put(ctx, "/_plugins/_security/api/actiongroups/"+ag.Name, reqBody)
		if err != nil {
			logger.Error(err, "Failed to sync action group", "actionGroup", ag.Name)
			result.ActionGroupsFailed++
			result.Errors = append(result.Errors, fmt.Errorf("actiongroup %s: %w", ag.Name, err))
			s.updateActionGroupStatus(ctx, &ag, "Failed", err.Error())
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			result.ActionGroupsFailed++
			s.updateActionGroupStatus(ctx, &ag, "Failed", fmt.Sprintf("HTTP %d", resp.StatusCode))
			continue
		}

		s.updateActionGroupStatus(ctx, &ag, "Ready", "Action group synced successfully")
		result.ActionGroupsUpdated++
	}

	return nil
}

// updateActionGroupStatus updates the status of an OpenSearchActionGroup CRD
func (s *SecurityConfigSynchronizer) updateActionGroupStatus(ctx context.Context, ag *wazuhv1alpha1.OpenSearchActionGroup, phase, message string) {
	ag.Status.Phase = phase
	ag.Status.Message = message
	ag.Status.LastSyncTime = &metav1.Time{Time: time.Now()}
	ag.Status.ObservedGeneration = ag.Generation

	if err := s.k8sClient.Status().Update(ctx, ag); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update action group status", "actionGroup", ag.Name)
	}
}
