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

package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ReservedRBACIDThreshold is the exclusive upper bound for reserved Wazuh API
// RBAC objects. Objects with an ID below this value are shipped by Wazuh and
// are immutable: the operator never updates or deletes them.
const ReservedRBACIDThreshold = 100

// rbacItem is a minimal RBAC object as returned in affected_items. Roles,
// policies and rules use "name"; users use "username". Both carry "id".
type rbacItem struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

// rbacResponse is the common Wazuh API envelope for /security operations.
type rbacResponse struct {
	Data struct {
		AffectedItems    []rbacItem `json:"affected_items"`
		TotalAffected    int        `json:"total_affected_items"`
		TotalFailedItems int        `json:"total_failed_items"`
	} `json:"data"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

// createRBAC POSTs body to a /security create path and returns the new object
// ID. existed is true when the object already exists (name/username conflict),
// in which case id is 0 and the caller should resolve the ID by name.
func (a *WazuhAPIAdapter) createRBAC(ctx context.Context, path string, payload any) (id int, existed bool, err error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, false, fmt.Errorf("marshal %s payload: %w", path, err)
	}
	resp, err := a.doRequest(ctx, "POST", path, bytes.NewReader(body))
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var r rbacResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return 0, false, fmt.Errorf("decode %s response (status %d): %w (body: %s)", path, resp.StatusCode, err, string(raw))
	}
	if len(r.Data.AffectedItems) > 0 {
		return r.Data.AffectedItems[0].ID, false, nil
	}
	// A name/username collision is reported as a failed item (HTTP 400). The
	// caller resolves the existing ID via Get*ByName for idempotency.
	if r.Data.TotalFailedItems > 0 || resp.StatusCode == http.StatusBadRequest {
		return 0, true, nil
	}
	return 0, false, fmt.Errorf("create %s failed (status %d): %s", path, resp.StatusCode, string(raw))
}

// getRBACIDByField lists a /security collection and returns the ID of the item
// whose field ("name" or "username") equals value, or 0 when absent.
func (a *WazuhAPIAdapter) getRBACIDByField(ctx context.Context, path, field, value string) (int, error) {
	resp, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("list %s failed (status %d): %s", path, resp.StatusCode, string(raw))
	}
	var r rbacResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, fmt.Errorf("decode %s list: %w", path, err)
	}
	for _, it := range r.Data.AffectedItems {
		switch field {
		case "username":
			if it.Username == value {
				return it.ID, nil
			}
		default:
			if it.Name == value {
				return it.ID, nil
			}
		}
	}
	return 0, nil
}

// putRBAC sends an update PUT to /security/<kind>/{id} with the given payload.
func (a *WazuhAPIAdapter) putRBAC(ctx context.Context, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s payload: %w", path, err)
	}
	resp, err := a.doRequest(ctx, "PUT", path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update %s failed (status %d): %s", path, resp.StatusCode, string(raw))
	}
	return nil
}

// linkRBAC performs an idempotent link/unlink against a /security relationship
// endpoint. Re-linking an existing relationship (or unlinking an absent one) is
// treated as success.
func (a *WazuhAPIAdapter) linkRBAC(ctx context.Context, method, path, param string, ids []int) error {
	if len(ids) == 0 {
		return nil
	}
	q := fmt.Sprintf("%s?%s=%s", path, param, joinInts(ids))
	resp, err := a.doRequest(ctx, method, q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	raw, _ := io.ReadAll(resp.Body)
	// Tolerate "already linked" / "already unlinked" so reconciliation is idempotent.
	if strings.Contains(strings.ToLower(string(raw)), "already") {
		return nil
	}
	return fmt.Errorf("%s %s failed (status %d): %s", method, q, resp.StatusCode, string(raw))
}

// deleteRBAC deletes a set of objects by ID from a /security collection.
func (a *WazuhAPIAdapter) deleteRBAC(ctx context.Context, path, param string, ids []int) error {
	if len(ids) == 0 {
		return nil
	}
	q := fmt.Sprintf("%s?%s=%s", path, param, joinInts(ids))
	resp, err := a.doRequest(ctx, "DELETE", q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete %s failed (status %d): %s", q, resp.StatusCode, string(raw))
	}
	return nil
}

func joinInts(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ",")
}

// ---- Roles ----

// GetRoleByName returns the Wazuh API role ID for name, or 0 when absent.
func (a *WazuhAPIAdapter) GetRoleByName(ctx context.Context, name string) (int, error) {
	return a.getRBACIDByField(ctx, "/security/roles", "name", name)
}

// EnsureRole creates the role if absent and returns its ID (idempotent).
func (a *WazuhAPIAdapter) EnsureRole(ctx context.Context, name string) (int, error) {
	id, existed, err := a.createRBAC(ctx, "/security/roles", map[string]string{"name": name})
	if err != nil {
		return 0, err
	}
	if existed {
		return a.GetRoleByName(ctx, name)
	}
	return id, nil
}

// DeleteRoles deletes the given role IDs.
func (a *WazuhAPIAdapter) DeleteRoles(ctx context.Context, ids ...int) error {
	return a.deleteRBAC(ctx, "/security/roles", "role_ids", ids)
}

// ---- Policies ----

// GetPolicyByName returns the policy ID for name, or 0 when absent.
func (a *WazuhAPIAdapter) GetPolicyByName(ctx context.Context, name string) (int, error) {
	return a.getRBACIDByField(ctx, "/security/policies", "name", name)
}

// EnsurePolicy creates or updates a policy and returns its ID. When the policy
// already exists and is not reserved, its definition is updated to match spec.
func (a *WazuhAPIAdapter) EnsurePolicy(ctx context.Context, name string, actions, resources []string, effect string) (int, error) {
	policy := map[string]any{"actions": actions, "resources": resources, "effect": effect}
	id, existed, err := a.createRBAC(ctx, "/security/policies", map[string]any{"name": name, "policy": policy})
	if err != nil {
		return 0, err
	}
	if !existed {
		return id, nil
	}
	id, err = a.GetPolicyByName(ctx, name)
	if err != nil || id == 0 {
		return id, err
	}
	if id >= ReservedRBACIDThreshold {
		if err := a.putRBAC(ctx, fmt.Sprintf("/security/policies/%d", id), map[string]any{"policy": policy}); err != nil {
			return id, err
		}
	}
	return id, nil
}

// DeletePolicies deletes the given policy IDs.
func (a *WazuhAPIAdapter) DeletePolicies(ctx context.Context, ids ...int) error {
	return a.deleteRBAC(ctx, "/security/policies", "policy_ids", ids)
}

// ---- Rules ----

// GetRuleByName returns the rule ID for name, or 0 when absent.
func (a *WazuhAPIAdapter) GetRuleByName(ctx context.Context, name string) (int, error) {
	return a.getRBACIDByField(ctx, "/security/rules", "name", name)
}

// EnsureRule creates or updates an auth-context rule and returns its ID. body
// is the raw JSON matcher (e.g. {"FIND":{"user_name":"jdoe"}}).
func (a *WazuhAPIAdapter) EnsureRule(ctx context.Context, name string, body []byte) (int, error) {
	rule := json.RawMessage(body)
	id, existed, err := a.createRBAC(ctx, "/security/rules", map[string]any{"name": name, "rule": rule})
	if err != nil {
		return 0, err
	}
	if !existed {
		return id, nil
	}
	id, err = a.GetRuleByName(ctx, name)
	if err != nil || id == 0 {
		return id, err
	}
	if id >= ReservedRBACIDThreshold {
		if err := a.putRBAC(ctx, fmt.Sprintf("/security/rules/%d", id), map[string]any{"rule": rule}); err != nil {
			return id, err
		}
	}
	return id, nil
}

// DeleteRules deletes the given rule IDs.
func (a *WazuhAPIAdapter) DeleteRules(ctx context.Context, ids ...int) error {
	return a.deleteRBAC(ctx, "/security/rules", "rule_ids", ids)
}

// ---- Users ----

// GetUserByName returns the Wazuh API user ID for username, or 0 when absent.
func (a *WazuhAPIAdapter) GetUserByName(ctx context.Context, username string) (int, error) {
	return a.getRBACIDByField(ctx, "/security/users", "username", username)
}

// EnsureUser creates the user if absent (or updates its password if it already
// exists and is not reserved) and returns its ID.
func (a *WazuhAPIAdapter) EnsureUser(ctx context.Context, username, password string) (int, error) {
	id, existed, err := a.createRBAC(ctx, "/security/users", map[string]string{"username": username, "password": password})
	if err != nil {
		return 0, err
	}
	if !existed {
		return id, nil
	}
	id, err = a.GetUserByName(ctx, username)
	if err != nil || id == 0 {
		return id, err
	}
	if id >= ReservedRBACIDThreshold {
		if err := a.putRBAC(ctx, fmt.Sprintf("/security/users/%d", id), map[string]string{"password": password}); err != nil {
			return id, err
		}
	}
	return id, nil
}

// SetUserRunAs enables or disables run_as impersonation for the user.
func (a *WazuhAPIAdapter) SetUserRunAs(ctx context.Context, userID int, allow bool) error {
	path := fmt.Sprintf("/security/users/%d/run_as?allow_run_as=%t", userID, allow)
	resp, err := a.doRequest(ctx, "PUT", path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set run_as on user %d failed (status %d): %s", userID, resp.StatusCode, string(raw))
	}
	return nil
}

// DeleteUsers deletes the given user IDs.
func (a *WazuhAPIAdapter) DeleteUsers(ctx context.Context, ids ...int) error {
	return a.deleteRBAC(ctx, "/security/users", "user_ids", ids)
}

// ---- Links ----

// LinkRolePolicies links policies to a role (idempotent).
func (a *WazuhAPIAdapter) LinkRolePolicies(ctx context.Context, roleID int, policyIDs []int) error {
	return a.linkRBAC(ctx, "POST", fmt.Sprintf("/security/roles/%d/policies", roleID), "policy_ids", policyIDs)
}

// UnlinkRolePolicies unlinks policies from a role (idempotent).
func (a *WazuhAPIAdapter) UnlinkRolePolicies(ctx context.Context, roleID int, policyIDs []int) error {
	return a.linkRBAC(ctx, "DELETE", fmt.Sprintf("/security/roles/%d/policies", roleID), "policy_ids", policyIDs)
}

// LinkRoleRules links rules to a role (idempotent).
func (a *WazuhAPIAdapter) LinkRoleRules(ctx context.Context, roleID int, ruleIDs []int) error {
	return a.linkRBAC(ctx, "POST", fmt.Sprintf("/security/roles/%d/rules", roleID), "rule_ids", ruleIDs)
}

// UnlinkRoleRules unlinks rules from a role (idempotent).
func (a *WazuhAPIAdapter) UnlinkRoleRules(ctx context.Context, roleID int, ruleIDs []int) error {
	return a.linkRBAC(ctx, "DELETE", fmt.Sprintf("/security/roles/%d/rules", roleID), "rule_ids", ruleIDs)
}

// LinkUserRoles links roles to a user (idempotent).
func (a *WazuhAPIAdapter) LinkUserRoles(ctx context.Context, userID int, roleIDs []int) error {
	return a.linkRBAC(ctx, "POST", fmt.Sprintf("/security/users/%d/roles", userID), "role_ids", roleIDs)
}

// UnlinkUserRoles unlinks roles from a user (idempotent).
func (a *WazuhAPIAdapter) UnlinkUserRoles(ctx context.Context, userID int, roleIDs []int) error {
	return a.linkRBAC(ctx, "DELETE", fmt.Sprintf("/security/users/%d/roles", userID), "role_ids", roleIDs)
}
