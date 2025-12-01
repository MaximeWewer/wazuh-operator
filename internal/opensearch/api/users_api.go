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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// User represents an OpenSearch internal user
type User struct {
	Password      string            `json:"password,omitempty"`
	Hash          string            `json:"hash,omitempty"`
	Reserved      bool              `json:"reserved,omitempty"`
	Hidden        bool              `json:"hidden,omitempty"`
	BackendRoles  []string          `json:"backend_roles,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	Description   string            `json:"description,omitempty"`
	SecurityRoles []string          `json:"opendistro_security_roles,omitempty"`
}

// UsersAPI provides user management operations
type UsersAPI struct {
	client *Client
}

// NewUsersAPI creates a new UsersAPI
func NewUsersAPI(client *Client) *UsersAPI {
	return &UsersAPI{client: client}
}

// Create creates a new user
func (a *UsersAPI) Create(ctx context.Context, username string, user User) error {
	resp, err := a.client.Put(ctx, "/_plugins/_security/api/internalusers/"+username, user)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create user: %s", string(body))
	}

	return nil
}

// Get retrieves a user
func (a *UsersAPI) Get(ctx context.Context, username string) (*User, error) {
	resp, err := a.client.Get(ctx, "/_plugins/_security/api/internalusers/"+username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user: %s", string(body))
	}

	var users map[string]User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}

	if user, ok := users[username]; ok {
		return &user, nil
	}

	return nil, nil
}

// Delete deletes a user
func (a *UsersAPI) Delete(ctx context.Context, username string) error {
	resp, err := a.client.Delete(ctx, "/_plugins/_security/api/internalusers/"+username)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete user: %s", string(body))
	}

	return nil
}

// Exists checks if a user exists
func (a *UsersAPI) Exists(ctx context.Context, username string) (bool, error) {
	user, err := a.Get(ctx, username)
	if err != nil {
		return false, err
	}
	return user != nil, nil
}

// List lists all users
func (a *UsersAPI) List(ctx context.Context) (map[string]User, error) {
	resp, err := a.client.Get(ctx, "/_plugins/_security/api/internalusers")
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list users: %s", string(body))
	}

	var users map[string]User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode users: %w", err)
	}

	return users, nil
}
