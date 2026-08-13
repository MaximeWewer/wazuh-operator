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

package api

import "sync"

// All OpenSearch security config (roles, role mappings, internal users, tenants, action
// groups) is stored as a single document per type in .opendistro_security, written with
// optimistic concurrency. Concurrent operator writes - the per-CR controllers
// (OpenSearchRole/RoleMapping/User/…) and the cluster-level SecurityConfigSynchronizer -
// therefore race with seqNo/primary-term version conflicts, and each successful write
// makes the security plugin reload the whole config. Serializing writes per target
// cluster removes both problems.
var (
	securityLocksMu sync.Mutex
	securityLocks   = map[string]*sync.Mutex{}
)

// securityWriteLock returns the process-wide mutex serializing writes to a cluster's
// .opendistro_security config, keyed by the cluster's API base URL.
func securityWriteLock(clusterKey string) *sync.Mutex {
	securityLocksMu.Lock()
	defer securityLocksMu.Unlock()
	m := securityLocks[clusterKey]
	if m == nil {
		m = &sync.Mutex{}
		securityLocks[clusterKey] = m
	}
	return m
}

// WithSecurityWriteLock runs fn while holding the per-cluster security write lock.
// Exported for the security synchronizer, whose writes go through the cluster reconcile
// path rather than the retry-wrapped per-CR API helpers.
func WithSecurityWriteLock(clusterKey string, fn func() error) error {
	lock := securityWriteLock(clusterKey)
	lock.Lock()
	defer lock.Unlock()
	return fn()
}

// SecurityKey returns the stable per-cluster key (the API base URL) used to serialize
// security-config writes for this client.
func (c *Client) SecurityKey() string { return c.baseURL }
