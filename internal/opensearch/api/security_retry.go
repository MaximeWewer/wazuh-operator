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

import (
	"context"
	"strings"
	"time"
)

// isSecurityVersionConflict reports whether err is a transient optimistic-lock
// conflict on the security index. It happens when two writers race on
// .opendistro_security (e.g. the cluster-wide security CRD sync and an
// OpenSearchRole/RoleMapping reconcile firing at the same time): the security
// plugin rejects the write with a seqNo/primary-term version conflict.
func isSecurityVersionConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "version conflict") ||
		strings.Contains(msg, `"status":"conflict"`) ||
		strings.Contains(msg, `"status":409`)
}

// retryOnSecurityConflict serializes fn under the per-cluster security write lock
// (clusterKey) and replays it while it returns a transient security-index version
// conflict, with a short linear backoff. The lock removes conflicts between the
// operator's own writers; the retry still covers rare races with external writers
// (e.g. securityadmin during bootstrap). The security API PUTs are idempotent
// full-document replaces, so replaying is safe.
func retryOnSecurityConflict(ctx context.Context, clusterKey string, fn func() error) error {
	lock := securityWriteLock(clusterKey)
	lock.Lock()
	defer lock.Unlock()

	const maxAttempts = 4
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = fn()
		if err == nil || !isSecurityVersionConflict(err) || attempt == maxAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
		}
	}
	return err
}
