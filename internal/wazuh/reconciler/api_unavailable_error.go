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
	"errors"
	"fmt"
)

// WazuhAPIUnavailableError indicates the Wazuh API is not reachable yet.
// The controller should requeue with a delay when this error is returned.
type WazuhAPIUnavailableError struct {
	Err error
}

func (e *WazuhAPIUnavailableError) Error() string {
	return fmt.Sprintf("wazuh API unavailable: %v", e.Err)
}

func (e *WazuhAPIUnavailableError) Unwrap() error {
	return e.Err
}

// IsAPIUnavailable returns true if the error (or any wrapped error) is a WazuhAPIUnavailableError.
func IsAPIUnavailable(err error) bool {
	var target *WazuhAPIUnavailableError
	return errors.As(err, &target)
}
