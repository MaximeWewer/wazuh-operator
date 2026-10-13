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

package controllers

import (
	"math/rand/v2"
	"time"
)

// apiUnavailableRequeue is the delay before retrying a resource whose Wazuh API is down:
// 30s plus up to 15s of jitter, so the resources that failed together during a manager
// restart do not all call the API again in the same second once it is back.
func apiUnavailableRequeue() time.Duration {
	return 30*time.Second + rand.N(15*time.Second) //nolint:gosec // jitter does not need crypto randomness
}
