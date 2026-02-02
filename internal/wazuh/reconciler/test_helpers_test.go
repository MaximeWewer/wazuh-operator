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

// Shared test helper functions for the reconciler package

// int32Ptr returns a pointer to an int32 value
// Used for creating WazuhWorkerSpec.Replicas and other pointer fields
func int32Ptr(i int32) *int32 {
	return &i
}
