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

package rolling

import (
	appsv1 "k8s.io/api/apps/v1"
)

// StatefulSetUpdateStrategy returns the update strategy to render for a StatefulSet.
//
// RollingUpdate always carries an explicit rollingUpdate.partition of 0. The API server
// only fills that block when the strategy type is left empty, and without it the
// StatefulSet controller picks the revision of a recreated pod from status.currentReplicas
// (newVersionedStatefulSetPod), which lags behind the pods it just deleted: during a
// rollout the replacement pod comes back on the OLD revision, becomes available, is
// replaced again, and so on - a restart every ~90s per pod on the manager (startup +
// minReadySeconds) until the status catches up. With a partition the controller compares
// the ordinal to the partition instead, so every recreated pod gets the update revision.
func StatefulSetUpdateStrategy(strategyType appsv1.StatefulSetUpdateStrategyType) appsv1.StatefulSetUpdateStrategy {
	strategy := appsv1.StatefulSetUpdateStrategy{Type: strategyType}
	if strategyType == appsv1.RollingUpdateStatefulSetStrategyType {
		strategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{Partition: new(int32(0))}
	}
	return strategy
}
