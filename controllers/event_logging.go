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
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// crEventLog is the shared logger for custom-resource lifecycle events.
var crEventLog = logf.Log.WithName("cr-events")

// eventLogPredicate returns a predicate that logs create/update/delete events for the
// primary custom resource, then passes every event through unchanged (it never filters).
//
// It exists because the controllers reconcile on a 30s resync as well as on real changes,
// and every reconcile logs the same "Successfully reconciled" line - so there was no way to
// tell from the logs when a CR was actually created, modified or deleted. Predicates fire
// only on watch events, never on the periodic requeue, so logging here yields clean
// lifecycle logs without the resync noise.
//
// Attach via builder.WithEventFilter, which also feeds owned/watched objects (ConfigMaps,
// Secrets, ...) through the predicate. The sample object's type is used to log only the
// primary kind and ignore those secondary events. Updates are logged only when the
// generation changes, so status-only writes do not spam the log.
func eventLogPredicate(kind string, sample client.Object) predicate.Predicate {
	primaryType := reflect.TypeOf(sample)
	isPrimary := func(o client.Object) bool {
		return o != nil && reflect.TypeOf(o) == primaryType
	}

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			if isPrimary(e.Object) {
				crEventLog.Info("Custom resource created",
					"kind", kind, "name", e.Object.GetName(), "namespace", e.Object.GetNamespace())
			}
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if !isPrimary(e.ObjectNew) {
				return true
			}
			// Deleting a finalizer-protected object sets deletionTimestamp, which also
			// bumps the generation. Report that as a deletion request rather than a
			// misleading "updated" (the actual delete event fires later, once the
			// finalizer is removed).
			if e.ObjectOld.GetDeletionTimestamp() == nil && e.ObjectNew.GetDeletionTimestamp() != nil {
				crEventLog.Info("Custom resource deletion requested",
					"kind", kind, "name", e.ObjectNew.GetName(), "namespace", e.ObjectNew.GetNamespace())
				return true
			}
			if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
				crEventLog.Info("Custom resource updated",
					"kind", kind, "name", e.ObjectNew.GetName(), "namespace", e.ObjectNew.GetNamespace(),
					"generation", e.ObjectNew.GetGeneration())
			}
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			if isPrimary(e.Object) {
				crEventLog.Info("Custom resource deleted",
					"kind", kind, "name", e.Object.GetName(), "namespace", e.Object.GetNamespace())
			}
			return true
		},
	}
}
