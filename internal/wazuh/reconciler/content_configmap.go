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
	"context"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// ErrContentStillMounted reports that a manager StatefulSet still mounts the ConfigMap of
// a resource being deleted, or has not finished rolling out without it. The caller keeps
// the finalizer and retries: deleting the ConfigMap first would leave a starting manager
// pod with a missing volume or an empty file (analysisd then stops on a configuration
// error and the API never comes up).
var ErrContentStillMounted = errors.New("content ConfigMap still mounted by a manager StatefulSet")

// deleteContentConfigMap deletes the ConfigMap cmName of a resource in the namespace of
// each cluster it targets, once that cluster's manager StatefulSets no longer mount it
// (the cluster reconcile drops the mount of a resource being deleted) and have rolled
// out. Returns ErrContentStillMounted while a cluster still mounts it.
func deleteContentConfigMap(ctx context.Context, c client.Client, refs []wazuhv1.WazuhClusterRef, cmName string) error {
	log := logf.FromContext(ctx)
	stillMounted := false
	for _, ref := range refs {
		released, err := managersReleasedConfigMap(ctx, c, ref, cmName)
		if err != nil {
			return err
		}
		if !released {
			log.Info("Waiting for the manager StatefulSets to stop mounting the ConfigMap before deleting it",
				"configMap", cmName, "cluster", ref.Name, "namespace", ref.Namespace)
			stillMounted = true
			continue
		}
		cm := &corev1.ConfigMap{}
		err = c.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, cm)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to get ConfigMap %s/%s: %w", ref.Namespace, cmName, err)
		}
		if err := c.Delete(ctx, cm); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete ConfigMap %s/%s: %w", ref.Namespace, cmName, err)
		}
	}
	if stillMounted {
		return ErrContentStillMounted
	}
	return nil
}

// managersReleasedConfigMap reports whether no manager StatefulSet of the cluster mounts
// the ConfigMap and all of them have rolled out (an older pod may still use it).
func managersReleasedConfigMap(ctx context.Context, c client.Client, ref wazuhv1.WazuhClusterRef, cmName string) (bool, error) {
	stsList := &appsv1.StatefulSetList{}
	if err := c.List(ctx, stsList, client.InNamespace(ref.Namespace), client.MatchingLabels{
		constants.LabelWazuhCluster: ref.Name,
		constants.LabelComponent:    constants.ComponentManager,
	}); err != nil {
		return false, fmt.Errorf("failed to list manager StatefulSets of %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	for i := range stsList.Items {
		sts := &stsList.Items[i]
		for _, v := range sts.Spec.Template.Spec.Volumes {
			if v.ConfigMap != nil && v.ConfigMap.Name == cmName {
				return false, nil
			}
		}
		if !statefulSetRolledOut(sts) {
			return false, nil
		}
	}
	return true, nil
}
