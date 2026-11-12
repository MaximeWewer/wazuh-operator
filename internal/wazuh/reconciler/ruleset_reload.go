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
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
	"github.com/MaximeWewer/wazuh-operator/pkg/versions"
)

// cdbListReloadMaxWait bounds how long the operator waits for every manager node to hold
// the new CDB list content (kubelet ConfigMap sync, then Wazuh cluster sync) before it
// restarts the nodes anyway.
const cdbListReloadMaxWait = 5 * time.Minute

// cdbListReloadAPI is the part of the Wazuh API the CDB list reload uses.
type cdbListReloadAPI interface {
	GetListFile(ctx context.Context, filename string) (string, error)
	UploadListFile(ctx context.Context, filename, content string) error
	RulesetSynchronized(ctx context.Context) (bool, error)
	RestartCluster(ctx context.Context) (*adapters.RestartResponse, error)
	RestartManager(ctx context.Context) (*adapters.RestartResponse, error)
	ReloadAnalysisd(ctx context.Context) error
}

// reconcileCDBListReload makes the manager nodes load new content of the CDB lists the API
// can update (see apiUpdatableCDBList). The operator uploads the new content to the master,
// which the Wazuh cluster syncs to the workers; once every node holds it, one
// PUT /cluster/analysisd/reload (Wazuh 4.13+, no outage)
// or PUT /cluster/restart (restarts the Wazuh daemons in place, seconds) loads it instead of
// recreating the pods. The master StatefulSet records the content hash the nodes last
// loaded, so each change triggers a single reload or restart.
func (r *ClusterReconciler) reconcileCDBListReload(ctx context.Context, cluster *wazuhv1.WazuhCluster, master *appsv1.StatefulSet, infos []CDBListConfigMapInfo) error {
	want := CDBListContentHash(infos)
	applied, known := master.Annotations[constants.AnnotationCDBListContentHash]
	pending := master.Annotations[constants.AnnotationCDBListReloadPendingSince] != ""
	if known && applied == want && !pending {
		return nil
	}
	if !known || applied == want {
		// First reconcile with this annotation (new StatefulSet, or one created by an
		// older operator), or a rollout already loaded the content: the pods loaded the
		// content they started with.
		return r.patchCDBListReloadState(ctx, master, want, "")
	}

	// Wait for a rollout to finish: the restarted pods load the current content anyway and
	// the API is unavailable meanwhile.
	if !statefulSetRolledOut(master) {
		return nil
	}

	api, err := buildWazuhAPIClient(ctx, r.Client, cluster)
	if err != nil {
		return err
	}
	return r.reloadCDBLists(ctx, cluster, master, api, infos, want, time.Now())
}

// reloadCDBLists reloads or restarts the manager nodes once they all hold the content hashed by want,
// or once cdbListReloadMaxWait has elapsed since the change was first seen.
func (r *ClusterReconciler) reloadCDBLists(ctx context.Context, cluster *wazuhv1.WazuhCluster, master *appsv1.StatefulSet,
	api cdbListReloadAPI, infos []CDBListConfigMapInfo, want string, now time.Time) error {
	log := logf.FromContext(ctx)

	stale, err := r.syncCDBListFiles(ctx, cluster, api, infos)
	if err != nil {
		return err
	}
	synced := true
	if len(stale) == 0 {
		if synced, err = api.RulesetSynchronized(ctx); err != nil {
			if IsAPIUnavailable(err) {
				return err
			}
			// Cluster disabled or endpoint missing: the master is the only node to check.
			log.V(1).Info("Cannot read the ruleset synchronization, checking the master only", "error", err.Error())
			synced = true
		}
	}

	if len(stale) > 0 || !synced {
		since, perr := time.Parse(time.RFC3339, master.Annotations[constants.AnnotationCDBListReloadPendingSince])
		if perr != nil {
			log.Info("Waiting for the manager nodes to receive the new CDB list content",
				"staleLists", stale, "rulesetSynced", synced)
			return r.patchCDBListReloadState(ctx, master, master.Annotations[constants.AnnotationCDBListContentHash], now.UTC().Format(time.RFC3339))
		}
		if now.Sub(since) < cdbListReloadMaxWait {
			log.V(1).Info("Still waiting for the manager nodes to receive the new CDB list content",
				"staleLists", stale, "rulesetSynced", synced, "since", since)
			return nil
		}
		msg := fmt.Sprintf("Manager nodes still miss the new CDB list content after %s (stale lists: %s, ruleset synced: %t); restarting them anyway",
			cdbListReloadMaxWait, strings.Join(stale, ","), synced)
		log.Info(msg)
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeWarning, "CDBListReloadTimeout", msg)
		}
	}

	if supportsAnalysisdReload(cluster.Spec.Version) {
		err := api.ReloadAnalysisd(ctx)
		switch {
		case err == nil:
			log.Info("Reloaded the manager ruleset to load the new CDB list content", "contentHash", utils.ShortHash(want))
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeNormal, "CDBListReloaded",
					"Reloaded the ruleset of the manager nodes through the Wazuh API to load the new CDB list content")
			}
			return r.patchCDBListReloadState(ctx, master, want, "")
		case IsAPIUnavailable(err):
			return err
		case !errors.Is(err, adapters.ErrEndpointNotFound):
			// analysisd keeps running the previous ruleset; a restart would reject the new
			// one the same way, so retry on the next reconcile instead.
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, "CDBListReloadFailed", err.Error())
			}
			return err
		}
		log.Info("Ruleset reload endpoint not found, restarting the manager nodes instead")
	}

	if _, err := api.RestartCluster(ctx); err != nil {
		if IsAPIUnavailable(err) {
			return err
		}
		// A manager running without the Wazuh cluster rejects /cluster/restart.
		log.Info("Cluster restart rejected, restarting the master manager", "error", err.Error())
		if _, err := api.RestartManager(ctx); err != nil {
			return fmt.Errorf("failed to restart the manager to load the new CDB list content: %w", err)
		}
	}
	log.Info("Restarted the manager nodes to load the new CDB list content", "contentHash", utils.ShortHash(want))
	if r.Recorder != nil {
		r.Recorder.Event(cluster, corev1.EventTypeNormal, "CDBListReloaded",
			"Restarted the manager nodes through the Wazuh API to load the new CDB list content")
	}
	return r.patchCDBListReloadState(ctx, master, want, "")
}

// analysisdReloadMinVersion is the first Wazuh version with PUT /cluster/analysisd/reload.
var analysisdReloadMinVersion = &versions.Version{Major: 4, Minor: 13, Patch: 0}

// supportsAnalysisdReload reports whether the manager reloads its ruleset through the API
// instead of restarting. An unparsable version falls back to the restart.
func supportsAnalysisdReload(wazuhVersion string) bool {
	v, err := versions.ParseVersion(wazuhVersion)
	return err == nil && v.GreaterThanOrEqual(analysisdReloadMinVersion)
}

// syncCDBListFiles makes the master serve the current content of every list the API can
// update (see apiUpdatableCDBList): a list whose content differs is uploaded from its
// ConfigMap, and the Wazuh cluster then syncs it to the workers. Returns the lists still
// stale, e.g. while the ConfigMap lags behind the WazuhCDBList status. Only an unavailable
// API is returned as an error.
func (r *ClusterReconciler) syncCDBListFiles(ctx context.Context, cluster *wazuhv1.WazuhCluster, api cdbListReloadAPI, infos []CDBListConfigMapInfo) ([]string, error) {
	log := logf.FromContext(ctx)
	var stale []string
	for _, info := range infos {
		if !apiUpdatableCDBList(info) {
			continue
		}
		served, err := api.GetListFile(ctx, info.FileName)
		if IsAPIUnavailable(err) {
			return nil, err
		}
		if err == nil && computeCDBListHash(served) == info.ContentHash {
			continue
		}
		cm := &corev1.ConfigMap{}
		if err := r.Get(ctx, types.NamespacedName{Name: info.ConfigMapName, Namespace: cluster.Namespace}, cm); err != nil {
			log.V(1).Info("Cannot read the CDB list ConfigMap", "list", info.FileName, "error", err.Error())
			stale = append(stale, info.FileName)
			continue
		}
		content, ok := cm.Data[info.Key]
		if !ok || computeCDBListHash(content) != info.ContentHash {
			stale = append(stale, info.FileName)
			continue
		}
		if err := api.UploadListFile(ctx, info.FileName, content); err != nil {
			if IsAPIUnavailable(err) {
				return nil, err
			}
			log.Error(err, "Failed to upload the CDB list to the master", "list", info.FileName)
			stale = append(stale, info.FileName)
			continue
		}
		log.Info("Uploaded the new CDB list content to the master", "list", info.FileName)
	}
	return stale, nil
}

// apiUpdatableCDBList reports whether a list is updated in place through the Wazuh API:
// ConfigMap-delivered and directly under etc/lists (PUT /lists/files cannot write into a
// subdirectory, so a change to such a list rolls the manager pods instead).
func apiUpdatableCDBList(info CDBListConfigMapInfo) bool {
	return info.Mode == cdbDeliveryConfigMap && !strings.Contains(info.FileName, "/")
}

// patchCDBListReloadState records on the master StatefulSet the CDB list content hash the
// manager nodes loaded and, when pendingSince is set, since when new content is waiting.
func (r *ClusterReconciler) patchCDBListReloadState(ctx context.Context, master *appsv1.StatefulSet, applied, pendingSince string) error {
	base := master.DeepCopy()
	if master.Annotations == nil {
		master.Annotations = map[string]string{}
	}
	master.Annotations[constants.AnnotationCDBListContentHash] = applied
	if pendingSince != "" {
		master.Annotations[constants.AnnotationCDBListReloadPendingSince] = pendingSince
	} else {
		delete(master.Annotations, constants.AnnotationCDBListReloadPendingSince)
	}
	if err := r.Patch(ctx, master, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("failed to record the CDB list reload state on %s: %w", master.Name, err)
	}
	return nil
}

// statefulSetRolledOut reports whether every replica runs the current revision and is ready.
func statefulSetRolledOut(sts *appsv1.StatefulSet) bool {
	replicas := int32(1)
	if sts.Spec.Replicas != nil {
		replicas = *sts.Spec.Replicas
	}
	return sts.Status.ObservedGeneration >= sts.Generation &&
		sts.Status.UpdatedReplicas == replicas &&
		sts.Status.ReadyReplicas == replicas &&
		(sts.Status.UpdateRevision == "" || sts.Status.CurrentRevision == sts.Status.UpdateRevision)
}
