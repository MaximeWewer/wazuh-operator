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
	"sort"
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

// rulesetReloadMaxWait bounds how long the operator waits for every manager node to hold
// the new rule, decoder or CDB list content (Wazuh cluster sync) before it reloads or
// restarts the nodes anyway.
const rulesetReloadMaxWait = 5 * time.Minute

// rulesetFile is a rule, decoder or CDB list file the operator updates in place on the
// managers through the Wazuh API: its ConfigMap holds the content to serve.
type rulesetFile struct {
	Kind          adapters.RulesetKind
	FileName      string // name under etc/<kind>
	ConfigMapName string
	Key           string // data key of the content in the ConfigMap
	ContentHash   string
}

// rulesetFiles returns the files of a cluster the Wazuh API updates in place: the rules,
// the decoders, and the CDB lists directly under etc/lists (see apiUpdatableCDBList).
func rulesetFiles(rules []RuleConfigMapInfo, decoders []DecoderConfigMapInfo, lists []CDBListConfigMapInfo) []rulesetFile {
	var files []rulesetFile
	for _, r := range rules {
		files = append(files, rulesetFile{Kind: adapters.RulesetRules, FileName: r.FileName, ConfigMapName: r.ConfigMapName, Key: r.FileName, ContentHash: r.ContentHash})
	}
	for _, d := range decoders {
		files = append(files, rulesetFile{Kind: adapters.RulesetDecoders, FileName: d.FileName, ConfigMapName: d.ConfigMapName, Key: d.FileName, ContentHash: d.ContentHash})
	}
	for _, l := range lists {
		if apiUpdatableCDBList(l) {
			files = append(files, rulesetFile{Kind: adapters.RulesetLists, FileName: l.FileName, ConfigMapName: l.ConfigMapName, Key: l.Key, ContentHash: l.ContentHash})
		}
	}
	return files
}

// rulesetContentHash returns a hash of the content of files. Returns "" when there is none.
func rulesetContentHash(files []rulesetFile) string {
	if len(files) == 0 {
		return ""
	}
	inputs := make([]string, 0, len(files))
	for _, f := range files {
		inputs = append(inputs, string(f.Kind)+"/"+f.FileName+"="+f.ContentHash)
	}
	sort.Strings(inputs)
	return computeCDBListHash(joinStrings(inputs))
}

// rulesetReloadAPI is the part of the Wazuh API the ruleset reload uses.
type rulesetReloadAPI interface {
	GetRulesetFile(ctx context.Context, kind adapters.RulesetKind, filename string) (string, error)
	UploadRulesetFile(ctx context.Context, kind adapters.RulesetKind, filename, content string) error
	RulesetSynchronized(ctx context.Context) (bool, error)
	RestartCluster(ctx context.Context) (*adapters.RestartResponse, error)
	RestartManager(ctx context.Context) (*adapters.RestartResponse, error)
	ReloadAnalysisd(ctx context.Context) error
}

// reconcileRulesetReload makes the manager nodes load new content of the rules, decoders
// and CDB lists the API updates in place (see rulesetFiles). The master gets the content of
// their ConfigMaps (a rule or decoder is already there, written when it was validated) and
// the Wazuh cluster syncs it to the workers; once every node holds it, one
// PUT /cluster/analysisd/reload (Wazuh 4.13+, no outage) or PUT /cluster/restart (restarts
// the Wazuh daemons in place, seconds) loads it instead of recreating the pods. The master
// StatefulSet records the content hash the nodes last loaded, so each change triggers a
// single reload or restart.
func (r *ClusterReconciler) reconcileRulesetReload(ctx context.Context, cluster *wazuhv1.WazuhCluster, master *appsv1.StatefulSet, files []rulesetFile) error {
	want := rulesetContentHash(files)
	applied, known := master.Annotations[constants.AnnotationRulesetContentHash]
	pending := master.Annotations[constants.AnnotationRulesetReloadPendingSince] != ""
	if known && applied == want && !pending {
		return nil
	}
	if !known || applied == want {
		// First reconcile with this annotation (new StatefulSet, or one created by an
		// older operator), or a rollout already loaded the content: the pods loaded the
		// content they started with.
		return r.patchRulesetReloadState(ctx, master, want, "")
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
	return r.reloadRuleset(ctx, cluster, master, api, files, want, time.Now())
}

// reloadRuleset reloads or restarts the manager nodes once they all hold the content hashed
// by want, or once rulesetReloadMaxWait has elapsed since the change was first seen.
func (r *ClusterReconciler) reloadRuleset(ctx context.Context, cluster *wazuhv1.WazuhCluster, master *appsv1.StatefulSet,
	api rulesetReloadAPI, files []rulesetFile, want string, now time.Time) error {
	log := logf.FromContext(ctx)

	stale, err := r.syncRulesetFiles(ctx, cluster, api, files)
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
		since, perr := time.Parse(time.RFC3339, master.Annotations[constants.AnnotationRulesetReloadPendingSince])
		if perr != nil {
			log.Info("Waiting for the manager nodes to receive the new ruleset content",
				"staleFiles", stale, "rulesetSynced", synced)
			return r.patchRulesetReloadState(ctx, master, master.Annotations[constants.AnnotationRulesetContentHash], now.UTC().Format(time.RFC3339))
		}
		if now.Sub(since) < rulesetReloadMaxWait {
			log.V(1).Info("Still waiting for the manager nodes to receive the new ruleset content",
				"staleFiles", stale, "rulesetSynced", synced, "since", since)
			return nil
		}
		msg := fmt.Sprintf("Manager nodes still miss the new ruleset content after %s (stale files: %s, ruleset synced: %t); reloading them anyway",
			rulesetReloadMaxWait, strings.Join(stale, ","), synced)
		log.Info(msg)
		if r.Recorder != nil {
			r.Recorder.Event(cluster, corev1.EventTypeWarning, "RulesetReloadTimeout", msg)
		}
	}

	if supportsAnalysisdReload(cluster.Spec.Version) {
		err := api.ReloadAnalysisd(ctx)
		switch {
		case err == nil:
			log.Info("Reloaded the manager ruleset to load the new content", "contentHash", utils.ShortHash(want))
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeNormal, "RulesetReloaded",
					"Reloaded the ruleset of the manager nodes through the Wazuh API to load the new rules, decoders or CDB lists")
			}
			return r.patchRulesetReloadState(ctx, master, want, "")
		case IsAPIUnavailable(err):
			return err
		case !errors.Is(err, adapters.ErrEndpointNotFound):
			// analysisd keeps running the previous ruleset; a restart would reject the new
			// one the same way, so retry on the next reconcile instead.
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, "RulesetReloadFailed", err.Error())
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
			return fmt.Errorf("failed to restart the manager to load the new ruleset content: %w", err)
		}
	}
	log.Info("Restarted the manager nodes to load the new ruleset content", "contentHash", utils.ShortHash(want))
	if r.Recorder != nil {
		r.Recorder.Event(cluster, corev1.EventTypeNormal, "RulesetReloaded",
			"Restarted the manager nodes through the Wazuh API to load the new rules, decoders or CDB lists")
	}
	return r.patchRulesetReloadState(ctx, master, want, "")
}

// analysisdReloadMinVersion is the first Wazuh version with PUT /cluster/analysisd/reload.
var analysisdReloadMinVersion = &versions.Version{Major: 4, Minor: 13, Patch: 0}

// supportsAnalysisdReload reports whether the manager reloads its ruleset through the API
// instead of restarting. An unparsable version falls back to the restart.
func supportsAnalysisdReload(wazuhVersion string) bool {
	v, err := versions.ParseVersion(wazuhVersion)
	return err == nil && v.GreaterThanOrEqual(analysisdReloadMinVersion)
}

// syncRulesetFiles makes the master serve the content of every file's ConfigMap: a file
// whose content differs is uploaded, and the Wazuh cluster then syncs it to the workers.
// The ConfigMap of a rule or decoder only holds content the managers accepted. Returns the
// files still stale, e.g. while a CDB list ConfigMap lags behind its WazuhCDBList status.
// Only an unavailable API is returned as an error.
func (r *ClusterReconciler) syncRulesetFiles(ctx context.Context, cluster *wazuhv1.WazuhCluster, api rulesetReloadAPI, files []rulesetFile) ([]string, error) {
	log := logf.FromContext(ctx)
	var stale []string
	for _, f := range files {
		name := string(f.Kind) + "/" + f.FileName
		served, err := api.GetRulesetFile(ctx, f.Kind, f.FileName)
		if IsAPIUnavailable(err) {
			return nil, err
		}
		if err == nil && computeCDBListHash(served) == f.ContentHash {
			continue
		}
		cm := &corev1.ConfigMap{}
		if err := r.Get(ctx, types.NamespacedName{Name: f.ConfigMapName, Namespace: cluster.Namespace}, cm); err != nil {
			log.V(1).Info("Cannot read the ConfigMap of a ruleset file", "file", name, "error", err.Error())
			stale = append(stale, name)
			continue
		}
		content, ok := cm.Data[f.Key]
		if !ok || computeCDBListHash(content) != f.ContentHash {
			stale = append(stale, name)
			continue
		}
		if err := api.UploadRulesetFile(ctx, f.Kind, f.FileName, content); err != nil {
			if IsAPIUnavailable(err) {
				return nil, err
			}
			log.Error(err, "Failed to upload the ruleset file to the master", "file", name)
			stale = append(stale, name)
			continue
		}
		log.Info("Uploaded the new ruleset file content to the master", "file", name)
	}
	return stale, nil
}

// apiUpdatableCDBList reports whether a list is updated in place through the Wazuh API:
// ConfigMap-delivered and directly under etc/lists (PUT /lists/files cannot write into a
// subdirectory, so a change to such a list rolls the manager pods instead).
func apiUpdatableCDBList(info CDBListConfigMapInfo) bool {
	return info.Mode == cdbDeliveryConfigMap && !strings.Contains(info.FileName, "/")
}

// patchRulesetReloadState records on the master StatefulSet the ruleset content hash the
// manager nodes loaded and, when pendingSince is set, since when new content is waiting.
func (r *ClusterReconciler) patchRulesetReloadState(ctx context.Context, master *appsv1.StatefulSet, applied, pendingSince string) error {
	base := master.DeepCopy()
	if master.Annotations == nil {
		master.Annotations = map[string]string{}
	}
	master.Annotations[constants.AnnotationRulesetContentHash] = applied
	if pendingSince != "" {
		master.Annotations[constants.AnnotationRulesetReloadPendingSince] = pendingSince
	} else {
		delete(master.Annotations, constants.AnnotationRulesetReloadPendingSince)
	}
	if err := r.Patch(ctx, master, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("failed to record the ruleset reload state on %s: %w", master.Name, err)
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
