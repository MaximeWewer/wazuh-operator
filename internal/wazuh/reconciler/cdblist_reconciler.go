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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"go.opentelemetry.io/otel/attribute"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/telemetry"
	"github.com/MaximeWewer/wazuh-operator/internal/utils"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/cdblist"
	"github.com/MaximeWewer/wazuh-operator/internal/wazuh/validation"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

const (
	// CDBListFinalizer is the finalizer for WazuhCDBList resources.
	CDBListFinalizer = "wazuhcdblist.resources.wazuh.com/finalizer"

	// Condition types for WazuhCDBList.
	ConditionTypeCDBListFetched = "Fetched"

	// Labels used to identify CDB list ConfigMaps owned by a WazuhCDBList CR.
	// Cross-namespace owner references are forbidden, so cleanup is finalizer-driven.
	labelCDBListCROwnerName      = "resources.wazuh.com/cdblist-cr"
	labelCDBListCROwnerNamespace = "resources.wazuh.com/cdblist-cr-namespace"

	// defaultCDBListRefreshInterval is used when a source has no explicit interval.
	defaultCDBListRefreshInterval = time.Hour

	// cdbListFetchTimeout bounds the HTTP GET when fetching remote list content.
	cdbListFetchTimeout = 30 * time.Second
)

// CDBListReconciler handles reconciliation of Wazuh CDB lists.
type CDBListReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Recorder   record.EventRecorder
	Validator  *validation.CDBListValidator
	HTTPClient *http.Client
}

// NewCDBListReconciler creates a new CDBListReconciler.
func NewCDBListReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *CDBListReconciler {
	return &CDBListReconciler{
		Client:    c,
		Scheme:    scheme,
		Recorder:  recorder,
		Validator: validation.NewCDBListValidator(c),
	}
}

// Reconcile reconciles the CDB list across all target clusters and returns the
// requeue interval to use for periodic source refresh (0 means no periodic refresh).
func (r *CDBListReconciler) Reconcile(ctx context.Context, list *wazuhv1.WazuhCDBList) (requeueAfter time.Duration, err error) {
	ctx, span := telemetry.Tracer().Start(ctx, "CDBListReconciler.Reconcile",
		telemetry.WithAttributes(
			attribute.String("resource.name", list.Name),
			attribute.String("resource.namespace", list.Namespace),
			attribute.Int("resource.clusterRefs", len(list.Spec.ClusterRefs)),
		))
	defer span.End()
	defer func() {
		if err != nil {
			telemetry.RecordError(span, err)
		}
	}()

	log := logf.FromContext(ctx)

	if list.Status.Phase == "" {
		list.Status.Phase = wazuhv1.CDBListPhasePending
	}

	// Content validation is cluster-independent.
	validationResult := r.Validator.Validate(ctx, list)
	if !validationResult.Valid {
		log.Info("CDB list validation failed", "errors", validationResult.Errors)
		list.Status.ValidationErrors = validationResult.Errors
		r.setCondition(list, ConditionTypeValidated, metav1.ConditionFalse, "ValidationFailed",
			validation.FormatValidationErrors(validationResult.Errors))
		r.setCondition(list, ConditionTypeReady, metav1.ConditionFalse, "ValidationFailed",
			"CDB list validation failed")
		list.Status.Phase = wazuhv1.CDBListPhaseFailed
		if r.Recorder != nil {
			r.Recorder.Event(list, corev1.EventTypeWarning, "ValidationFailed",
				validation.FormatValidationErrors(validationResult.Errors))
		}
		return 0, r.updateStatus(ctx, list)
	}
	list.Status.ValidationErrors = nil
	r.setCondition(list, ConditionTypeValidated, metav1.ConditionTrue, "ValidationPassed",
		"CDB list content is valid")

	// Resolve the desired list content (fetches the URL when a source is due for refresh).
	content, fetched, err := r.resolveContent(ctx, list)
	if err != nil {
		list.Status.Phase = wazuhv1.CDBListPhaseFailed
		list.Status.Message = err.Error()
		r.setCondition(list, ConditionTypeCDBListFetched, metav1.ConditionFalse, "FetchFailed", err.Error())
		r.setCondition(list, ConditionTypeReady, metav1.ConditionFalse, "FetchFailed",
			"Failed to resolve CDB list content")
		if r.Recorder != nil {
			r.Recorder.Event(list, corev1.EventTypeWarning, "FetchFailed", err.Error())
		}
		_ = r.updateStatus(ctx, list)
		return r.refreshInterval(list), err
	}
	if list.Spec.Source != nil {
		r.setCondition(list, ConditionTypeCDBListFetched, metav1.ConditionTrue, "Fetched",
			"CDB list content resolved from source")
		if fetched {
			now := metav1.Now()
			list.Status.LastFetchTime = &now
		}
	}

	list.Status.EntryCount = int32(cdblist.CountEntries(content))
	list.Status.ContentHash = computeCDBListHash(content)

	existingByKey := make(map[string]wazuhv1.CDBListClusterStatus, len(list.Status.ClusterStatuses))
	for _, s := range list.Status.ClusterStatuses {
		existingByKey[clusterKey(s.Name, s.Namespace)] = s
	}

	newStatuses := make([]wazuhv1.CDBListClusterStatus, 0, len(list.Spec.ClusterRefs))
	anyFailed := false
	allApplied := true

	for _, ref := range list.Spec.ClusterRefs {
		st := existingByKey[clusterKey(ref.Name, ref.Namespace)]
		st.Name = ref.Name
		st.Namespace = ref.Namespace

		if err := r.reconcileListForCluster(ctx, list, ref, content, &st); err != nil {
			anyFailed = true
			log.Error(err, "Failed to reconcile CDB list on cluster",
				"cluster", ref.Name, "clusterNamespace", ref.Namespace)
		}
		if st.Phase != wazuhv1.CDBListPhaseApplied {
			allApplied = false
		}
		newStatuses = append(newStatuses, st)
	}

	sort.Slice(newStatuses, func(i, j int) bool {
		if newStatuses[i].Namespace != newStatuses[j].Namespace {
			return newStatuses[i].Namespace < newStatuses[j].Namespace
		}
		return newStatuses[i].Name < newStatuses[j].Name
	})
	list.Status.ClusterStatuses = newStatuses

	switch {
	case anyFailed:
		list.Status.Phase = wazuhv1.CDBListPhaseFailed
		r.setCondition(list, ConditionTypeReady, metav1.ConditionFalse, "ClusterFailures",
			"One or more target clusters failed to apply the CDB list")
		list.Status.Message = "One or more target clusters failed to apply the CDB list"
	case allApplied:
		list.Status.Phase = wazuhv1.CDBListPhaseApplied
		r.setCondition(list, ConditionTypeReady, metav1.ConditionTrue, "ListApplied",
			"CDB list applied to all target clusters")
		r.setCondition(list, ConditionTypeConfigMapCreated, metav1.ConditionTrue, "ConfigMapCreated",
			"All cluster ConfigMaps reconciled")
		list.Status.Message = ""
	default:
		list.Status.Phase = wazuhv1.CDBListPhasePending
	}

	list.Status.ObservedGeneration = list.Generation

	if err := r.updateStatus(ctx, list); err != nil {
		return r.refreshInterval(list), fmt.Errorf("failed to update CDB list status: %w", err)
	}

	if anyFailed {
		return r.refreshInterval(list), fmt.Errorf("one or more target clusters failed to apply the CDB list")
	}
	log.Info("CDB list reconciliation completed", "name", list.Name)
	return r.refreshInterval(list), nil
}

// resolveContent computes the desired CDB list content. For a URL source it fetches
// only when due (generation changed, no stored hash, or the refresh interval elapsed);
// otherwise it reuses the content already stored in a target ConfigMap.
func (r *CDBListReconciler) resolveContent(ctx context.Context, list *wazuhv1.WazuhCDBList) (string, bool, error) {
	switch {
	case len(list.Spec.Entries) > 0:
		entries := make([]cdblist.Entry, 0, len(list.Spec.Entries))
		for _, e := range list.Spec.Entries {
			entries = append(entries, cdblist.Entry{Key: e.Key, Value: e.Value})
		}
		return cdblist.RenderEntries(entries), false, nil

	case list.Spec.Content != "":
		return r.formatRaw(list.Spec.Content, list.Spec.Format, list.Spec.SkipLines), false, nil

	case list.Spec.Source != nil:
		if !r.shouldRefetch(ctx, list) {
			if existing, ok := r.readExistingContent(ctx, list); ok {
				return existing, false, nil
			}
		}
		raw, err := r.fetch(ctx, list)
		if err != nil {
			return "", false, err
		}
		return r.formatRaw(raw, list.Spec.Format, list.Spec.SkipLines), true, nil
	}

	return "", false, fmt.Errorf("no content source configured")
}

// formatRaw skips any header lines then applies the requested converter to raw content.
func (r *CDBListReconciler) formatRaw(raw string, format wazuhv1.CDBListFormat, skipLines int32) string {
	raw = cdblist.SkipLines(raw, int(skipLines))
	switch format {
	case wazuhv1.CDBListFormatIPList:
		return cdblist.IPListToCDB(raw)
	case wazuhv1.CDBListFormatKeyList:
		return cdblist.KeyListToCDB(raw)
	default:
		return cdblist.Normalize(raw)
	}
}

// shouldRefetch reports whether a URL source is due for a new fetch.
func (r *CDBListReconciler) shouldRefetch(ctx context.Context, list *wazuhv1.WazuhCDBList) bool {
	// Spec changed since last observed generation, or never fetched.
	if list.Status.ObservedGeneration != list.Generation || list.Status.ContentHash == "" || list.Status.LastFetchTime == nil {
		return true
	}
	interval := r.refreshInterval(list)
	if interval <= 0 {
		return false // fetch-once semantics
	}
	return time.Since(list.Status.LastFetchTime.Time) >= interval
}

// readExistingContent returns the stored list content from the first target ConfigMap.
func (r *CDBListReconciler) readExistingContent(ctx context.Context, list *wazuhv1.WazuhCDBList) (string, bool) {
	cmName := cdbListConfigMapName(list.Namespace, list.Name)
	for _, ref := range list.Spec.ClusterRefs {
		cm := &corev1.ConfigMap{}
		if err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, cm); err != nil {
			continue
		}
		if content, ok := cm.Data[cdbListDataKey(list.Spec.ListName)]; ok {
			return content, true
		}
	}
	return "", false
}

// fetch performs the HTTP GET for a URL source, applying optional headers and TLS settings.
func (r *CDBListReconciler) fetch(ctx context.Context, list *wazuhv1.WazuhCDBList) (string, error) {
	src := list.Spec.Source
	reqCtx, cancel := context.WithTimeout(ctx, cdbListFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, src.URL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request for %s: %w", src.URL, err)
	}

	if src.HeadersSecretRef != nil {
		headers, err := r.resolveHeaders(ctx, list.Namespace, src.HeadersSecretRef)
		if err != nil {
			return "", err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	httpClient := r.httpClientFor(src.InsecureSkipVerify)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch %s: %w", src.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch %s returned status %d", src.URL, resp.StatusCode)
	}

	// Cap the body to a sane size to avoid unbounded memory use (10 MiB).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read body from %s: %w", src.URL, err)
	}
	return string(body), nil
}

// resolveHeaders reads the header key/value pairs from the referenced Secret.
func (r *CDBListReconciler) resolveHeaders(ctx context.Context, crNamespace string, ref *wazuhv1.SecretReference) (map[string]string, error) {
	ns := ref.Namespace
	if ns == "" {
		ns = crNamespace
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ns}, secret); err != nil {
		return nil, fmt.Errorf("failed to get headers secret %s/%s: %w", ns, ref.Name, err)
	}
	headers := make(map[string]string, len(secret.Data))
	if ref.Key != "" {
		// Single header whose name is the key.
		val, ok := secret.Data[ref.Key]
		if !ok {
			return nil, fmt.Errorf("key %q not found in secret %s/%s", ref.Key, ns, ref.Name)
		}
		headers[ref.Key] = string(val)
		return headers, nil
	}
	for k, v := range secret.Data {
		headers[k] = string(v)
	}
	return headers, nil
}

// httpClientFor returns an HTTP client honoring the insecure TLS setting.
func (r *CDBListReconciler) httpClientFor(insecure bool) *http.Client {
	if r.HTTPClient != nil && !insecure {
		return r.HTTPClient
	}
	transport := &http.Transport{}
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - opt-in per source
	}
	return &http.Client{Timeout: cdbListFetchTimeout, Transport: transport}
}

// refreshInterval returns the effective periodic refresh interval for a URL source.
func (r *CDBListReconciler) refreshInterval(list *wazuhv1.WazuhCDBList) time.Duration {
	src := list.Spec.Source
	if src == nil {
		return 0
	}
	if src.RefreshInterval == nil {
		return defaultCDBListRefreshInterval
	}
	if src.RefreshInterval.Duration <= 0 {
		return 0 // fetch-once
	}
	return src.RefreshInterval.Duration
}

// reconcileListForCluster reconciles the list on a single target cluster.
func (r *CDBListReconciler) reconcileListForCluster(
	ctx context.Context,
	list *wazuhv1.WazuhCDBList,
	ref wazuhv1.WazuhClusterRef,
	content string,
	st *wazuhv1.CDBListClusterStatus,
) error {
	log := logf.FromContext(ctx).WithValues("cluster", ref.Name, "clusterNamespace", ref.Namespace)

	cluster := &wazuhv1.WazuhCluster{}
	clusterKeyNN := types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}
	if err := r.Get(ctx, clusterKeyNN, cluster); err != nil {
		if errors.IsNotFound(err) {
			st.Phase = wazuhv1.CDBListPhasePending
			st.Message = fmt.Sprintf("WazuhCluster %s not found", clusterKeyNN)
			if r.Recorder != nil {
				r.Recorder.Event(list, corev1.EventTypeWarning, "ClusterNotFound", st.Message)
			}
			return nil
		}
		st.Phase = wazuhv1.CDBListPhaseFailed
		st.Message = fmt.Sprintf("failed to get WazuhCluster: %v", err)
		return err
	}

	cmName, err := r.reconcileConfigMap(ctx, list, ref, content)
	if err != nil {
		st.Phase = wazuhv1.CDBListPhaseFailed
		st.Message = fmt.Sprintf("Failed to reconcile ConfigMap: %v", err)
		if r.Recorder != nil {
			r.Recorder.Event(list, corev1.EventTypeWarning, "ConfigMapFailed", err.Error())
		}
		return err
	}

	st.ConfigMapRef = &wazuhv1.ConfigMapReference{Name: cmName, Namespace: ref.Namespace}
	st.AppliedToNodes = r.determineAppliedNodes(list, cluster)

	wasApplied := st.Phase == wazuhv1.CDBListPhaseApplied
	st.Phase = wazuhv1.CDBListPhaseApplied
	st.Message = ""
	if !wasApplied {
		now := metav1.Now()
		st.LastAppliedTime = &now
		if r.Recorder != nil {
			r.Recorder.Event(list, corev1.EventTypeNormal, "ListApplied",
				fmt.Sprintf("CDB list %s applied to %s/%s", list.Name, ref.Namespace, ref.Name))
		}
	}
	log.V(1).Info("CDB list applied", "configMap", cmName)
	return nil
}

// cdbListConfigMapName returns the cross-namespace-safe ConfigMap name for the list on a given cluster.
func cdbListConfigMapName(crNamespace, crName string) string {
	return fmt.Sprintf("%s-%s-cdblist", crNamespace, crName)
}

// cdbListDataKey returns the ConfigMap data key (and mount subPath) for a list.
// It is the last path segment of listName, since ConfigMap keys cannot contain "/".
// For a top-level list this equals listName; for "malicious-ioc/malicious-ip" it is
// "malicious-ip". The file is still mounted at /var/ossec/etc/lists/<listName>.
func cdbListDataKey(listName string) string {
	if i := strings.LastIndex(listName, "/"); i >= 0 {
		return listName[i+1:]
	}
	return listName
}

// reconcileConfigMap creates/updates the list ConfigMap in the target cluster's namespace.
// The ConfigMap key is the list filename (no extension), matching the mount at
// /var/ossec/etc/lists/<listName>.
func (r *CDBListReconciler) reconcileConfigMap(
	ctx context.Context,
	list *wazuhv1.WazuhCDBList,
	ref wazuhv1.WazuhClusterRef,
	content string,
) (string, error) {
	log := logf.FromContext(ctx)
	cmName := cdbListConfigMapName(list.Namespace, list.Name)

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: ref.Namespace,
			Labels: map[string]string{
				constants.LabelName:          "wazuh-cdblist",
				constants.LabelInstance:      list.Name,
				constants.LabelManagedBy:     constants.OperatorName,
				constants.LabelComponent:     "cdblist",
				"wazuh.com/cluster":          ref.Name,
				labelCDBListCROwnerName:      list.Name,
				labelCDBListCROwnerNamespace: list.Namespace,
			},
		},
		Data: map[string]string{
			cdbListDataKey(list.Spec.ListName): content,
		},
	}

	existing := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, existing)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating CDB list ConfigMap", "name", cmName, "namespace", ref.Namespace)
		if err := r.Create(ctx, desired); err != nil {
			return "", err
		}
		return cmName, nil
	} else if err != nil {
		return "", err
	}

	if !mapsEqual(existing.Data, desired.Data) || !mapsEqual(existing.Labels, desired.Labels) {
		existing.Data = desired.Data
		existing.Labels = desired.Labels
		log.V(1).Info("Updating CDB list ConfigMap", "name", cmName, "namespace", ref.Namespace)
		if err := r.Update(ctx, existing); err != nil {
			return "", err
		}
	}
	return cmName, nil
}

// setCondition sets a status condition on the list.
func (r *CDBListReconciler) setCondition(list *wazuhv1.WazuhCDBList, conditionType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&list.Status.Conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: list.Generation,
		Reason:             reason,
		Message:            message,
	})
}

// updateStatus updates the list status with retry on conflict.
func (r *CDBListReconciler) updateStatus(ctx context.Context, list *wazuhv1.WazuhCDBList) error {
	desiredStatus := list.Status
	return utils.RetryOnConflict(ctx, func() error {
		latest := &wazuhv1.WazuhCDBList{}
		if err := r.Get(ctx, types.NamespacedName{Name: list.Name, Namespace: list.Namespace}, latest); err != nil {
			return err
		}
		if apiequality.Semantic.DeepEqual(latest.Status, desiredStatus) {
			return nil
		}
		latest.Status = desiredStatus
		if err := r.Status().Update(ctx, latest); err != nil {
			return err
		}
		list.Status = latest.Status
		return nil
	})
}

// determineAppliedNodes determines which manager nodes the list applies to.
func (r *CDBListReconciler) determineAppliedNodes(list *wazuhv1.WazuhCDBList, cluster *wazuhv1.WazuhCluster) []string {
	targetNodes := list.Spec.TargetNodes
	if targetNodes == "" {
		targetNodes = "all"
	}

	workerCount := int32(0)
	if cluster.Spec.Manager != nil && cluster.Spec.Manager.Workers.Replicas != nil {
		workerCount = *cluster.Spec.Manager.Workers.Replicas
	}

	var nodes []string
	if targetNodes == "master" || targetNodes == "all" {
		nodes = append(nodes, fmt.Sprintf("%s-manager-master-0", cluster.Name))
	}
	if targetNodes == "workers" || targetNodes == "all" {
		for i := int32(0); i < workerCount; i++ {
			nodes = append(nodes, fmt.Sprintf("%s-manager-worker-%d", cluster.Name, i))
		}
	}
	return nodes
}

// Delete handles cleanup when a list is deleted. Deletes the list ConfigMap from
// each target cluster's namespace (cross-NS, no ownerRef).
func (r *CDBListReconciler) Delete(ctx context.Context, list *wazuhv1.WazuhCDBList) error {
	log := logf.FromContext(ctx)
	cmName := cdbListConfigMapName(list.Namespace, list.Name)

	for _, ref := range list.Spec.ClusterRefs {
		cm := &corev1.ConfigMap{}
		err := r.Get(ctx, types.NamespacedName{Name: cmName, Namespace: ref.Namespace}, cm)
		if err == nil {
			if err := r.Client.Delete(ctx, cm); err != nil && !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete CDB list ConfigMap",
					"configMap", cmName, "namespace", ref.Namespace)
			}
		} else if !errors.IsNotFound(err) {
			log.Error(err, "Failed to lookup CDB list ConfigMap",
				"configMap", cmName, "namespace", ref.Namespace)
		}
	}

	if r.Recorder != nil {
		r.Recorder.Event(list, corev1.EventTypeNormal, "ListDeleted",
			fmt.Sprintf("CDB list %s deleted on all target clusters", list.Name))
	}
	return nil
}

// ListCDBListsForCluster lists all WazuhCDBLists targeting a specific cluster (cross-NS).
func (r *CDBListReconciler) ListCDBListsForCluster(ctx context.Context, clusterName, namespace string) ([]wazuhv1.WazuhCDBList, error) {
	listList := &wazuhv1.WazuhCDBListList{}
	if err := r.List(ctx, listList); err != nil {
		return nil, fmt.Errorf("failed to list WazuhCDBLists: %w", err)
	}

	var matching []wazuhv1.WazuhCDBList
	for _, l := range listList.Items {
		for _, ref := range l.Spec.ClusterRefs {
			if ref.Name == clusterName && ref.Namespace == namespace {
				matching = append(matching, l)
				break
			}
		}
	}
	return matching, nil
}

// CDBListConfigMapInfo holds information about a CDB list ConfigMap for mounting.
type CDBListConfigMapInfo struct {
	ConfigMapName string
	FileName      string // list path relative to etc/lists (may contain a subdir), used for the mount path and <list> entry
	Key           string // ConfigMap data key and mount subPath (basename of FileName)
	TargetNodes   string
	ListCRName    string
}

// GetCDBListConfigMapsForCluster returns ConfigMap references and a content hash for
// all CDB lists applied on a cluster. Only lists whose per-cluster status is Applied
// are returned so half-reconciled lists are not mounted.
func (r *CDBListReconciler) GetCDBListConfigMapsForCluster(ctx context.Context, clusterName, namespace string) ([]CDBListConfigMapInfo, string, error) {
	lists, err := r.ListCDBListsForCluster(ctx, clusterName, namespace)
	if err != nil {
		return nil, "", err
	}

	var configMaps []CDBListConfigMapInfo
	var hashInputs []string

	for _, l := range lists {
		applied := false
		for _, st := range l.Status.ClusterStatuses {
			if st.Name == clusterName && st.Namespace == namespace && st.Phase == wazuhv1.CDBListPhaseApplied && st.ConfigMapRef != nil {
				applied = true
				break
			}
		}
		if !applied {
			continue
		}

		configMaps = append(configMaps, CDBListConfigMapInfo{
			ConfigMapName: cdbListConfigMapName(l.Namespace, l.Name),
			FileName:      l.Spec.ListName,
			Key:           cdbListDataKey(l.Spec.ListName),
			TargetNodes:   l.Spec.TargetNodes,
			ListCRName:    l.Name,
		})
		hashInputs = append(hashInputs, l.Spec.ListName+"="+l.Status.ContentHash)
	}

	sort.Slice(configMaps, func(i, j int) bool {
		return configMaps[i].ListCRName < configMaps[j].ListCRName
	})
	sort.Strings(hashInputs)

	return configMaps, computeCDBListHash(joinStrings(hashInputs)), nil
}

// GetCDBListNamesForCluster returns the ossec.conf <list> paths (etc/lists/<name>) for
// all CDB lists applied on a cluster, so the operator can inject them into the manager
// ruleset configuration.
func (r *CDBListReconciler) GetCDBListNamesForCluster(ctx context.Context, clusterName, namespace string) ([]string, error) {
	infos, _, err := r.GetCDBListConfigMapsForCluster(ctx, clusterName, namespace)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(infos))
	for _, info := range infos {
		names = append(names, "etc/lists/"+info.FileName)
	}
	sort.Strings(names)
	return names, nil
}

// computeCDBListHash computes a short hash of the given content for change detection.
func computeCDBListHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])[:16]
}

// joinStrings concatenates strings with a newline separator.
func joinStrings(items []string) string {
	out := ""
	for _, s := range items {
		out += s + "\n"
	}
	return out
}
