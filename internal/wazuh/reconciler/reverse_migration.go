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
	"fmt"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// vctNameSet returns the set of VolumeClaimTemplate names in a StatefulSet.
func vctNameSet(sts *appsv1.StatefulSet) map[string]struct{} {
	m := make(map[string]struct{}, len(sts.Spec.VolumeClaimTemplates))
	for _, v := range sts.Spec.VolumeClaimTemplates {
		m[v.Name] = struct{}{}
	}
	return m
}

// parsePVCName splits a StatefulSet PVC name "<vct>-<sts>-<ordinal>" into its VCT name and
// ordinal. Returns ok=false when the name does not match the expected shape.
func parsePVCName(pvcName, stsName string) (vct string, ordinal int, ok bool) {
	sep := "-" + stsName + "-"
	idx := strings.LastIndex(pvcName, sep)
	if idx <= 0 {
		return "", 0, false
	}
	ord, err := strconv.Atoi(pvcName[idx+len(sep):])
	if err != nil {
		return "", 0, false
	}
	return pvcName[:idx], ord, true
}

// deriveSubPathForVCT is the fallback (used when the PVC lost its subPath annotation) mapping
// a dedicated VCT name back to the wazuh-data subPath it was carved from.
func deriveSubPathForVCT(vct string) string {
	rel := strings.TrimPrefix(vct, constants.VolumeNameWazuhData+"-")
	return "wazuh/" + strings.ReplaceAll(rel, "-", "/")
}

// reverseMigrationJobName derives a DNS-1123, <=63 char Job name for an orphaned PVC.
func reverseMigrationJobName(pvcName string) string {
	name := "revmig-" + pvcName
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

// reconcileReverseMigration copies the data of any orphaned per-path PVC (a PVC whose
// VolumeClaimTemplate is no longer part of the desired StatefulSet) back into the default
// wazuh-data volume, then deletes the orphaned PVC. It runs while the StatefulSet is absent
// (during a recreation window) so the PVCs are detached and a migration Job can mount them.
// Returns done=true only when no orphaned PVC remains to process.
func (r *ClusterReconciler) reconcileReverseMigration(ctx context.Context, cluster *wazuhv1.WazuhCluster, stsName string, desiredVCTs map[string]struct{}) (bool, error) {
	log := logf.FromContext(ctx)

	// List PVCs by the instance label and filter by name (<vct>-<stsName>-<ordinal>). This is
	// robust to the component-label variations across manager PVCs.
	pvcList := &corev1.PersistentVolumeClaimList{}
	if err := r.List(ctx, pvcList,
		client.InNamespace(cluster.Namespace),
		client.MatchingLabels{constants.LabelInstance: cluster.Name},
	); err != nil {
		return false, fmt.Errorf("list PVCs for reverse migration: %w", err)
	}

	allDone := true

	for i := range pvcList.Items {
		pvc := &pvcList.Items[i]
		vct, ordinal, ok := parsePVCName(pvc.Name, stsName)
		if !ok || vct == constants.VolumeNameWazuhData {
			continue // unrelated PVC or the default volume (never an orphan)
		}
		if _, wanted := desiredVCTs[vct]; wanted {
			continue // still declared in the spec
		}

		// Orphan: a per-path PVC removed from the spec. Migrate its data back into wazuh-data.
		subPath := pvc.Annotations[constants.AnnotationVolumeSubPath]
		if subPath == "" {
			subPath = deriveSubPathForVCT(vct)
		}
		sibling := fmt.Sprintf("%s-%s-%d", constants.VolumeNameWazuhData, stsName, ordinal)
		jobName := reverseMigrationJobName(pvc.Name)

		job := &batchv1.Job{}
		err := r.Get(ctx, types.NamespacedName{Name: jobName, Namespace: cluster.Namespace}, job)
		switch {
		case apierrors.IsNotFound(err):
			newJob := r.buildReverseMigrationJob(cluster, jobName, pvc.Name, sibling, subPath)
			if cerr := controllerutil.SetControllerReference(cluster, newJob, r.Scheme); cerr != nil {
				return false, fmt.Errorf("set owner on reverse-migration job: %w", cerr)
			}
			if cerr := r.Create(ctx, newJob); cerr != nil && !apierrors.IsAlreadyExists(cerr) {
				return false, fmt.Errorf("create reverse-migration job for %s: %w", pvc.Name, cerr)
			}
			log.Info("Started reverse migration for orphaned PVC", "pvc", pvc.Name, "subPath", subPath)
			allDone = false
		case err != nil:
			return false, fmt.Errorf("get reverse-migration job %s: %w", jobName, err)
		case job.Status.Succeeded > 0:
			// Data copied back: delete the orphaned PVC and the completed Job.
			if derr := r.Delete(ctx, pvc); derr != nil && !apierrors.IsNotFound(derr) {
				return false, fmt.Errorf("delete orphaned PVC %s: %w", pvc.Name, derr)
			}
			bg := metav1.DeletePropagationBackground
			_ = r.Delete(ctx, job, &client.DeleteOptions{PropagationPolicy: &bg})
			log.Info("Reverse migration complete; deleted orphaned PVC", "pvc", pvc.Name)
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeNormal, constants.EventReasonReverseMigration,
					fmt.Sprintf("Migrated %s back into %s and removed the orphaned PVC", pvc.Name, sibling))
			}
		case job.Status.Failed > 0:
			// Keep the PVC for manual recovery; surface the failure and keep waiting.
			log.Info("Reverse migration job failed; keeping orphaned PVC", "pvc", pvc.Name, "job", jobName)
			if r.Recorder != nil {
				r.Recorder.Event(cluster, corev1.EventTypeWarning, constants.EventReasonReverseMigrationFailed,
					fmt.Sprintf("Reverse migration job %s failed; orphaned PVC %s kept for manual recovery", jobName, pvc.Name))
			}
			allDone = false
		default:
			allDone = false // job still running
		}
	}

	return allDone, nil
}

// buildReverseMigrationJob builds the one-shot Job that copies srcPVC's content into dstPVC
// (the wazuh-data volume) at the recorded subPath. It mounts both PVCs whole; both are
// detached because the StatefulSet is absent during the recreation window.
func (r *ClusterReconciler) buildReverseMigrationJob(cluster *wazuhv1.WazuhCluster, jobName, srcPVC, dstPVC, subPath string) *batchv1.Job {
	backoff := int32(2)
	ttl := int32(3600)
	script := fmt.Sprintf(`set -eu
mkdir -p "/dst/%[1]s"
cp -a /src/. "/dst/%[1]s/"
chown -R 999:999 "/dst/%[1]s"
echo "reverse-migration: copied /src -> /dst/%[1]s"`, subPath)

	labels := map[string]string{
		constants.LabelInstance:  cluster.Name,
		constants.LabelManagedBy: "wazuh-operator",
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: jobName, Namespace: cluster.Namespace, Labels: labels},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoff,
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{{
						Name:    "reverse-migrate",
						Image:   constants.ImageBusyboxInit,
						Command: []string{"/bin/sh", "-c", script},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "src", MountPath: "/src"},
							{Name: "dst", MountPath: "/dst"},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "src", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: srcPVC}}},
						{Name: "dst", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: dstPVC}}},
					},
				},
			},
		},
	}
}
