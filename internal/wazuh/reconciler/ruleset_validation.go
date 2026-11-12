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
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
	"github.com/MaximeWewer/wazuh-operator/pkg/constants"
)

// RulesetAPIFactory returns the API a cluster's rule and decoder files are validated with.
type RulesetAPIFactory func(ctx context.Context, c client.Client, cluster *wazuhv1.WazuhCluster) (RulesetValidationAPI, error)

// clusterRulesetAPI is the RulesetAPIFactory of the cluster's Wazuh API.
func clusterRulesetAPI(ctx context.Context, c client.Client, cluster *wazuhv1.WazuhCluster) (RulesetValidationAPI, error) {
	return buildWazuhAPIClient(ctx, c, cluster)
}

// validateContentForCluster validates the rule or decoder file content the ConfigMap cmName
// is about to hold for a cluster (see validateRulesetFile). Content the ConfigMap already
// holds was validated when written; it is the version restored when the new one is
// rejected. A cluster whose master StatefulSet does not exist yet
// has no manager to validate against: its managers load the content on their first start.
func validateContentForCluster(ctx context.Context, c client.Client, factory RulesetAPIFactory, cluster *wazuhv1.WazuhCluster,
	cmName string, kind adapters.RulesetKind, filename, content string) error {
	cm := &corev1.ConfigMap{}
	err := c.Get(ctx, types.NamespacedName{Name: cmName, Namespace: cluster.Namespace}, cm)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	installed, hasInstalled := "", false
	if err == nil {
		installed, hasInstalled = cm.Data[filename]
	}
	if hasInstalled && installed == content {
		return nil
	}
	master := &appsv1.StatefulSet{}
	err = c.Get(ctx, types.NamespacedName{Name: constants.ManagerMasterName(cluster.Name), Namespace: cluster.Namespace}, master)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if factory == nil {
		factory = clusterRulesetAPI
	}
	api, err := factory(ctx, c, cluster)
	if err != nil {
		return err
	}
	return validateRulesetFile(ctx, api, clusterKey(cluster.Name, cluster.Namespace), kind, filename, content, installed, hasInstalled)
}

// RulesetValidationAPI is the part of the Wazuh API a rule or decoder file is validated with.
type RulesetValidationAPI interface {
	GetRulesetFile(ctx context.Context, kind adapters.RulesetKind, filename string) (string, error)
	UploadRulesetFile(ctx context.Context, kind adapters.RulesetKind, filename, content string) error
	DeleteRulesetFile(ctx context.Context, kind adapters.RulesetKind, filename string) error
	ValidateConfiguration(ctx context.Context) error
}

// RulesetRejectedError carries the Wazuh message of a rule or decoder file the managers
// would not load (e.g. "(2101): Parent decoder name invalid").
type RulesetRejectedError struct {
	Message string
}

func (e *RulesetRejectedError) Error() string {
	return "Wazuh rejected the file: " + e.Message
}

// rulesetValidationLocks serializes the validations of one cluster: a file uploaded for
// validation is on the master until it is restored, and would fail the validation of
// another file running at the same time.
var rulesetValidationLocks sync.Map // cluster key -> *sync.Mutex

// ErrRulesetRestoreFailed reports a validation that could not put the master's file back
// to the installed version: retried soon, and the next attempt repairs the file first.
var ErrRulesetRestoreFailed = errors.New("could not restore the ruleset file on the master")

// validateRulesetFile writes candidate to etc/<kind>/<filename> on the master and checks
// that the managers would load the resulting ruleset (see ValidateConfiguration, the check
// analysisd runs at startup). installed is the version the managers run (the ConfigMap content, "" when hasInstalled is false): a
// rejected candidate is replaced by it, or removed, and a *RulesetRejectedError carries the
// Wazuh message. The candidate then never reaches the ConfigMap the manager pods install
// their files from, so a pod never starts on it and stops (1202).
//
// The master's file is first brought back to installed when it differs (a validation
// whose restore failed, or a manual edit), so the current configuration is judged on what
// the managers run. When that configuration is already invalid, the candidate cannot be
// judged and an error names the existing failure.
func validateRulesetFile(ctx context.Context, api RulesetValidationAPI, clusterKey string, kind adapters.RulesetKind,
	filename, candidate, installed string, hasInstalled bool) error {
	lock, _ := rulesetValidationLocks.LoadOrStore(clusterKey, &sync.Mutex{})
	mu, _ := lock.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	restore := func() error {
		var err error
		if hasInstalled {
			err = api.UploadRulesetFile(ctx, kind, filename, installed)
		} else {
			err = api.DeleteRulesetFile(ctx, kind, filename)
		}
		if err != nil {
			return fmt.Errorf("%w %s/%s: %w", ErrRulesetRestoreFailed, kind, filename, err)
		}
		return nil
	}

	served, err := api.GetRulesetFile(ctx, kind, filename)
	exists := err == nil
	if err != nil && !errors.Is(err, adapters.ErrRulesetFileNotFound) {
		return err
	}
	if exists != hasInstalled || (exists && served != installed) {
		logf.FromContext(ctx).Info("Restoring the installed version of the ruleset file on the master", "kind", kind, "file", filename)
		if err := restore(); err != nil {
			return err
		}
	}
	if err := api.ValidateConfiguration(ctx); err != nil {
		if errors.Is(err, adapters.ErrInvalidConfiguration) {
			return fmt.Errorf("cannot validate %s/%s, the managers' configuration is already invalid: %w", kind, filename, err)
		}
		return err
	}

	// Upload the candidate as a new file: over an existing one, the API restores the
	// previous file itself when the managers reject the candidate and only answers "XML
	// syntax error", which hides the reason the validation below reports.
	if hasInstalled {
		if err := api.DeleteRulesetFile(ctx, kind, filename); err != nil {
			return err
		}
	}
	uploadErr := api.UploadRulesetFile(ctx, kind, filename, candidate)
	var validationErr error
	if !IsAPIUnavailable(uploadErr) {
		validationErr = api.ValidateConfiguration(ctx)
	}
	if uploadErr == nil && validationErr == nil {
		return nil
	}

	// Rejected, or not judged: put the installed version back either way.
	if err := restore(); err != nil {
		return err
	}
	switch {
	case errors.Is(validationErr, adapters.ErrInvalidConfiguration):
		return &RulesetRejectedError{Message: wazuhMessage(validationErr)}
	case validationErr != nil:
		return validationErr
	default:
		// Not judged: the API was unavailable, or the upload failed for another reason
		// (e.g. the file is still a read-only mount while the managers roll out): retry.
		return uploadErr
	}
}

// wazuhMessage returns the Wazuh part of a validation error.
func wazuhMessage(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, adapters.ErrInvalidConfiguration.Error()+": "); i >= 0 {
		return msg[i+len(adapters.ErrInvalidConfiguration.Error())+2:]
	}
	return msg
}

// singleConfigMapEntry returns the file name and content of a rule or decoder ConfigMap,
// which holds one file.
func singleConfigMapEntry(cm *corev1.ConfigMap) (string, string) {
	for name, content := range cm.Data {
		return name, content
	}
	return "", ""
}

// computeContentHash returns a short hash of a file content for change detection.
func computeContentHash(content string) string {
	return computeCDBListHash(content)
}
