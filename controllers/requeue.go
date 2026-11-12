package controllers

import (
	"errors"
	"math/rand/v2"
	"time"

	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
)

func apiUnavailableRequeue() time.Duration {
	return 30*time.Second + rand.N(15*time.Second) //nolint:gosec // jitter does not need crypto randomness
}

// contentReleaseRequeue is how often the deletion of a resource whose ConfigMap the manager
// StatefulSets still mount is retried.
const contentReleaseRequeue = 15 * time.Second

// contentStillMounted reports whether a cleanup waits for the manager StatefulSets to stop
// mounting the resource's ConfigMap: not a failure, the finalizer stays until they do.
func contentStillMounted(err error) bool {
	return errors.Is(err, wazuhreconciler.ErrContentStillMounted)
}

// rulesetRejectedRequeue is when a rule or decoder the managers rejected is validated
// again: a dependency (e.g. its parent decoder) may have been added meanwhile, and a spec
// change is reconciled right away anyway.
const rulesetRejectedRequeue = 5 * time.Minute

// rulesetRequeue returns when to retry a rule or decoder whose validation against the
// managers did not complete, and false for any other error (reported, with back-off).
func rulesetRequeue(err error) (time.Duration, bool) {
	var rejected *wazuhreconciler.RulesetRejectedError
	switch {
	case errors.As(err, &rejected):
		return rulesetRejectedRequeue, true
	case wazuhreconciler.IsAPIUnavailable(err), errors.Is(err, wazuhreconciler.ErrRulesetRestoreFailed):
		return apiUnavailableRequeue(), true
	}
	return 0, false
}
