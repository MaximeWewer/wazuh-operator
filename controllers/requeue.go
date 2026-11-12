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
