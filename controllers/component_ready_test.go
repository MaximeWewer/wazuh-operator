package controllers

import (
	"testing"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// TestComponentNotReady guards the WazuhCluster Ready condition: it was reported true while
// the indexer StatefulSet had just been created and had no pod yet (0 ready of 0 observed).
func TestComponentNotReady(t *testing.T) {
	for name, tt := range map[string]struct {
		status   wazuhv1.ComponentStatus
		notReady bool
	}{
		"no pod yet":              {wazuhv1.ComponentStatus{Replicas: 0, ReadyReplicas: 0, DesiredReplicas: 1}, true},
		"no pod, desired unknown": {wazuhv1.ComponentStatus{}, true},
		"scaling up":              {wazuhv1.ComponentStatus{Replicas: 2, ReadyReplicas: 2, DesiredReplicas: 3}, true},
		"pod starting":            {wazuhv1.ComponentStatus{Replicas: 1, ReadyReplicas: 0, DesiredReplicas: 1}, true},
		"all ready":               {wazuhv1.ComponentStatus{Replicas: 3, ReadyReplicas: 3, DesiredReplicas: 3}, false},
		"scaling down":            {wazuhv1.ComponentStatus{Replicas: 3, ReadyReplicas: 2, DesiredReplicas: 2}, true},
	} {
		if got := componentNotReady(&tt.status); got != tt.notReady {
			t.Errorf("%s: componentNotReady() = %v, want %v", name, got, tt.notReady)
		}
	}
}
