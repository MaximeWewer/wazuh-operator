package reconciler

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// TestRBACStatusReportsEffectiveName guards the kubectl printer columns of WazuhRole and
// WazuhUser: they read the effective name from the status, which must fall back to
// metadata.name when spec.roleName / spec.username is omitted (the column was empty).
func TestRBACStatusReportsEffectiveName(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = wazuhv1.AddToScheme(scheme)
	refs := []wazuhv1.WazuhClusterRef{{Name: "missing", Namespace: "ns"}}

	t.Run("role", func(t *testing.T) {
		for _, tt := range []struct{ specName, want string }{{"", "soc-viewer"}, {"custom", "custom"}} {
			role := &wazuhv1.WazuhRole{
				ObjectMeta: metav1.ObjectMeta{Name: "soc-viewer", Namespace: "ns"},
				Spec:       wazuhv1.WazuhRoleSpec{ClusterRefs: refs, RoleName: tt.specName},
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(role).
				WithStatusSubresource(&wazuhv1.WazuhRole{}).Build()
			_ = NewWazuhAPIRoleReconciler(c, scheme, nil).Reconcile(context.Background(), role)
			if role.Status.RoleName != tt.want {
				t.Errorf("spec.roleName=%q: status.roleName = %q, want %q", tt.specName, role.Status.RoleName, tt.want)
			}
		}
	})

	t.Run("user", func(t *testing.T) {
		for _, tt := range []struct{ specName, want string }{{"", "analyst"}, {"custom", "custom"}} {
			user := &wazuhv1.WazuhUser{
				ObjectMeta: metav1.ObjectMeta{Name: "analyst", Namespace: "ns"},
				Spec:       wazuhv1.WazuhUserSpec{ClusterRefs: refs, Username: tt.specName},
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(user).
				WithStatusSubresource(&wazuhv1.WazuhUser{}).Build()
			_ = NewWazuhAPIUserReconciler(c, scheme, nil).Reconcile(context.Background(), user)
			if user.Status.Username != tt.want {
				t.Errorf("spec.username=%q: status.username = %q, want %q", tt.specName, user.Status.Username, tt.want)
			}
		}
	})
}
