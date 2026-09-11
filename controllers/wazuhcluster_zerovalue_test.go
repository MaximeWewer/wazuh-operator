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

package controllers

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

// An explicit false on a defaulted field used to be lost the moment the
// operator wrote the CR back (it adds its finalizer on the first reconcile):
// `omitempty` dropped the zero value from the request body and the API server
// re-applied +kubebuilder:default=true. GitOps kept re-applying false, the
// operator kept turning it back into true, and nothing reported the drift.
var _ = Describe("WazuhCluster defaulted fields", func() {
	var (
		ctx       context.Context
		namespace string
		cluster   *wazuhv1.WazuhCluster
	)

	BeforeEach(func() {
		ctx = context.Background()
		namespace = fmt.Sprintf("test-%d-%s", GinkgoRandomSeed(), randStringRunes(6))
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace},
		})).To(Succeed())

		cluster = &wazuhv1.WazuhCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "zero-value-cluster", Namespace: namespace},
			Spec: wazuhv1.WazuhClusterSpec{
				Version: "4.9.2",
				Dashboard: &wazuhv1.WazuhDashboardClusterSpec{
					Replicas:  1,
					EnableSSL: new(false),
				},
			},
		}
	})

	AfterEach(func() {
		if cluster != nil {
			_ = k8sClient.Delete(ctx, cluster)
		}
		_ = k8sClient.Delete(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace},
		})
	})

	It("Should keep dashboard.enableSSL=false across a write-back of the CR", func() {
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		key := types.NamespacedName{Name: cluster.Name, Namespace: namespace}
		stored := &wazuhv1.WazuhCluster{}
		Expect(k8sClient.Get(ctx, key, stored)).To(Succeed())
		Expect(stored.Spec.Dashboard.EnableSSL).To(HaveValue(BeFalse()), "false must survive creation")

		// What the reconciler does on its first pass: take the object it just
		// read and write it straight back with a finalizer attached.
		stored.Finalizers = append(stored.Finalizers, "wazuh.io/test-writeback")
		Expect(k8sClient.Update(ctx, stored)).To(Succeed())

		reread := &wazuhv1.WazuhCluster{}
		Expect(k8sClient.Get(ctx, key, reread)).To(Succeed())
		Expect(reread.Spec.Dashboard.EnableSSL).To(HaveValue(BeFalse()), "false must survive the write-back")

		// Drop the finalizer again so the namespace teardown can complete.
		reread.Finalizers = nil
		Expect(k8sClient.Update(ctx, reread)).To(Succeed())
	})

	It("Should still default dashboard.enableSSL to true when unset", func() {
		cluster.Spec.Dashboard.EnableSSL = nil
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		stored := &wazuhv1.WazuhCluster{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: cluster.Name, Namespace: namespace}, stored)).To(Succeed())
		Expect(stored.Spec.Dashboard.EnableSSL).To(HaveValue(BeTrue()))
	})
})
