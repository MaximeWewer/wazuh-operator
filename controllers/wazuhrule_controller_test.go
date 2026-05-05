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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	wazuhreconciler "github.com/MaximeWewer/wazuh-operator/internal/wazuh/reconciler"
)

var _ = Describe("WazuhRule Controller", func() {
	Context("When creating a WazuhRule (Story 1.8)", func() {
		const (
			timeout  = time.Minute * 2
			interval = time.Second * 1
		)

		var (
			ctx              context.Context
			namespace        string
			clusterName      string
			ruleName         string
			cluster          *wazuhv1.WazuhCluster
			rule             *wazuhv1.WazuhRule
			ruleReconciler   *WazuhRuleReconciler
			reconcileRequest reconcile.Request
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = fmt.Sprintf("test-rule-%d-%s", GinkgoRandomSeed(), randStringRunes(6))
			clusterName = "test-cluster"
			ruleName = "test-ssh-rule"

			// Create namespace
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}
			Expect(k8sClient.Create(ctx, ns)).To(Succeed())

			// Create WazuhCluster CR (required reference for WazuhRule)
			cluster = &wazuhv1.WazuhCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clusterName,
					Namespace: namespace,
				},
				Spec: wazuhv1.WazuhClusterSpec{
					Version: "4.9.2",
					Manager: &wazuhv1.WazuhManagerClusterSpec{
						Master: wazuhv1.WazuhMasterSpec{
							Resources: &corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
							},
							StorageSize: "10Gi",
						},
						Workers: wazuhv1.WazuhWorkerSpec{
							Replicas: int32Ptr(0),
						},
					},
					Indexer: &wazuhv1.WazuhIndexerClusterSpec{
						Replicas: 1,
						Resources: &corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("512Mi"),
							},
						},
						StorageSize: "10Gi",
					},
					Dashboard: &wazuhv1.WazuhDashboardClusterSpec{
						Replicas: 1,
						Resources: &corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("512Mi"),
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

			// Create test event recorder
			eventRecorder := record.NewFakeRecorder(100)

			// Initialize WazuhRule reconciler
			ruleReconciler = &WazuhRuleReconciler{
				Client:         k8sClient,
				Scheme:         scheme.Scheme,
				Recorder:       eventRecorder,
				RuleReconciler: wazuhreconciler.NewRuleReconciler(k8sClient, scheme.Scheme, eventRecorder),
			}

			reconcileRequest = reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      ruleName,
					Namespace: namespace,
				},
			}
		})

		AfterEach(func() {
			// Cleanup rule
			if rule != nil {
				_ = k8sClient.Delete(ctx, rule)
			}
			// Cleanup cluster
			if cluster != nil {
				_ = k8sClient.Delete(ctx, cluster)
			}
			// Cleanup namespace
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}
			_ = k8sClient.Delete(ctx, ns)
		})

		It("should create a ConfigMap for valid rule content", func() {
			By("Creating a WazuhRule with valid XML content")
			rule = &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ruleName,
					Namespace: namespace,
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRefs: []wazuhv1.WazuhClusterRef{
						{Name: clusterName, Namespace: namespace},
					},
					RuleName:    "ssh_custom",
					Description: "Custom SSH brute force detection",
					RuleID:      100001,
					TargetNodes: "all",
					Rules: `<group name="sshd,authentication_failed">
  <rule id="100001" level="10" frequency="5" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>SSH brute force attack detected</description>
  </rule>
</group>`,
				},
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())

			By("Reconciling the WazuhRule")
			// First reconcile adds finalizer
			_, err := ruleReconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())
			// Second reconcile does actual work (creates ConfigMap)
			_, err = ruleReconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Checking the ConfigMap was created in the target cluster's namespace")
			configMap := &corev1.ConfigMap{}
			configMapName := fmt.Sprintf("%s-%s-rule", namespace, ruleName)
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      configMapName,
					Namespace: namespace,
				}, configMap)
			}, timeout, interval).Should(Succeed())

			Expect(configMap.Data).To(HaveKey("ssh_custom.xml"))
			Expect(configMap.Data["ssh_custom.xml"]).To(ContainSubstring("SSH brute force attack detected"))

			By("Checking the rule status was updated")
			updatedRule := &wazuhv1.WazuhRule{}
			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      ruleName,
					Namespace: namespace,
				}, updatedRule)
				if err != nil {
					return ""
				}
				return string(updatedRule.Status.Phase)
			}, timeout, interval).Should(Equal(string(wazuhv1.RulePhaseApplied)))

			Expect(updatedRule.Status.ClusterStatuses).To(HaveLen(1))
			Expect(updatedRule.Status.ClusterStatuses[0].ConfigMapRef).NotTo(BeNil())
			Expect(updatedRule.Status.ClusterStatuses[0].ConfigMapRef.Name).To(Equal(configMapName))
		})

		It("should fail validation for invalid XML content", func() {
			By("Creating a WazuhRule with invalid XML")
			rule = &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ruleName,
					Namespace: namespace,
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRefs: []wazuhv1.WazuhClusterRef{
						{Name: clusterName, Namespace: namespace},
					},
					RuleName: "invalid_rule",
					Rules:    "this is not xml at all",
				},
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())

			By("Reconciling the WazuhRule")
			// First reconcile adds finalizer
			_, err := ruleReconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())
			// Second reconcile does actual work (validation happens here)
			_, err = ruleReconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Checking the rule status shows validation failed")
			updatedRule := &wazuhv1.WazuhRule{}
			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      ruleName,
					Namespace: namespace,
				}, updatedRule)
				if err != nil {
					return ""
				}
				return string(updatedRule.Status.Phase)
			}, timeout, interval).Should(Equal(string(wazuhv1.RulePhaseFailed)))

			Expect(updatedRule.Status.ValidationErrors).NotTo(BeEmpty())
		})

		It("should fail validation for rule ID outside custom range at API level", func() {
			By("Creating a WazuhRule with invalid rule ID")
			// Note: The CRD has kubebuilder validation (minimum: 100000) that rejects
			// invalid rule IDs at the API level before the controller sees them.
			invalidRule := &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ruleName,
					Namespace: namespace,
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRefs: []wazuhv1.WazuhClusterRef{
						{Name: clusterName, Namespace: namespace},
					},
					RuleName: "invalid_id_rule",
					RuleID:   5000, // Outside custom range (100000-999999)
					Rules: `<group name="test">
  <rule id="5000" level="5">
    <description>Rule with invalid ID</description>
  </rule>
</group>`,
				},
			}

			By("Expecting the API server to reject the invalid rule ID")
			err := k8sClient.Create(ctx, invalidRule)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("should be greater than or equal to 100000"))
		})

		It("should set Pending phase when referenced cluster doesn't exist", func() {
			By("Creating a WazuhRule referencing non-existent cluster")
			rule = &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ruleName,
					Namespace: namespace,
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRefs: []wazuhv1.WazuhClusterRef{
						{Name: "non-existent-cluster", Namespace: namespace},
					},
					RuleName: "orphan_rule",
					RuleID:   100001,
					Rules: `<group name="test">
  <rule id="100001" level="5">
    <description>Test rule</description>
  </rule>
</group>`,
				},
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())

			By("Reconciling the WazuhRule")
			// First reconcile adds finalizer
			_, err := ruleReconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())
			// Second reconcile checks cluster reference (sets Pending)
			_, err = ruleReconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Checking the rule status shows pending")
			updatedRule := &wazuhv1.WazuhRule{}
			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      ruleName,
					Namespace: namespace,
				}, updatedRule)
				if err != nil {
					return ""
				}
				return string(updatedRule.Status.Phase)
			}, timeout, interval).Should(Equal(string(wazuhv1.RulePhasePending)))
		})

		It("should add finalizer to new rules", func() {
			By("Creating a WazuhRule")
			rule = &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ruleName,
					Namespace: namespace,
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRefs: []wazuhv1.WazuhClusterRef{
						{Name: clusterName, Namespace: namespace},
					},
					RuleName: "finalizer_test",
					RuleID:   100001,
					Rules: `<group name="test">
  <rule id="100001" level="5">
    <description>Test rule</description>
  </rule>
</group>`,
				},
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())

			By("Reconciling the WazuhRule (first reconcile adds finalizer)")
			_, err := ruleReconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Checking the finalizer was added")
			updatedRule := &wazuhv1.WazuhRule{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      ruleName,
					Namespace: namespace,
				}, updatedRule)
				if err != nil {
					return false
				}
				for _, f := range updatedRule.Finalizers {
					if f == wazuhreconciler.RuleFinalizer {
						return true
					}
				}
				return false
			}, timeout, interval).Should(BeTrue())
		})

		It("should correctly determine applied nodes for master-only target", func() {
			By("Creating a WazuhRule targeting only master")
			rule = &wazuhv1.WazuhRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ruleName,
					Namespace: namespace,
				},
				Spec: wazuhv1.WazuhRuleSpec{
					ClusterRefs: []wazuhv1.WazuhClusterRef{
						{Name: clusterName, Namespace: namespace},
					},
					RuleName:    "master_only_rule",
					RuleID:      100001,
					TargetNodes: "master",
					Rules: `<group name="test">
  <rule id="100001" level="5">
    <description>Test rule for master only</description>
  </rule>
</group>`,
				},
			}
			Expect(k8sClient.Create(ctx, rule)).To(Succeed())

			By("Reconciling the WazuhRule twice (first adds finalizer, second does actual work)")
			_, err := ruleReconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())
			_, err = ruleReconciler.Reconcile(ctx, reconcileRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Checking the applied nodes include only master")
			updatedRule := &wazuhv1.WazuhRule{}
			Eventually(func() []string {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      ruleName,
					Namespace: namespace,
				}, updatedRule)
				if err != nil || len(updatedRule.Status.ClusterStatuses) == 0 {
					return nil
				}
				return updatedRule.Status.ClusterStatuses[0].AppliedToNodes
			}, timeout, interval).Should(ContainElement(fmt.Sprintf("%s-manager-master-0", clusterName)))

			Expect(updatedRule.Status.ClusterStatuses[0].AppliedToNodes).To(HaveLen(1))
		})
	})
})
