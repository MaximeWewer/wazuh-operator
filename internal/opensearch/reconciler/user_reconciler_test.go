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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
)

func TestUserReconciler_getPassword(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = wazuhv1.AddToScheme(scheme)

	tests := []struct {
		name       string
		user       *wazuhv1.OpenSearchUser
		secret     *corev1.Secret
		wantErr    bool
		wantPasswd string
	}{
		{
			name: "password from hash field",
			user: &wazuhv1.OpenSearchUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-user",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchUserSpec{
					Hash: "$2y$12$hashedpassword",
				},
			},
			wantErr:    false,
			wantPasswd: "$2y$12$hashedpassword",
		},
		{
			name: "password from secret with default key",
			user: &wazuhv1.OpenSearchUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-user",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchUserSpec{
					PasswordSecret: &wazuhv1.CredentialsSecretRef{
						SecretName: "user-password-secret",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "user-password-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"password": []byte("secretpassword"),
				},
			},
			wantErr:    false,
			wantPasswd: "secretpassword",
		},
		{
			name: "password from secret with custom key",
			user: &wazuhv1.OpenSearchUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-user",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchUserSpec{
					PasswordSecret: &wazuhv1.CredentialsSecretRef{
						SecretName:  "user-password-secret",
						PasswordKey: "custom-key",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "user-password-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"custom-key": []byte("custompassword"),
				},
			},
			wantErr:    false,
			wantPasswd: "custompassword",
		},
		{
			name: "error when no password source",
			user: &wazuhv1.OpenSearchUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-user",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchUserSpec{},
			},
			wantErr: true,
		},
		{
			name: "error when secret not found",
			user: &wazuhv1.OpenSearchUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-user",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchUserSpec{
					PasswordSecret: &wazuhv1.CredentialsSecretRef{
						SecretName: "nonexistent-secret",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "error when secret key not found",
			user: &wazuhv1.OpenSearchUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-user",
					Namespace: "default",
				},
				Spec: wazuhv1.OpenSearchUserSpec{
					PasswordSecret: &wazuhv1.CredentialsSecretRef{
						SecretName:  "user-password-secret",
						PasswordKey: "wrong-key",
					},
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "user-password-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"password": []byte("secretpassword"),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			if tt.secret != nil {
				objs = append(objs, tt.secret)
			}
			client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
			recorder := record.NewFakeRecorder(10)

			r := NewUserReconciler(client, scheme, recorder)

			got, err := r.getPassword(context.Background(), tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.wantPasswd {
				t.Errorf("getPassword() = %v, want %v", got, tt.wantPasswd)
			}
		})
	}
}

func TestUserReconciler_recordEvent(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = wazuhv1.AddToScheme(scheme)

	tests := []struct {
		name         string
		recorder     record.EventRecorder
		user         *wazuhv1.OpenSearchUser
		eventType    string
		reason       string
		message      string
		expectEvents int
	}{
		{
			name:     "records event when recorder is available",
			recorder: record.NewFakeRecorder(10),
			user: &wazuhv1.OpenSearchUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-user",
					Namespace: "default",
				},
			},
			eventType:    corev1.EventTypeNormal,
			reason:       "Synced",
			message:      "User synchronized",
			expectEvents: 1,
		},
		{
			name:     "no panic when recorder is nil",
			recorder: nil,
			user: &wazuhv1.OpenSearchUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-user",
					Namespace: "default",
				},
			},
			eventType:    corev1.EventTypeNormal,
			reason:       "Synced",
			message:      "User synchronized",
			expectEvents: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).Build()
			r := NewUserReconciler(client, scheme, tt.recorder)

			// Should not panic
			r.recordEvent(tt.user, tt.eventType, tt.reason, tt.message)

			// Verify event was recorded if recorder was provided
			if fakeRecorder, ok := tt.recorder.(*record.FakeRecorder); ok && tt.expectEvents > 0 {
				select {
				case event := <-fakeRecorder.Events:
					if event == "" {
						t.Error("Expected event to be recorded, but got empty event")
					}
				default:
					t.Error("Expected event to be recorded, but none was")
				}
			}
		})
	}
}
