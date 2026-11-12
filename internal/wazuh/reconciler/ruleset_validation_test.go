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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wazuhv1 "github.com/MaximeWewer/wazuh-operator/api/v1"
	"github.com/MaximeWewer/wazuh-operator/internal/adapters"
)

// fakeRulesetAPI holds the master's decoder files; the ruleset is invalid while a file
// contains "bad", as analysisd would reject it.
type fakeRulesetAPI struct {
	files     map[string]string
	readOnly  bool
	failWrite string // content whose upload fails, as a restore hitting an API timeout
	uploads   int
	calls     int
	brokenMsg string
}

func (f *fakeRulesetAPI) GetRulesetFile(_ context.Context, _ adapters.RulesetKind, name string) (string, error) {
	f.calls++
	if c, ok := f.files[name]; ok {
		return c, nil
	}
	return "", fmt.Errorf("x: %w", adapters.ErrRulesetFileNotFound)
}

func (f *fakeRulesetAPI) UploadRulesetFile(_ context.Context, _ adapters.RulesetKind, name, content string) error {
	f.calls++
	if f.readOnly {
		return errors.New("upload failed: read-only file system")
	}
	if f.failWrite != "" && content == f.failWrite {
		return errors.New("upload failed: timeout")
	}
	f.uploads++
	f.files[name] = content
	return nil
}

func (f *fakeRulesetAPI) DeleteRulesetFile(_ context.Context, _ adapters.RulesetKind, name string) error {
	f.calls++
	if f.readOnly {
		return errors.New("delete failed: read-only file system")
	}
	delete(f.files, name)
	return nil
}

func (f *fakeRulesetAPI) ValidateConfiguration(context.Context) error {
	f.calls++
	for name, c := range f.files {
		if strings.Contains(c, "bad") {
			return fmt.Errorf("%w: master: (1202): Configuration error at 'etc/decoders/%s'", adapters.ErrInvalidConfiguration, name)
		}
	}
	if f.brokenMsg != "" {
		return fmt.Errorf("%w: %s", adapters.ErrInvalidConfiguration, f.brokenMsg)
	}
	return nil
}

func TestValidateRulesetFile(t *testing.T) {
	for name, tc := range map[string]struct {
		files        map[string]string // master files before
		installed    string            // ConfigMap content ("" = not installed)
		candidate    string
		readOnly     bool
		failWrite    string
		brokenMsg    string
		wantRejected bool
		wantErr      error // when set, the error must wrap it
		wantAnyErr   bool
		wantFile     string // master content of new.xml afterwards ("" = absent)
	}{
		"valid new file kept":       {files: map[string]string{}, candidate: "good", wantFile: "good"},
		"valid update kept":         {files: map[string]string{"new.xml": "v1"}, installed: "v1", candidate: "v2", wantFile: "v2"},
		"rejected new file removed": {files: map[string]string{}, candidate: "bad", wantRejected: true},
		"rejected update restores the installed version": {files: map[string]string{"new.xml": "v1"}, installed: "v1", candidate: "bad v2",
			wantRejected: true, wantFile: "v1"},
		"drifted master file repaired before judging": {files: map[string]string{"new.xml": "bad leftover"}, installed: "v1", candidate: "v2",
			wantFile: "v2"},
		"leftover candidate on the master is still judged": {files: map[string]string{"new.xml": "bad v2"}, installed: "v1", candidate: "bad v2",
			wantRejected: true, wantFile: "v1"},
		"configuration already invalid: not judged": {files: map[string]string{}, candidate: "good", brokenMsg: "other.xml broken",
			wantAnyErr: true},
		"read-only file: retried, not rejected": {files: map[string]string{"new.xml": "v1"}, installed: "v1", candidate: "v2",
			readOnly: true, wantAnyErr: true, wantFile: "v1"},
		"restore failing after a rejection: retried, not rejected": {files: map[string]string{"new.xml": "v1"}, installed: "v1", candidate: "bad v2",
			failWrite: "v1", wantErr: ErrRulesetRestoreFailed, wantFile: "bad v2"},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeRulesetAPI{files: tc.files, readOnly: tc.readOnly, failWrite: tc.failWrite, brokenMsg: tc.brokenMsg}
			err := validateRulesetFile(context.Background(), api, "ns/c", adapters.RulesetDecoders, "new.xml",
				tc.candidate, tc.installed, tc.installed != "")
			var rejected *RulesetRejectedError
			if errors.As(err, &rejected) != tc.wantRejected {
				t.Fatalf("validateRulesetFile error = %v, want rejected %v", err, tc.wantRejected)
			}
			if wantErr := tc.wantRejected || tc.wantAnyErr || tc.wantErr != nil; (err != nil) != wantErr {
				t.Fatalf("validateRulesetFile error = %v, want an error %v", err, wantErr)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("validateRulesetFile error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantRejected && !strings.Contains(rejected.Message, "(1202)") {
				t.Errorf("rejection message %q lacks the Wazuh error", rejected.Message)
			}
			if got := api.files["new.xml"]; got != tc.wantFile {
				t.Errorf("master file = %q, want %q", got, tc.wantFile)
			}
		})
	}
}

func TestValidateContentForCluster(t *testing.T) {
	cluster := &wazuhv1.WazuhCluster{ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "ns"}}
	master := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "c-manager-master", Namespace: "ns"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "ns"}, Data: map[string]string{"d.xml": "applied"}}
	newClient := func(objs ...runtime.Object) client.Client {
		scheme := runtime.NewScheme()
		_ = corev1.AddToScheme(scheme)
		_ = appsv1.AddToScheme(scheme)
		return fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
	}

	for name, tc := range map[string]struct {
		objs      []runtime.Object
		content   string
		wantCalls bool
		wantErr   bool
	}{
		"content the ConfigMap already holds": {objs: []runtime.Object{master, cm}, content: "applied"},
		"new cluster, no manager yet":         {objs: []runtime.Object{cm}, content: "bad"},
		"changed content validated":           {objs: []runtime.Object{master, cm}, content: "good", wantCalls: true},
		"changed content rejected":            {objs: []runtime.Object{master, cm}, content: "bad", wantCalls: true, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeRulesetAPI{files: map[string]string{}}
			factory := func(context.Context, client.Client, *wazuhv1.WazuhCluster) (RulesetValidationAPI, error) {
				return api, nil
			}
			err := validateContentForCluster(context.Background(), newClient(tc.objs...), factory, cluster, "cm",
				adapters.RulesetDecoders, "d.xml", tc.content)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", err, tc.wantErr)
			}
			if (api.calls > 0) != tc.wantCalls {
				t.Errorf("API calls = %d, want calls %v", api.calls, tc.wantCalls)
			}
		})
	}
}
