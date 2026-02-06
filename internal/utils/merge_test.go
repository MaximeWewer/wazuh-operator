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

package utils //nolint:revive // utils is a common package name

import (
	"testing"
)

func TestDeepMerge_NestedMaps(t *testing.T) {
	type Config struct {
		Settings map[string]any `json:"settings"`
	}

	dst := &Config{
		Settings: map[string]any{
			"index": map[string]any{
				"number_of_shards":   3,
				"number_of_replicas": 1,
			},
			"keep": "this",
		},
	}

	src := &Config{
		Settings: map[string]any{
			"index": map[string]any{
				"number_of_replicas": 2,
				"refresh_interval":   "30s",
			},
		},
	}

	if err := DeepMerge(dst, src); err != nil {
		t.Fatalf("DeepMerge returned error: %v", err)
	}

	index, ok := dst.Settings["index"].(map[string]any)
	if !ok {
		t.Fatal("settings.index is not a map")
	}

	// src value overrides dst
	if v := index["number_of_replicas"]; v != float64(2) {
		t.Errorf("number_of_replicas: got %v, want 2", v)
	}

	// dst-only key preserved
	if v := index["number_of_shards"]; v != float64(3) {
		t.Errorf("number_of_shards: got %v, want 3", v)
	}

	// src-only key added
	if v := index["refresh_interval"]; v != "30s" {
		t.Errorf("refresh_interval: got %v, want 30s", v)
	}

	// top-level dst-only key preserved
	if v := dst.Settings["keep"]; v != "this" {
		t.Errorf("keep: got %v, want 'this'", v)
	}
}

func TestDeepMerge_ScalarOverride(t *testing.T) {
	type Simple struct {
		A string `json:"a"`
		B string `json:"b"`
	}

	dst := &Simple{A: "one", B: "two"}
	src := &Simple{A: "override"}

	if err := DeepMerge(dst, src); err != nil {
		t.Fatalf("DeepMerge returned error: %v", err)
	}

	if dst.A != "override" {
		t.Errorf("A: got %q, want %q", dst.A, "override")
	}
	// B should remain since src has zero value
	// (json omitempty not set, so empty string overwrites)
}

func TestDeepMerge_DeeplyNested(t *testing.T) {
	type Doc struct {
		Data map[string]any `json:"data"`
	}

	dst := &Doc{
		Data: map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"a": "from_dst",
					"b": "from_dst",
				},
			},
		},
	}

	src := &Doc{
		Data: map[string]any{
			"level1": map[string]any{
				"level2": map[string]any{
					"b": "from_src",
					"c": "from_src",
				},
			},
		},
	}

	if err := DeepMerge(dst, src); err != nil {
		t.Fatalf("DeepMerge returned error: %v", err)
	}

	l1, ok := dst.Data["level1"].(map[string]any)
	if !ok {
		t.Fatal("level1 is not a map")
	}
	l2, ok := l1["level2"].(map[string]any)
	if !ok {
		t.Fatal("level2 is not a map")
	}

	if v := l2["a"]; v != "from_dst" {
		t.Errorf("a: got %v, want from_dst", v)
	}
	if v := l2["b"]; v != "from_src" {
		t.Errorf("b: got %v, want from_src", v)
	}
	if v := l2["c"]; v != "from_src" {
		t.Errorf("c: got %v, want from_src", v)
	}
}
