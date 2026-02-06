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
	"encoding/json"
	"fmt"
)

// MergeStringMaps merges multiple string maps, with later maps taking precedence
func MergeStringMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// MergeLabels is an alias for MergeStringMaps for semantic clarity
func MergeLabels(maps ...map[string]string) map[string]string {
	return MergeStringMaps(maps...)
}

// MergeAnnotations is an alias for MergeStringMaps for semantic clarity
func MergeAnnotations(maps ...map[string]string) map[string]string {
	return MergeStringMaps(maps...)
}

// DeepMerge performs a recursive deep merge of two objects.
// Both dst and src are marshaled to map[string]any, merged recursively,
// then the result is unmarshalled back into dst.
// For nested maps, keys are merged individually rather than overwritten.
func DeepMerge(dst, src any) error {
	// Marshal both to JSON then to map[string]any
	dstBytes, err := json.Marshal(dst)
	if err != nil {
		return fmt.Errorf("failed to marshal destination: %w", err)
	}
	srcBytes, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("failed to marshal source: %w", err)
	}

	var dstMap, srcMap map[string]any
	if err := json.Unmarshal(dstBytes, &dstMap); err != nil {
		return fmt.Errorf("failed to unmarshal destination: %w", err)
	}
	if err := json.Unmarshal(srcBytes, &srcMap); err != nil {
		return fmt.Errorf("failed to unmarshal source: %w", err)
	}

	merged := deepMergeMaps(dstMap, srcMap)

	mergedBytes, err := json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("failed to marshal merged result: %w", err)
	}
	if err := json.Unmarshal(mergedBytes, dst); err != nil {
		return fmt.Errorf("failed to unmarshal merged result into destination: %w", err)
	}

	return nil
}

// deepMergeMaps recursively merges src into dst.
// For keys present in both maps where both values are maps, the merge is recursive.
// Otherwise src values override dst values.
func deepMergeMaps(dst, src map[string]any) map[string]any {
	result := make(map[string]any, len(dst))
	for k, v := range dst {
		result[k] = v
	}
	for k, srcVal := range src {
		if dstVal, exists := result[k]; exists {
			srcMap, srcOk := srcVal.(map[string]any)
			dstMap, dstOk := dstVal.(map[string]any)
			if srcOk && dstOk {
				result[k] = deepMergeMaps(dstMap, srcMap)
				continue
			}
		}
		result[k] = srcVal
	}
	return result
}

// MergeSlices merges two string slices, removing duplicates
func MergeSlices(slices ...[]string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, slice := range slices {
		for _, item := range slice {
			if !seen[item] {
				seen[item] = true
				result = append(result, item)
			}
		}
	}

	return result
}

// CopyStringMap creates a copy of a string map
func CopyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// SetStringMapDefault sets a default value in a map if the key doesn't exist
func SetStringMapDefault(m map[string]string, key, defaultValue string) {
	if _, exists := m[key]; !exists {
		m[key] = defaultValue
	}
}

// FilterStringMap filters a map by keys
func FilterStringMap(m map[string]string, keys []string) map[string]string {
	result := make(map[string]string)
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}
	for k, v := range m {
		if keySet[k] {
			result[k] = v
		}
	}
	return result
}

// ExcludeFromStringMap returns a map excluding specified keys
func ExcludeFromStringMap(m map[string]string, keys []string) map[string]string {
	result := make(map[string]string)
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}
	for k, v := range m {
		if !keySet[k] {
			result[k] = v
		}
	}
	return result
}
