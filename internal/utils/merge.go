/*
Copyright 2025.

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

package utils

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

// DeepMerge performs a deep merge of two objects
// dst is the destination object that will be modified
// src is the source object whose values will override dst
func DeepMerge(dst, src interface{}) error {
	// Marshal src to JSON
	srcBytes, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("failed to marshal source: %w", err)
	}

	// Unmarshal into dst, which merges the values
	if err := json.Unmarshal(srcBytes, dst); err != nil {
		return fmt.Errorf("failed to unmarshal into destination: %w", err)
	}

	return nil
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
