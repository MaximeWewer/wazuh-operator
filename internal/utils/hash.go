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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// HashObject computes a SHA256 hash of an object's JSON representation
func HashObject(obj interface{}) (string, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal object for hashing: %w", err)
	}
	return HashBytes(data), nil
}

// HashBytes computes a SHA256 hash of a byte slice
func HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// HashString computes a SHA256 hash of a string
func HashString(s string) string {
	return HashBytes([]byte(s))
}

// HashStrings computes a hash of multiple strings
func HashStrings(strings ...string) string {
	combined := ""
	for _, s := range strings {
		combined += s + "\n"
	}
	return HashString(combined)
}

// HashMap computes a deterministic hash of a map
func HashMap(m map[string]string) string {
	// Sort keys for deterministic ordering
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	combined := ""
	for _, k := range keys {
		combined += k + "=" + m[k] + "\n"
	}
	return HashString(combined)
}

// ShortHash returns a truncated hash (first 8 characters)
func ShortHash(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}

// HashConfigData computes a hash for ConfigMap data
func HashConfigData(data map[string]string) string {
	return HashMap(data)
}

// HashSecretData computes a hash for Secret data
func HashSecretData(data map[string][]byte) string {
	// Convert to string map for consistent hashing
	strMap := make(map[string]string, len(data))
	for k, v := range data {
		strMap[k] = string(v)
	}
	return HashMap(strMap)
}

// CompareHashes checks if two hashes are equal
func CompareHashes(hash1, hash2 string) bool {
	return hash1 == hash2
}

// HashChanged checks if the object hash has changed from the stored hash
func HashChanged(obj interface{}, storedHash string) (bool, string, error) {
	newHash, err := HashObject(obj)
	if err != nil {
		return false, "", err
	}
	return newHash != storedHash, newHash, nil
}
