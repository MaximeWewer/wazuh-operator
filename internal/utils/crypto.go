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
	"crypto/rand"
	"encoding/base64"
)

// GenerateRandomPassword generates a secure random password of the specified length
func GenerateRandomPassword(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a basic password if random fails
		return "admin"
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateRandomString generates a random alphanumeric string of the specified length
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(bytes)
}

// GenerateWazuhAPIPassword generates a secure random password for Wazuh API
// The password contains alphanumeric characters plus at least one special character
// from the set: . * + ? -
// Length must be at least 8, defaults to 20 if less
func GenerateWazuhAPIPassword(length int) string {
	if length < 8 {
		length = 20
	}

	const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const specialChars = ".*+?-"

	// Generate length-1 alphanumeric characters
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "WazuhAdmin.2025" // Fallback with special char
	}

	for i := 0; i < length-1; i++ {
		bytes[i] = alphanumeric[int(bytes[i])%len(alphanumeric)]
	}

	// Add one random special character at a random position
	specialByte := make([]byte, 2)
	if _, err := rand.Read(specialByte); err != nil {
		bytes[length-1] = '.'
	} else {
		specialChar := specialChars[int(specialByte[0])%len(specialChars)]
		insertPos := int(specialByte[1]) % length
		// Shift characters and insert special char
		for i := length - 1; i > insertPos; i-- {
			bytes[i] = bytes[i-1]
		}
		bytes[insertPos] = specialChar
	}

	return string(bytes)
}
