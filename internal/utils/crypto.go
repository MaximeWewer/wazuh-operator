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
// that meets Wazuh's password policy requirements:
// - Minimum 8 characters
// - At least one lowercase letter (a-z)
// - At least one uppercase letter (A-Z)
// - At least one digit (0-9)
// - At least one special character
// Length must be at least 8, defaults to 20 if less
func GenerateWazuhAPIPassword(length int) string {
	if length < 8 {
		length = 20
	}

	const lowercase = "abcdefghijklmnopqrstuvwxyz"
	const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const digits = "0123456789"
	const specialChars = ".*+?-@#$%"
	const allChars = lowercase + uppercase + digits + specialChars

	// Generate random bytes for character selection
	randomBytes := make([]byte, length+10) // Extra bytes for position selection
	if _, err := rand.Read(randomBytes); err != nil {
		return "WazuhAdmin.2025!" // Fallback that meets all requirements
	}

	password := make([]byte, length)

	// First, ensure at least one character from each required category
	// Place them at random positions in the first 4 slots
	password[0] = lowercase[int(randomBytes[0])%len(lowercase)]
	password[1] = uppercase[int(randomBytes[1])%len(uppercase)]
	password[2] = digits[int(randomBytes[2])%len(digits)]
	password[3] = specialChars[int(randomBytes[3])%len(specialChars)]

	// Fill the rest with random characters from all categories
	for i := 4; i < length; i++ {
		password[i] = allChars[int(randomBytes[i])%len(allChars)]
	}

	// Shuffle the password to randomize positions of required characters
	// Fisher-Yates shuffle
	for i := length - 1; i > 0; i-- {
		j := int(randomBytes[length+i%10]) % (i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}
