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
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateRandomPassword generates a secure random password of the specified length.
// Returns an error if the length is invalid or if cryptographic random generation fails.
func GenerateRandomPassword(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be positive, got %d", length)
	}
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
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

// GenerateRandomString generates a random alphanumeric string of the specified length.
// Returns an error if the length is invalid or if cryptographic random generation fails.
func GenerateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("string length must be positive, got %d", length)
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(bytes), nil
}

// GenerateWazuhAPIPassword generates a secure random password for Wazuh API
// that meets Wazuh's password policy requirements:
// - Minimum 8 characters
// - At least one lowercase letter (a-z)
// - At least one uppercase letter (A-Z)
// - At least one digit (0-9)
// - At least one special character
// Length must be at least 8, defaults to 20 if less.
// Returns an error if cryptographic random generation fails.
func GenerateWazuhAPIPassword(length int) (string, error) {
	if length < 8 {
		length = 20
	}

	const lowercase = "abcdefghijklmnopqrstuvwxyz"
	const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const digits = "0123456789"
	const specialChars = ".*+?-@#$%"
	const allChars = lowercase + uppercase + digits + specialChars

	// Generate random bytes for character selection and shuffle
	// Need: length bytes for characters + length bytes for Fisher-Yates shuffle
	randomBytes := make([]byte, length*2)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}

	password := make([]byte, length)

	// First, ensure at least one character from each required category
	password[0] = lowercase[int(randomBytes[0])%len(lowercase)]
	password[1] = uppercase[int(randomBytes[1])%len(uppercase)]
	password[2] = digits[int(randomBytes[2])%len(digits)]
	password[3] = specialChars[int(randomBytes[3])%len(specialChars)]

	// Fill the rest with random characters from all categories
	for i := 4; i < length; i++ {
		password[i] = allChars[int(randomBytes[i])%len(allChars)]
	}

	// Fisher-Yates shuffle using dedicated random bytes (no reuse, no bias)
	for i := length - 1; i > 0; i-- {
		j := int(randomBytes[length+i]) % (i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password), nil
}
