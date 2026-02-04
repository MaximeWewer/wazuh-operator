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

package certcommon

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseCertDuration parses a duration string like "365d", "24h", "30m"
// Supported units:
//   - d: days (24 hours)
//   - h: hours
//   - m: minutes
//
// Examples: "365d" (1 year), "24h" (1 day), "30m" (30 minutes), "10m" (10 minutes)
// Returns the duration as time.Duration
func ParseCertDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// Get the unit (last character)
	unit := s[len(s)-1:]
	valueStr := s[:len(s)-1]

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return 0, fmt.Errorf("invalid duration value '%s': %w", valueStr, err)
	}

	if value < 0 {
		return 0, fmt.Errorf("duration value must be positive, got %d", value)
	}

	switch strings.ToLower(unit) {
	case "d":
		return time.Duration(value) * 24 * time.Hour, nil
	case "h":
		return time.Duration(value) * time.Hour, nil
	case "m":
		return time.Duration(value) * time.Minute, nil
	default:
		return 0, fmt.Errorf("invalid duration unit '%s': use 'd' (days), 'h' (hours), or 'm' (minutes)", unit)
	}
}

// MustParseCertDuration parses a duration string and panics on error
// Use only for known-good values (e.g., constants)
func MustParseCertDuration(s string) time.Duration {
	d, err := ParseCertDuration(s)
	if err != nil {
		panic(fmt.Sprintf("invalid duration %q: %v", s, err))
	}
	return d
}

// FormatCertDuration formats a time.Duration as a human-readable string
// Uses the most appropriate unit (days, hours, or minutes)
func FormatCertDuration(d time.Duration) string {
	if d <= 0 {
		return "0m"
	}

	// Use days if evenly divisible and >= 1 day
	days := d / (24 * time.Hour)
	if days > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", days)
	}

	// Use hours if evenly divisible and >= 1 hour
	hours := d / time.Hour
	if hours > 0 && d%time.Hour == 0 {
		return fmt.Sprintf("%dh", hours)
	}

	// Fall back to minutes
	minutes := d / time.Minute
	return fmt.Sprintf("%dm", minutes)
}

// DaysFromDuration converts a time.Duration to days (rounded down)
func DaysFromDuration(d time.Duration) int {
	return int(d / (24 * time.Hour))
}

// HoursFromDuration converts a time.Duration to hours (rounded down)
func HoursFromDuration(d time.Duration) int {
	return int(d / time.Hour)
}

// MinutesFromDuration converts a time.Duration to minutes (rounded down)
func MinutesFromDuration(d time.Duration) int {
	return int(d / time.Minute)
}

// DurationFromDays converts days to time.Duration
func DurationFromDays(days int) time.Duration {
	return time.Duration(days) * 24 * time.Hour
}

// DurationFromHours converts hours to time.Duration
func DurationFromHours(hours int) time.Duration {
	return time.Duration(hours) * time.Hour
}

// DurationFromMinutes converts minutes to time.Duration
func DurationFromMinutes(minutes int) time.Duration {
	return time.Duration(minutes) * time.Minute
}

// Default durations as strings (for CRD defaults)
const (
	// DefaultCAValidityStr is the default CA validity as a duration string
	DefaultCAValidityStr = "3650d" // 10 years

	// DefaultNodeValidityStr is the default node certificate validity
	DefaultNodeValidityStr = "365d" // 1 year

	// DefaultCARenewalThresholdStr is the default CA renewal threshold
	DefaultCARenewalThresholdStr = "60d"

	// DefaultNodeRenewalThresholdStr is the default node certificate renewal threshold
	DefaultNodeRenewalThresholdStr = "30d"
)
