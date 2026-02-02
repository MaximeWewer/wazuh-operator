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

package certificates

import (
	"testing"
	"time"
)

func TestParseCertDuration(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  time.Duration
		expectErr bool
	}{
		// Valid days
		{"1 day", "1d", 24 * time.Hour, false},
		{"365 days", "365d", 365 * 24 * time.Hour, false},
		{"3650 days", "3650d", 3650 * 24 * time.Hour, false},

		// Valid hours
		{"1 hour", "1h", time.Hour, false},
		{"24 hours", "24h", 24 * time.Hour, false},
		{"48 hours", "48h", 48 * time.Hour, false},

		// Valid minutes
		{"1 minute", "1m", time.Minute, false},
		{"10 minutes", "10m", 10 * time.Minute, false},
		{"30 minutes", "30m", 30 * time.Minute, false},
		{"60 minutes", "60m", 60 * time.Minute, false},

		// Edge cases
		{"zero days", "0d", 0, false},
		{"zero hours", "0h", 0, false},
		{"zero minutes", "0m", 0, false},
		{"uppercase D", "1D", 24 * time.Hour, false},
		{"uppercase H", "1H", time.Hour, false},
		{"uppercase M", "1M", time.Minute, false},
		{"with spaces", "  10m  ", 10 * time.Minute, false},

		// Invalid inputs
		{"empty string", "", 0, true},
		{"no unit", "10", 0, true},
		{"invalid unit", "10s", 0, true},
		{"invalid value", "abcd", 0, true},
		{"negative value", "-10m", 0, true},
		{"float value", "1.5d", 0, true},
		{"only unit", "d", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCertDuration(tt.input)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error for input %q, got none", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for input %q: %v", tt.input, err)
				return
			}

			if result != tt.expected {
				t.Errorf("for input %q: expected %v, got %v", tt.input, tt.expected, result)
			}
		})
	}
}

func TestFormatCertDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected string
	}{
		{"0 duration", 0, "0m"},
		{"negative duration", -10 * time.Minute, "0m"},

		// Days
		{"1 day", 24 * time.Hour, "1d"},
		{"365 days", 365 * 24 * time.Hour, "365d"},
		{"7 days", 7 * 24 * time.Hour, "7d"},

		// Hours (not evenly divisible by days)
		{"1 hour", time.Hour, "1h"},
		{"12 hours", 12 * time.Hour, "12h"},
		{"25 hours", 25 * time.Hour, "25h"}, // Not evenly divisible by 24

		// Minutes (not evenly divisible by hours)
		{"30 minutes", 30 * time.Minute, "30m"},
		{"90 minutes", 90 * time.Minute, "90m"}, // 1.5 hours
		{"10 minutes", 10 * time.Minute, "10m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatCertDuration(tt.input)
			if result != tt.expected {
				t.Errorf("for input %v: expected %q, got %q", tt.input, tt.expected, result)
			}
		})
	}
}

func TestDurationConversions(t *testing.T) {
	// Test DaysFromDuration
	if got := DaysFromDuration(48 * time.Hour); got != 2 {
		t.Errorf("DaysFromDuration(48h) = %d, want 2", got)
	}
	if got := DaysFromDuration(36 * time.Hour); got != 1 {
		t.Errorf("DaysFromDuration(36h) = %d, want 1 (rounded down)", got)
	}

	// Test HoursFromDuration
	if got := HoursFromDuration(90 * time.Minute); got != 1 {
		t.Errorf("HoursFromDuration(90m) = %d, want 1 (rounded down)", got)
	}

	// Test MinutesFromDuration
	if got := MinutesFromDuration(2*time.Hour + 30*time.Minute); got != 150 {
		t.Errorf("MinutesFromDuration(2h30m) = %d, want 150", got)
	}

	// Test DurationFromDays
	if got := DurationFromDays(7); got != 7*24*time.Hour {
		t.Errorf("DurationFromDays(7) = %v, want 168h", got)
	}

	// Test DurationFromHours
	if got := DurationFromHours(48); got != 48*time.Hour {
		t.Errorf("DurationFromHours(48) = %v, want 48h", got)
	}

	// Test DurationFromMinutes
	if got := DurationFromMinutes(30); got != 30*time.Minute {
		t.Errorf("DurationFromMinutes(30) = %v, want 30m", got)
	}
}

func TestMustParseCertDuration(t *testing.T) {
	// Valid input should not panic
	result := MustParseCertDuration("10m")
	if result != 10*time.Minute {
		t.Errorf("MustParseCertDuration(10m) = %v, want 10m", result)
	}

	// Invalid input should panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("MustParseCertDuration with invalid input should panic")
		}
	}()
	MustParseCertDuration("invalid")
}

func TestRoundTripParsing(t *testing.T) {
	// Test that parsing and formatting are consistent
	testCases := []string{"1d", "7d", "365d", "1h", "24h", "1m", "30m", "60m"}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			parsed, err := ParseCertDuration(tc)
			if err != nil {
				t.Fatalf("failed to parse %q: %v", tc, err)
			}

			formatted := FormatCertDuration(parsed)
			reparsed, err := ParseCertDuration(formatted)
			if err != nil {
				t.Fatalf("failed to reparse %q: %v", formatted, err)
			}

			if parsed != reparsed {
				t.Errorf("round-trip failed: %q -> %v -> %q -> %v", tc, parsed, formatted, reparsed)
			}
		})
	}
}
