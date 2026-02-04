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

package utils

import (
	"testing"
	"time"
)

func TestMaintenanceWindowChecker_IsWithinWindow(t *testing.T) {
	tests := []struct {
		name        string
		schedule    string
		duration    time.Duration
		timezone    string
		now         time.Time
		expectIn    bool
		expectError bool
	}{
		{
			name:     "Within window - same day",
			schedule: "0 2 * * *", // Every day at 2 AM
			duration: 4 * time.Hour,
			timezone: "UTC",
			// Test at 3 AM UTC (within 2-6 AM window)
			now:      time.Date(2026, 1, 15, 3, 0, 0, 0, time.UTC),
			expectIn: true,
		},
		{
			name:     "Outside window - before start",
			schedule: "0 2 * * *",
			duration: 4 * time.Hour,
			timezone: "UTC",
			// Test at 1 AM UTC (before 2 AM window)
			now:      time.Date(2026, 1, 15, 1, 0, 0, 0, time.UTC),
			expectIn: false,
		},
		{
			name:     "Outside window - after end",
			schedule: "0 2 * * *",
			duration: 4 * time.Hour,
			timezone: "UTC",
			// Test at 7 AM UTC (after 6 AM window end)
			now:      time.Date(2026, 1, 15, 7, 0, 0, 0, time.UTC),
			expectIn: false,
		},
		{
			name:     "Weekly window - Saturday at 2 AM",
			schedule: "0 2 * * 6", // Saturdays at 2 AM
			duration: 4 * time.Hour,
			timezone: "UTC",
			// Test Saturday 3 AM UTC
			now:      time.Date(2026, 1, 17, 3, 0, 0, 0, time.UTC), // Saturday
			expectIn: true,
		},
		{
			name:     "Weekly window - Not Saturday",
			schedule: "0 2 * * 6", // Saturdays at 2 AM
			duration: 4 * time.Hour,
			timezone: "UTC",
			// Test Friday 3 AM UTC
			now:      time.Date(2026, 1, 16, 3, 0, 0, 0, time.UTC), // Friday
			expectIn: false,
		},
		{
			name:        "Invalid schedule",
			schedule:    "invalid cron",
			duration:    4 * time.Hour,
			timezone:    "UTC",
			now:         time.Now(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewMaintenanceWindowChecker(tt.schedule, tt.duration, tt.timezone)
			if err != nil && !tt.expectError {
				t.Fatalf("Failed to create checker: %v", err)
			}
			if tt.expectError && err != nil {
				return // Expected error creating checker
			}

			inWindow, err := checker.IsWithinWindow(tt.now)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if inWindow != tt.expectIn {
				t.Errorf("IsWithinWindow() = %v, want %v", inWindow, tt.expectIn)
			}
		})
	}
}

func TestMaintenanceWindowChecker_NextWindowStart(t *testing.T) {
	checker, err := NewMaintenanceWindowChecker("0 2 * * *", 4*time.Hour, "UTC")
	if err != nil {
		t.Fatalf("Failed to create checker: %v", err)
	}

	// Test from 10 AM, expect next window at 2 AM next day
	now := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	next, err := checker.NextWindowStart(now)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expected := time.Date(2026, 1, 16, 2, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Errorf("NextWindowStart() = %v, want %v", next, expected)
	}
}

func TestMaintenanceWindowChecker_TimeUntilNextWindow(t *testing.T) {
	checker, err := NewMaintenanceWindowChecker("0 2 * * *", 4*time.Hour, "UTC")
	if err != nil {
		t.Fatalf("Failed to create checker: %v", err)
	}

	// Test from 10 PM, expect ~4 hours until next window at 2 AM
	now := time.Date(2026, 1, 15, 22, 0, 0, 0, time.UTC)
	duration, err := checker.TimeUntilNextWindow(now)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedDuration := 4 * time.Hour
	if duration != expectedDuration {
		t.Errorf("TimeUntilNextWindow() = %v, want %v", duration, expectedDuration)
	}
}

func TestCheckMaintenanceWindows_MultipleWindows(t *testing.T) {
	// Create two windows: one at 2 AM, one at 6 PM
	window1, err := NewMaintenanceWindowChecker("0 2 * * *", 2*time.Hour, "UTC")
	if err != nil {
		t.Fatalf("Failed to create window1: %v", err)
	}
	window2, err := NewMaintenanceWindowChecker("0 18 * * *", 2*time.Hour, "UTC")
	if err != nil {
		t.Fatalf("Failed to create window2: %v", err)
	}

	windows := []MaintenanceWindowChecker{*window1, *window2}

	tests := []struct {
		name     string
		now      time.Time
		expectIn bool
	}{
		{
			name:     "In first window (3 AM)",
			now:      time.Date(2026, 1, 15, 3, 0, 0, 0, time.UTC),
			expectIn: true,
		},
		{
			name:     "In second window (7 PM)",
			now:      time.Date(2026, 1, 15, 19, 0, 0, 0, time.UTC),
			expectIn: true,
		},
		{
			name:     "Outside both windows (noon)",
			now:      time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
			expectIn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inWindow, err := CheckMaintenanceWindows(windows, tt.now)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if inWindow != tt.expectIn {
				t.Errorf("CheckMaintenanceWindows() = %v, want %v", inWindow, tt.expectIn)
			}
		})
	}
}

func TestMaintenanceWindowChecker_DifferentTimezones(t *testing.T) {
	// Window at 2 AM UTC
	checker, err := NewMaintenanceWindowChecker("0 2 * * *", 4*time.Hour, "UTC")
	if err != nil {
		t.Fatalf("Failed to create checker: %v", err)
	}

	// 3 AM UTC should be in window
	utcTime := time.Date(2026, 1, 15, 3, 0, 0, 0, time.UTC)
	inWindow, err := checker.IsWithinWindow(utcTime)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !inWindow {
		t.Error("Expected to be in window at 3 AM UTC")
	}

	// Test with Europe/Paris timezone (UTC+1)
	parisChecker, err := NewMaintenanceWindowChecker("0 2 * * *", 4*time.Hour, "Europe/Paris")
	if err != nil {
		t.Fatalf("Failed to create Paris checker: %v", err)
	}

	// 3 AM Paris time should be in window
	parisLoc, _ := time.LoadLocation("Europe/Paris")
	parisTime := time.Date(2026, 1, 15, 3, 0, 0, 0, parisLoc)
	inParisWindow, err := parisChecker.IsWithinWindow(parisTime)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !inParisWindow {
		t.Error("Expected to be in window at 3 AM Paris time")
	}
}
