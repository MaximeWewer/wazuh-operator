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

package utils //nolint:revive // utils is an established package name in this project

import (
	"time"

	"github.com/robfig/cron/v3"
)

// MaintenanceWindowChecker checks if operations are allowed based on maintenance windows
type MaintenanceWindowChecker struct {
	// Schedule is the cron expression for window start
	Schedule string
	// Duration is how long the window lasts
	Duration time.Duration
	// Timezone for schedule evaluation
	Timezone *time.Location
}

// NewMaintenanceWindowChecker creates a new maintenance window checker
func NewMaintenanceWindowChecker(schedule string, duration time.Duration, timezone string) (*MaintenanceWindowChecker, error) {
	loc := time.UTC
	if timezone != "" && timezone != "UTC" {
		var err error
		loc, err = time.LoadLocation(timezone)
		if err != nil {
			return nil, err
		}
	}

	return &MaintenanceWindowChecker{
		Schedule: schedule,
		Duration: duration,
		Timezone: loc,
	}, nil
}

// IsWithinWindow checks if the current time is within the maintenance window
func (m *MaintenanceWindowChecker) IsWithinWindow(now time.Time) (bool, error) {
	// Parse the cron schedule
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(m.Schedule)
	if err != nil {
		return false, err
	}

	// Convert now to the configured timezone
	nowInTZ := now.In(m.Timezone)

	// Find the most recent scheduled start time before now
	// We need to check if now falls within a window that started recently
	// Go back far enough to catch any window that might still be active
	checkStart := nowInTZ.Add(-m.Duration - 24*time.Hour)

	// Find the last scheduled time before now
	lastScheduled := checkStart
	for {
		nextScheduled := schedule.Next(lastScheduled)
		if nextScheduled.After(nowInTZ) {
			break
		}
		lastScheduled = nextScheduled
	}

	// If there was no scheduled time found, the window hasn't started yet
	if lastScheduled.Equal(checkStart) {
		return false, nil
	}

	// Check if we're still within the duration window
	windowEnd := lastScheduled.Add(m.Duration)
	return nowInTZ.After(lastScheduled) && nowInTZ.Before(windowEnd), nil
}

// NextWindowStart returns the next maintenance window start time
func (m *MaintenanceWindowChecker) NextWindowStart(after time.Time) (time.Time, error) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(m.Schedule)
	if err != nil {
		return time.Time{}, err
	}

	afterInTZ := after.In(m.Timezone)
	return schedule.Next(afterInTZ), nil
}

// TimeUntilNextWindow returns the duration until the next maintenance window
func (m *MaintenanceWindowChecker) TimeUntilNextWindow(now time.Time) (time.Duration, error) {
	next, err := m.NextWindowStart(now)
	if err != nil {
		return 0, err
	}
	return next.Sub(now.In(m.Timezone)), nil
}

// CheckMaintenanceWindows checks multiple maintenance windows and returns true if any is active
func CheckMaintenanceWindows(windows []MaintenanceWindowChecker, now time.Time) (bool, error) {
	for _, w := range windows {
		inWindow, err := w.IsWithinWindow(now)
		if err != nil {
			return false, err
		}
		if inWindow {
			return true, nil
		}
	}
	return false, nil
}
