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

package certificates

import (
	"testing"
	"time"
)

func TestDefaultCertificateOptions(t *testing.T) {
	opts := DefaultCertificateOptions()

	if opts.CAValidityDays != DefaultCAValidityDays {
		t.Errorf("expected CAValidityDays %d, got %d", DefaultCAValidityDays, opts.CAValidityDays)
	}
	if opts.NodeValidityDays != DefaultNodeValidityDays {
		t.Errorf("expected NodeValidityDays %d, got %d", DefaultNodeValidityDays, opts.NodeValidityDays)
	}
	if opts.RenewalThresholdDays != 30 {
		t.Errorf("expected RenewalThresholdDays 30, got %d", opts.RenewalThresholdDays)
	}
	if opts.TestMode {
		t.Error("expected TestMode to be false by default")
	}
	if opts.ValidityMinutes != 8 {
		t.Errorf("expected ValidityMinutes 8, got %d", opts.ValidityMinutes)
	}
	if opts.RenewalThresholdMinutes != 3 {
		t.Errorf("expected RenewalThresholdMinutes 3, got %d", opts.RenewalThresholdMinutes)
	}
}

func TestTestModeCertificateOptions(t *testing.T) {
	opts := TestModeCertificateOptions()

	if !opts.TestMode {
		t.Error("expected TestMode to be true")
	}
	if opts.ValidityMinutes != 8 {
		t.Errorf("expected ValidityMinutes 8, got %d", opts.ValidityMinutes)
	}
	if opts.RenewalThresholdMinutes != 3 {
		t.Errorf("expected RenewalThresholdMinutes 3, got %d", opts.RenewalThresholdMinutes)
	}
}

func TestCertificateOptions_GetCAValidityDays(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"returns configured value when positive", 100, 100},
		{"returns default when zero", 0, DefaultCAValidityDays},
		{"returns default when negative", -10, DefaultCAValidityDays},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{CAValidityDays: tt.input}
			if got := opts.GetCAValidityDays(); got != tt.expected {
				t.Errorf("GetCAValidityDays() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestCertificateOptions_GetNodeValidityDays(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"returns configured value when positive", 90, 90},
		{"returns default when zero", 0, DefaultNodeValidityDays},
		{"returns default when negative", -5, DefaultNodeValidityDays},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{NodeValidityDays: tt.input}
			if got := opts.GetNodeValidityDays(); got != tt.expected {
				t.Errorf("GetNodeValidityDays() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestCertificateOptions_GetRenewalThresholdDays(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"returns configured value when positive", 60, 60},
		{"returns default when zero", 0, 30},
		{"returns default when negative", -1, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{RenewalThresholdDays: tt.input}
			if got := opts.GetRenewalThresholdDays(); got != tt.expected {
				t.Errorf("GetRenewalThresholdDays() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestCertificateOptions_GetValidityMinutes(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"returns configured value when positive", 10, 10},
		{"returns default when zero", 0, 8},
		{"returns default when negative", -1, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{ValidityMinutes: tt.input}
			if got := opts.GetValidityMinutes(); got != tt.expected {
				t.Errorf("GetValidityMinutes() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestCertificateOptions_GetRenewalThresholdMinutes(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"returns configured value when positive", 4, 4},
		{"returns default when zero", 0, 3},
		{"returns default when negative", -1, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{RenewalThresholdMinutes: tt.input}
			if got := opts.GetRenewalThresholdMinutes(); got != tt.expected {
				t.Errorf("GetRenewalThresholdMinutes() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestCertificateOptions_ShouldRenewCA_ProductionMode(t *testing.T) {
	// Create a CA that expires in 30 days
	caConfig := DefaultCAConfig("test-ca")
	caConfig.ValidityDays = 30 // 30 days validity so we can test with realistic threshold
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	tests := []struct {
		name          string
		thresholdDays int
		expectedRenew bool
	}{
		{"should renew when threshold is larger than remaining days", 365, true},
		{"should not renew when threshold is smaller than remaining days", 7, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{
				TestMode:               false,
				CARenewalThresholdDays: tt.thresholdDays,
			}
			if got := opts.ShouldRenewCA(ca); got != tt.expectedRenew {
				t.Errorf("ShouldRenewCA() = %v, expected %v (threshold: %d days, expiry in: %d days)",
					got, tt.expectedRenew, tt.thresholdDays, ca.DaysUntilExpiry())
			}
		})
	}
}

func TestCertificateOptions_ShouldRenewCA_TestMode(t *testing.T) {
	// Create a CA that expires in 10 minutes
	caConfig := DefaultCAConfig("test-ca")
	caConfig.ValidityMinutes = 10
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	tests := []struct {
		name             string
		thresholdMinutes int
		expectedRenew    bool
	}{
		{"should renew when threshold is larger than remaining minutes", 60, true},
		{"should not renew when threshold is smaller than remaining minutes", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{
				TestMode:                  true,
				CARenewalThresholdMinutes: tt.thresholdMinutes,
			}
			if got := opts.ShouldRenewCA(ca); got != tt.expectedRenew {
				t.Errorf("ShouldRenewCA() = %v, expected %v (threshold: %d min, expiry in: %d min)",
					got, tt.expectedRenew, tt.thresholdMinutes, ca.MinutesUntilExpiry())
			}
		})
	}
}

func TestCertificateOptions_ShouldRenewNode(t *testing.T) {
	// Create a CA first
	caConfig := DefaultCAConfig("test-ca")
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// Create a node cert that expires in 30 days
	nodeConfig := DefaultNodeCertConfig("test-node")
	nodeConfig.ValidityDays = 30
	node, err := GenerateNodeCert(nodeConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate node cert: %v", err)
	}

	tests := []struct {
		name          string
		testMode      bool
		thresholdDays int
		expectedRenew bool
	}{
		{"production mode - should renew when threshold is larger", false, 365, true},
		{"production mode - should not renew when threshold is smaller", false, 7, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{
				TestMode:             tt.testMode,
				RenewalThresholdDays: tt.thresholdDays,
			}
			if got := opts.ShouldRenewNode(node); got != tt.expectedRenew {
				t.Errorf("ShouldRenewNode() = %v, expected %v (threshold: %d days, expiry in: %d days)",
					got, tt.expectedRenew, tt.thresholdDays, node.DaysUntilExpiry())
			}
		})
	}
}

func TestCertificateOptions_ShouldRenewDashboard(t *testing.T) {
	// Create a CA first
	caConfig := DefaultCAConfig("test-ca")
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// Create a dashboard cert that expires in 30 days
	dashConfig := DefaultDashboardCertConfig()
	dashConfig.ValidityDays = 30
	dash, err := GenerateDashboardCert(dashConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate dashboard cert: %v", err)
	}

	opts := &CertificateOptions{
		TestMode:             false,
		RenewalThresholdDays: 365,
	}
	if !opts.ShouldRenewDashboard(dash) {
		t.Error("ShouldRenewDashboard() should return true when threshold is larger than remaining days")
	}

	opts.RenewalThresholdDays = 7
	if opts.ShouldRenewDashboard(dash) {
		t.Errorf("ShouldRenewDashboard() should return false when threshold is smaller than remaining days (threshold: %d, expiry in: %d days)",
			opts.RenewalThresholdDays, dash.DaysUntilExpiry())
	}
}

func TestCertificateOptions_ShouldRenewFilebeat(t *testing.T) {
	// Create a CA first
	caConfig := DefaultCAConfig("test-ca")
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// Create a filebeat cert that expires in 30 days
	fbConfig := DefaultFilebeatCertConfig()
	fbConfig.ValidityDays = 30
	fb, err := GenerateFilebeatCert(fbConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate filebeat cert: %v", err)
	}

	opts := &CertificateOptions{
		TestMode:             false,
		RenewalThresholdDays: 365,
	}
	if !opts.ShouldRenewFilebeat(fb) {
		t.Error("ShouldRenewFilebeat() should return true when threshold is larger than remaining days")
	}

	opts.RenewalThresholdDays = 7
	if opts.ShouldRenewFilebeat(fb) {
		t.Errorf("ShouldRenewFilebeat() should return false when threshold is smaller than remaining days (threshold: %d, expiry in: %d days)",
			opts.RenewalThresholdDays, fb.DaysUntilExpiry())
	}
}

func TestCertificateOptions_ShouldRenewAdmin(t *testing.T) {
	// Create a CA first
	caConfig := DefaultCAConfig("test-ca")
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// Create an admin cert that expires in 30 days
	adminConfig := DefaultAdminCertConfig()
	adminConfig.ValidityDays = 30
	admin, err := GenerateAdminCert(adminConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate admin cert: %v", err)
	}

	opts := &CertificateOptions{
		TestMode:             false,
		RenewalThresholdDays: 365,
	}
	if !opts.ShouldRenewAdmin(admin) {
		t.Error("ShouldRenewAdmin() should return true when threshold is larger than remaining days")
	}

	opts.RenewalThresholdDays = 7
	if opts.ShouldRenewAdmin(admin) {
		t.Errorf("ShouldRenewAdmin() should return false when threshold is smaller than remaining days (threshold: %d, expiry in: %d days)",
			opts.RenewalThresholdDays, admin.DaysUntilExpiry())
	}
}

func TestCertificateOptions_TestModeValidity(t *testing.T) {
	// Test that test mode correctly uses minutes instead of days
	opts := TestModeCertificateOptions()

	// Create a CA first
	caConfig := DefaultCAConfig("test-ca")
	caConfig.ValidityMinutes = 10 // 10 minute validity
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// The CA should expire in about 10 minutes
	minutesUntilExpiry := ca.MinutesUntilExpiry()
	if minutesUntilExpiry < 8 || minutesUntilExpiry > 11 {
		t.Errorf("expected CA to expire in ~10 minutes, got %d minutes", minutesUntilExpiry)
	}

	// With 2-minute threshold, should not need renewal yet
	opts.CARenewalThresholdMinutes = 2
	if opts.ShouldRenewCA(ca) {
		t.Error("CA with 10 min validity should not need renewal with 2 min threshold")
	}

	// With 15-minute threshold, should need renewal
	opts.CARenewalThresholdMinutes = 15
	if !opts.ShouldRenewCA(ca) {
		t.Error("CA with 10 min validity should need renewal with 15 min threshold")
	}
}

// Mock expiring certificate for edge case testing
type mockExpiringCert struct {
	notAfter time.Time
}

func TestCertificateOptions_RenewalEdgeCases(t *testing.T) {
	// Test that custom values from CRD are respected
	opts := &CertificateOptions{
		CAValidityDays:          1000,
		NodeValidityDays:        180,
		RenewalThresholdDays:    45,
		TestMode:                false,
		ValidityMinutes:         10,
		RenewalThresholdMinutes: 3,
	}

	if opts.GetCAValidityDays() != 1000 {
		t.Errorf("expected CAValidityDays 1000, got %d", opts.GetCAValidityDays())
	}
	if opts.GetNodeValidityDays() != 180 {
		t.Errorf("expected NodeValidityDays 180, got %d", opts.GetNodeValidityDays())
	}
	if opts.GetRenewalThresholdDays() != 45 {
		t.Errorf("expected RenewalThresholdDays 45, got %d", opts.GetRenewalThresholdDays())
	}
	if opts.GetValidityMinutes() != 10 {
		t.Errorf("expected ValidityMinutes 10, got %d", opts.GetValidityMinutes())
	}
	if opts.GetRenewalThresholdMinutes() != 3 {
		t.Errorf("expected RenewalThresholdMinutes 3, got %d", opts.GetRenewalThresholdMinutes())
	}
}
