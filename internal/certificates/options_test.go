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

func TestDefaultCertificateOptions(t *testing.T) {
	opts := DefaultCertificateOptions()

	expectedCAValidity := MustParseCertDuration(DefaultCAValidityStr)
	expectedNodeValidity := MustParseCertDuration(DefaultNodeValidityStr)
	expectedRenewalThreshold := MustParseCertDuration(DefaultNodeRenewalThresholdStr)

	if opts.CAValidity != expectedCAValidity {
		t.Errorf("expected CAValidity %v, got %v", expectedCAValidity, opts.CAValidity)
	}
	if opts.NodeValidity != expectedNodeValidity {
		t.Errorf("expected NodeValidity %v, got %v", expectedNodeValidity, opts.NodeValidity)
	}
	if opts.RenewalThreshold != expectedRenewalThreshold {
		t.Errorf("expected RenewalThreshold %v, got %v", expectedRenewalThreshold, opts.RenewalThreshold)
	}
	if opts.KeyAlgorithm != KeyAlgorithmRSA {
		t.Errorf("expected KeyAlgorithm RSA, got %s", opts.KeyAlgorithm)
	}
	if opts.ECDSACurve != ECDSACurveP256 {
		t.Errorf("expected ECDSACurve P256, got %s", opts.ECDSACurve)
	}
}

func TestCertificateOptions_GetCAValidity(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected time.Duration
	}{
		{"returns configured value when positive", 100 * 24 * time.Hour, 100 * 24 * time.Hour},
		{"returns default when zero", 0, MustParseCertDuration(DefaultCAValidityStr)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{CAValidity: tt.input}
			if got := opts.GetCAValidity(); got != tt.expected {
				t.Errorf("GetCAValidity() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestCertificateOptions_GetNodeValidity(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected time.Duration
	}{
		{"returns configured value when positive", 90 * 24 * time.Hour, 90 * 24 * time.Hour},
		{"returns default when zero", 0, MustParseCertDuration(DefaultNodeValidityStr)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{NodeValidity: tt.input}
			if got := opts.GetNodeValidity(); got != tt.expected {
				t.Errorf("GetNodeValidity() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestCertificateOptions_GetRenewalThreshold(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected time.Duration
	}{
		{"returns configured value when positive", 60 * 24 * time.Hour, 60 * 24 * time.Hour},
		{"returns default when zero", 0, MustParseCertDuration(DefaultNodeRenewalThresholdStr)},
		{"returns 30 minutes", 30 * time.Minute, 30 * time.Minute},
		{"returns 2 hours", 2 * time.Hour, 2 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{RenewalThreshold: tt.input}
			if got := opts.GetRenewalThreshold(); got != tt.expected {
				t.Errorf("GetRenewalThreshold() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestCertificateOptions_ShouldRenewCA(t *testing.T) {
	// Create a CA that expires in 30 days
	caConfig := DefaultCAConfig("test-ca")
	caConfig.Validity = 30 * 24 * time.Hour // 30 days validity
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	tests := []struct {
		name          string
		threshold     time.Duration
		expectedRenew bool
	}{
		{"should renew when threshold is larger than remaining time", 365 * 24 * time.Hour, true},
		{"should not renew when threshold is smaller than remaining time", 7 * 24 * time.Hour, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{
				CARenewalThreshold: tt.threshold,
			}
			if got := opts.ShouldRenewCA(ca); got != tt.expectedRenew {
				t.Errorf("ShouldRenewCA() = %v, expected %v (threshold: %v, expiry in: %d days)",
					got, tt.expectedRenew, tt.threshold, ca.DaysUntilExpiry())
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
	nodeConfig.Validity = 30 * 24 * time.Hour
	node, err := GenerateNodeCert(nodeConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate node cert: %v", err)
	}

	tests := []struct {
		name          string
		threshold     time.Duration
		expectedRenew bool
	}{
		{"should renew when threshold is larger", 365 * 24 * time.Hour, true},
		{"should not renew when threshold is smaller", 7 * 24 * time.Hour, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{
				RenewalThreshold: tt.threshold,
			}
			if got := opts.ShouldRenewNode(node); got != tt.expectedRenew {
				t.Errorf("ShouldRenewNode() = %v, expected %v (threshold: %v, expiry in: %d days)",
					got, tt.expectedRenew, tt.threshold, node.DaysUntilExpiry())
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
	dashConfig.Validity = 30 * 24 * time.Hour
	dash, err := GenerateDashboardCert(dashConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate dashboard cert: %v", err)
	}

	opts := &CertificateOptions{
		DashboardRenewalThreshold: 365 * 24 * time.Hour,
	}
	if !opts.ShouldRenewDashboard(dash) {
		t.Error("ShouldRenewDashboard() should return true when threshold is larger than remaining days")
	}

	opts.DashboardRenewalThreshold = 7 * 24 * time.Hour
	if opts.ShouldRenewDashboard(dash) {
		t.Errorf("ShouldRenewDashboard() should return false when threshold is smaller than remaining days (threshold: %v, expiry in: %d days)",
			opts.DashboardRenewalThreshold, dash.DaysUntilExpiry())
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
	fbConfig.Validity = 30 * 24 * time.Hour
	fb, err := GenerateFilebeatCert(fbConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate filebeat cert: %v", err)
	}

	opts := &CertificateOptions{
		FilebeatRenewalThreshold: 365 * 24 * time.Hour,
	}
	if !opts.ShouldRenewFilebeat(fb) {
		t.Error("ShouldRenewFilebeat() should return true when threshold is larger than remaining days")
	}

	opts.FilebeatRenewalThreshold = 7 * 24 * time.Hour
	if opts.ShouldRenewFilebeat(fb) {
		t.Errorf("ShouldRenewFilebeat() should return false when threshold is smaller than remaining days (threshold: %v, expiry in: %d days)",
			opts.FilebeatRenewalThreshold, fb.DaysUntilExpiry())
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
	adminConfig.Validity = 30 * 24 * time.Hour
	admin, err := GenerateAdminCert(adminConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate admin cert: %v", err)
	}

	opts := &CertificateOptions{
		AdminRenewalThreshold: 365 * 24 * time.Hour,
	}
	if !opts.ShouldRenewAdmin(admin) {
		t.Error("ShouldRenewAdmin() should return true when threshold is larger than remaining days")
	}

	opts.AdminRenewalThreshold = 7 * 24 * time.Hour
	if opts.ShouldRenewAdmin(admin) {
		t.Errorf("ShouldRenewAdmin() should return false when threshold is smaller than remaining days (threshold: %v, expiry in: %d days)",
			opts.AdminRenewalThreshold, admin.DaysUntilExpiry())
	}
}

func TestCertificateOptions_RenewalEdgeCases(t *testing.T) {
	// Test that custom values from CRD are respected
	opts := &CertificateOptions{
		CAValidity:       1000 * 24 * time.Hour,
		NodeValidity:     180 * 24 * time.Hour,
		RenewalThreshold: 45 * 24 * time.Hour,
		KeyAlgorithm:     KeyAlgorithmECDSA,
		ECDSACurve:       ECDSACurveP384,
	}

	if opts.GetCAValidity() != 1000*24*time.Hour {
		t.Errorf("expected CAValidity 1000d, got %v", opts.GetCAValidity())
	}
	if opts.GetNodeValidity() != 180*24*time.Hour {
		t.Errorf("expected NodeValidity 180d, got %v", opts.GetNodeValidity())
	}
	if opts.GetRenewalThreshold() != 45*24*time.Hour {
		t.Errorf("expected RenewalThreshold 45d, got %v", opts.GetRenewalThreshold())
	}
	if opts.KeyAlgorithm != KeyAlgorithmECDSA {
		t.Errorf("expected KeyAlgorithm ECDSA, got %s", opts.KeyAlgorithm)
	}
	if opts.ECDSACurve != ECDSACurveP384 {
		t.Errorf("expected ECDSACurve P384, got %s", opts.ECDSACurve)
	}
}

func TestCertificateOptions_ECDSASupport(t *testing.T) {
	// Test ECDSA certificate generation through options
	opts := &CertificateOptions{
		CAValidity:   365 * 24 * time.Hour,
		NodeValidity: 90 * 24 * time.Hour,
		KeyAlgorithm: KeyAlgorithmECDSA,
		ECDSACurve:   ECDSACurveP256,
	}

	// Generate CA with ECDSA
	caConfig := DefaultCAConfig("test-ca")
	caConfig.KeyAlgorithm = opts.KeyAlgorithm
	caConfig.ECDSACurve = opts.ECDSACurve
	caConfig.Validity = opts.CAValidity
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate ECDSA CA: %v", err)
	}

	// Verify CA was created
	if ca.Certificate == nil {
		t.Error("expected CA certificate to be generated")
	}
	if ca.PrivateKey == nil {
		t.Error("expected CA private key to be generated")
	}

	// Generate node cert with ECDSA signed by ECDSA CA
	nodeConfig := DefaultNodeCertConfig("test-node")
	nodeConfig.KeyAlgorithm = opts.KeyAlgorithm
	nodeConfig.ECDSACurve = opts.ECDSACurve
	nodeConfig.Validity = opts.NodeValidity
	node, err := GenerateNodeCert(nodeConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate ECDSA node cert: %v", err)
	}

	if node.Certificate == nil {
		t.Error("expected node certificate to be generated")
	}
	if node.PrivateKey == nil {
		t.Error("expected node private key to be generated")
	}
}

func TestCertificateOptions_P384Curve(t *testing.T) {
	// Test P-384 curve support
	caConfig := DefaultCAConfig("test-ca-p384")
	caConfig.KeyAlgorithm = KeyAlgorithmECDSA
	caConfig.ECDSACurve = ECDSACurveP384
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate P-384 CA: %v", err)
	}

	if ca.Certificate == nil {
		t.Error("expected P-384 CA certificate to be generated")
	}

	// Generate admin cert with P-384
	adminConfig := DefaultAdminCertConfig()
	adminConfig.KeyAlgorithm = KeyAlgorithmECDSA
	adminConfig.ECDSACurve = ECDSACurveP384
	admin, err := GenerateAdminCert(adminConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate P-384 admin cert: %v", err)
	}

	if admin.Certificate == nil {
		t.Error("expected P-384 admin certificate to be generated")
	}
}

func TestCertificateOptions_MinuteGranularity(t *testing.T) {
	// Test certificate generation with minute-level validity (for testing scenarios)
	caConfig := DefaultCAConfig("test-ca-minutes")
	caConfig.Validity = 10 * time.Minute // 10 minutes validity
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate short-lived CA: %v", err)
	}

	// Verify the certificate has correct validity
	validityDuration := ca.Certificate.NotAfter.Sub(ca.Certificate.NotBefore)
	// Allow for small timing differences (within 1 second)
	expectedMin := 10*time.Minute - time.Second
	expectedMax := 10*time.Minute + time.Second
	if validityDuration < expectedMin || validityDuration > expectedMax {
		t.Errorf("expected validity ~10m, got %v", validityDuration)
	}

	// Test node cert with hour-level validity
	nodeConfig := DefaultNodeCertConfig("test-node-hours")
	nodeConfig.Validity = 2 * time.Hour // 2 hours validity
	node, err := GenerateNodeCert(nodeConfig, ca)
	if err != nil {
		t.Fatalf("failed to generate short-lived node cert: %v", err)
	}

	nodeValidity := node.Certificate.NotAfter.Sub(node.Certificate.NotBefore)
	expectedNodeMin := 2*time.Hour - time.Second
	expectedNodeMax := 2*time.Hour + time.Second
	if nodeValidity < expectedNodeMin || nodeValidity > expectedNodeMax {
		t.Errorf("expected node validity ~2h, got %v", nodeValidity)
	}
}

func TestCertificateOptions_RenewalWithMinuteThreshold(t *testing.T) {
	// Create a CA that expires in 5 minutes
	caConfig := DefaultCAConfig("test-ca-short")
	caConfig.Validity = 5 * time.Minute
	ca, err := GenerateCA(caConfig)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	// Test with 10-minute threshold (should trigger renewal)
	opts := &CertificateOptions{
		CARenewalThreshold: 10 * time.Minute,
	}
	if !opts.ShouldRenewCA(ca) {
		t.Error("ShouldRenewCA() should return true when 10m threshold > 5m remaining")
	}

	// Test with 2-minute threshold (should not trigger renewal)
	opts.CARenewalThreshold = 2 * time.Minute
	if opts.ShouldRenewCA(ca) {
		t.Error("ShouldRenewCA() should return false when 2m threshold < 5m remaining")
	}
}
