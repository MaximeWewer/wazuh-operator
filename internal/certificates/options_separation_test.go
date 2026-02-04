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
	"crypto/x509"
	"testing"
	"time"
)

func TestCANodeSeparation_IndependentValidity(t *testing.T) {
	tests := []struct {
		name           string
		caValidity     time.Duration
		nodeValidity   time.Duration
		expectCADays   int
		expectNodeDays int
	}{
		{
			name:           "Default values - CA 10 years, Node 1 year",
			caValidity:     MustParseCertDuration(DefaultCAValidityStr),
			nodeValidity:   MustParseCertDuration(DefaultNodeValidityStr),
			expectCADays:   3650,
			expectNodeDays: 365,
		},
		{
			name:           "Short CA for testing",
			caValidity:     30 * 24 * time.Hour, // 30 days
			nodeValidity:   7 * 24 * time.Hour,  // 7 days
			expectCADays:   30,
			expectNodeDays: 7,
		},
		{
			name:           "CA longer than default, Node shorter",
			caValidity:     5 * 365 * 24 * time.Hour, // 5 years
			nodeValidity:   180 * 24 * time.Hour,     // 180 days
			expectCADays:   1825,
			expectNodeDays: 180,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{
				CAValidity:   tt.caValidity,
				NodeValidity: tt.nodeValidity,
			}

			// Verify CA validity
			caValidity := opts.GetCAValidity()
			caDays := int(caValidity / (24 * time.Hour))
			if caDays != tt.expectCADays {
				t.Errorf("CA validity days = %d, want %d", caDays, tt.expectCADays)
			}

			// Verify Node validity
			nodeValidity := opts.GetNodeValidity()
			nodeDays := int(nodeValidity / (24 * time.Hour))
			if nodeDays != tt.expectNodeDays {
				t.Errorf("Node validity days = %d, want %d", nodeDays, tt.expectNodeDays)
			}
		})
	}
}

func TestCANodeSeparation_IndependentRenewalThresholds(t *testing.T) {
	tests := []struct {
		name                  string
		caRenewalThreshold    time.Duration
		nodeRenewalThreshold  time.Duration
		expectCARenewalDays   int
		expectNodeRenewalDays int
	}{
		{
			name:                  "Default thresholds - CA 60d, Node 30d",
			caRenewalThreshold:    MustParseCertDuration(DefaultCARenewalThresholdStr),
			nodeRenewalThreshold:  MustParseCertDuration(DefaultNodeRenewalThresholdStr),
			expectCARenewalDays:   60,
			expectNodeRenewalDays: 30,
		},
		{
			name:                  "Custom short thresholds",
			caRenewalThreshold:    10 * 24 * time.Hour,
			nodeRenewalThreshold:  5 * 24 * time.Hour,
			expectCARenewalDays:   10,
			expectNodeRenewalDays: 5,
		},
		{
			name:                  "Hours-based threshold for Node",
			caRenewalThreshold:    7 * 24 * time.Hour,
			nodeRenewalThreshold:  12 * time.Hour,
			expectCARenewalDays:   7,
			expectNodeRenewalDays: 0, // Less than a day
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &CertificateOptions{
				CARenewalThreshold: tt.caRenewalThreshold,
				RenewalThreshold:   tt.nodeRenewalThreshold,
			}

			// Verify CA renewal threshold
			caThreshold := opts.GetCARenewalThreshold()
			caDays := int(caThreshold / (24 * time.Hour))
			if caDays != tt.expectCARenewalDays {
				t.Errorf("CA renewal threshold days = %d, want %d", caDays, tt.expectCARenewalDays)
			}

			// Verify Node renewal threshold
			nodeThreshold := opts.GetRenewalThreshold()
			nodeDays := int(nodeThreshold / (24 * time.Hour))
			if nodeDays != tt.expectNodeRenewalDays {
				t.Errorf("Node renewal threshold days = %d, want %d", nodeDays, tt.expectNodeRenewalDays)
			}
		})
	}
}

func TestCANodeSeparation_ShouldRenewCA(t *testing.T) {
	opts := DefaultCertificateOptions()
	opts.CARenewalThreshold = 30 * 24 * time.Hour // 30 days

	tests := []struct {
		name         string
		daysToExpiry int
		shouldRenew  bool
	}{
		{
			name:         "CA expires in 60 days - should not renew",
			daysToExpiry: 60,
			shouldRenew:  false,
		},
		{
			name:         "CA expires in 30 days - should renew (exactly at threshold)",
			daysToExpiry: 30,
			shouldRenew:  true,
		},
		{
			name:         "CA expires in 15 days - should renew",
			daysToExpiry: 15,
			shouldRenew:  true,
		},
		{
			name:         "CA expires in 5 days - critical, should renew",
			daysToExpiry: 5,
			shouldRenew:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock CA result with the specified expiry
			caResult := &CAResult{
				Certificate: &x509.Certificate{
					NotAfter: time.Now().Add(time.Duration(tt.daysToExpiry) * 24 * time.Hour),
				},
			}

			shouldRenew := opts.ShouldRenewCA(caResult)
			if shouldRenew != tt.shouldRenew {
				t.Errorf("ShouldRenewCA() = %v, want %v", shouldRenew, tt.shouldRenew)
			}
		})
	}
}

func TestCANodeSeparation_ShouldRenewNode(t *testing.T) {
	opts := DefaultCertificateOptions()
	opts.RenewalThreshold = 7 * 24 * time.Hour // 7 days

	tests := []struct {
		name         string
		daysToExpiry int
		shouldRenew  bool
	}{
		{
			name:         "Node expires in 30 days - should not renew",
			daysToExpiry: 30,
			shouldRenew:  false,
		},
		{
			name:         "Node expires in 7 days - should renew (at threshold)",
			daysToExpiry: 7,
			shouldRenew:  true,
		},
		{
			name:         "Node expires in 3 days - should renew",
			daysToExpiry: 3,
			shouldRenew:  true,
		},
		{
			name:         "Node expires in 1 day - critical, should renew",
			daysToExpiry: 1,
			shouldRenew:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock Node result with the specified expiry
			nodeResult := &NodeCertResult{
				Certificate: &x509.Certificate{
					NotAfter: time.Now().Add(time.Duration(tt.daysToExpiry) * 24 * time.Hour),
				},
			}

			shouldRenew := opts.ShouldRenewNode(nodeResult)
			if shouldRenew != tt.shouldRenew {
				t.Errorf("ShouldRenewNode() = %v, want %v", shouldRenew, tt.shouldRenew)
			}
		})
	}
}

func TestCANodeSeparation_DifferentThresholds(t *testing.T) {
	// Test that CA and Node can have different thresholds and be evaluated independently
	opts := &CertificateOptions{
		CAValidity:         365 * 24 * time.Hour, // 1 year
		CARenewalThreshold: 60 * 24 * time.Hour,  // 60 days for CA
		NodeValidity:       90 * 24 * time.Hour,  // 90 days
		RenewalThreshold:   10 * 24 * time.Hour,  // 10 days for Node
	}

	// CA expires in 50 days - should be renewed (< 60 days)
	caResult := &CAResult{
		Certificate: &x509.Certificate{
			NotAfter: time.Now().Add(50 * 24 * time.Hour),
		},
	}

	// Node expires in 15 days - should NOT be renewed (> 10 days)
	nodeResult := &NodeCertResult{
		Certificate: &x509.Certificate{
			NotAfter: time.Now().Add(15 * 24 * time.Hour),
		},
	}

	caShouldRenew := opts.ShouldRenewCA(caResult)
	nodeShouldRenew := opts.ShouldRenewNode(nodeResult)

	if !caShouldRenew {
		t.Error("CA should be renewed (50 days < 60 day threshold)")
	}
	if nodeShouldRenew {
		t.Error("Node should NOT be renewed (15 days > 10 day threshold)")
	}

	// Now test the opposite scenario
	// CA expires in 90 days - should NOT be renewed (> 60 days)
	caResult2 := &CAResult{
		Certificate: &x509.Certificate{
			NotAfter: time.Now().Add(90 * 24 * time.Hour),
		},
	}

	// Node expires in 8 days - SHOULD be renewed (< 10 days)
	nodeResult2 := &NodeCertResult{
		Certificate: &x509.Certificate{
			NotAfter: time.Now().Add(8 * 24 * time.Hour),
		},
	}

	caShouldRenew2 := opts.ShouldRenewCA(caResult2)
	nodeShouldRenew2 := opts.ShouldRenewNode(nodeResult2)

	if caShouldRenew2 {
		t.Error("CA should NOT be renewed (90 days > 60 day threshold)")
	}
	if !nodeShouldRenew2 {
		t.Error("Node SHOULD be renewed (8 days < 10 day threshold)")
	}
}

func TestCANodeSeparation_MinutesPrecision(t *testing.T) {
	// Test that minute-level precision works for both CA and Node
	opts := &CertificateOptions{
		CARenewalThreshold: 30 * time.Minute, // 30 minutes for CA
		RenewalThreshold:   10 * time.Minute, // 10 minutes for Node
	}

	// CA expires in 20 minutes - should be renewed
	caResult := &CAResult{
		Certificate: &x509.Certificate{
			NotAfter: time.Now().Add(20 * time.Minute),
		},
	}

	// Node expires in 15 minutes - should NOT be renewed (> 10 minutes)
	nodeResult := &NodeCertResult{
		Certificate: &x509.Certificate{
			NotAfter: time.Now().Add(15 * time.Minute),
		},
	}

	if !opts.ShouldRenewCA(caResult) {
		t.Error("CA should be renewed (20 min < 30 min threshold)")
	}
	if opts.ShouldRenewNode(nodeResult) {
		t.Error("Node should NOT be renewed (15 min > 10 min threshold)")
	}

	// Node expires in 5 minutes - should be renewed
	nodeResult2 := &NodeCertResult{
		Certificate: &x509.Certificate{
			NotAfter: time.Now().Add(5 * time.Minute),
		},
	}
	if !opts.ShouldRenewNode(nodeResult2) {
		t.Error("Node should be renewed (5 min < 10 min threshold)")
	}
}

func TestCANodeSeparation_HoursPrecision(t *testing.T) {
	// Test that hour-level precision works
	opts := &CertificateOptions{
		CARenewalThreshold: 24 * time.Hour, // 24 hours (1 day) for CA
		RenewalThreshold:   12 * time.Hour, // 12 hours for Node
	}

	// CA expires in 18 hours - should be renewed
	caResult := &CAResult{
		Certificate: &x509.Certificate{
			NotAfter: time.Now().Add(18 * time.Hour),
		},
	}

	if !opts.ShouldRenewCA(caResult) {
		t.Error("CA should be renewed (18h < 24h threshold)")
	}

	// Node expires in 6 hours - should be renewed
	nodeResult := &NodeCertResult{
		Certificate: &x509.Certificate{
			NotAfter: time.Now().Add(6 * time.Hour),
		},
	}

	if !opts.ShouldRenewNode(nodeResult) {
		t.Error("Node should be renewed (6h < 12h threshold)")
	}
}
