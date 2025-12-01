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
)

func TestFormatDN(t *testing.T) {
	tests := []struct {
		name       string
		commonName string
		ou         string
		org        string
		locality   string
		state      string
		country    string
		expected   string
	}{
		{
			name:       "standard DN",
			commonName: "admin",
			ou:         "Wazuh",
			org:        "Wazuh",
			locality:   "California",
			state:      "California",
			country:    "US",
			expected:   "CN=admin,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US",
		},
		{
			name:       "wildcard CN",
			commonName: "*",
			ou:         "Wazuh",
			org:        "Wazuh",
			locality:   "California",
			state:      "California",
			country:    "US",
			expected:   "CN=*,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US",
		},
		{
			name:       "custom organization",
			commonName: "node1",
			ou:         "IT",
			org:        "MyCompany",
			locality:   "Paris",
			state:      "Ile-de-France",
			country:    "FR",
			expected:   "CN=node1,OU=IT,O=MyCompany,L=Paris,ST=Ile-de-France,C=FR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatDN(tt.commonName, tt.ou, tt.org, tt.locality, tt.state, tt.country)
			if result != tt.expected {
				t.Errorf("FormatDN() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestDefaultAdminDN(t *testing.T) {
	expected := "CN=admin,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US"
	result := DefaultAdminDN()

	if result != expected {
		t.Errorf("DefaultAdminDN() = %q, want %q", result, expected)
	}
}

func TestDefaultNodesDN(t *testing.T) {
	expected := "CN=*,OU=Wazuh,O=Wazuh,L=California,ST=California,C=US"
	result := DefaultNodesDN()

	if result != expected {
		t.Errorf("DefaultNodesDN() = %q, want %q", result, expected)
	}
}

func TestDefaultCAConfig(t *testing.T) {
	commonName := "test-ca"
	config := DefaultCAConfig(commonName)

	if config.CommonName != commonName {
		t.Errorf("CommonName = %q, want %q", config.CommonName, commonName)
	}
	if config.Organization != DefaultOrganization {
		t.Errorf("Organization = %q, want %q", config.Organization, DefaultOrganization)
	}
	if config.OrganizationalUnit != DefaultOrganizationalUnit {
		t.Errorf("OrganizationalUnit = %q, want %q", config.OrganizationalUnit, DefaultOrganizationalUnit)
	}
	if config.Country != DefaultCountry {
		t.Errorf("Country = %q, want %q", config.Country, DefaultCountry)
	}
	if config.State != DefaultState {
		t.Errorf("State = %q, want %q", config.State, DefaultState)
	}
	if config.Locality != DefaultLocality {
		t.Errorf("Locality = %q, want %q", config.Locality, DefaultLocality)
	}
	if config.ValidityDays != DefaultCAValidityDays {
		t.Errorf("ValidityDays = %d, want %d", config.ValidityDays, DefaultCAValidityDays)
	}
	if config.KeySize != DefaultKeySize {
		t.Errorf("KeySize = %d, want %d", config.KeySize, DefaultKeySize)
	}
}
