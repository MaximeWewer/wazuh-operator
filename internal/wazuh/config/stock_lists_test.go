package config

import (
	"strings"
	"testing"
)

func TestStockRulesetLists(t *testing.T) {
	tests := map[string][]string{
		"4.9.0":   {"etc/lists/audit-keys"},
		"4.13.1":  {"etc/lists/audit-keys"},
		"4.14.0":  {"etc/lists/audit-keys", "etc/lists/malicious-ioc/malware-hashes", "etc/lists/malicious-ioc/malicious-ip", "etc/lists/malicious-ioc/malicious-domains"},
		"v4.14.2": {"etc/lists/audit-keys", "etc/lists/malicious-ioc/malware-hashes", "etc/lists/malicious-ioc/malicious-ip", "etc/lists/malicious-ioc/malicious-domains"},
		"":        {"etc/lists/audit-keys"},
	}
	for version, want := range tests {
		if got := StockRulesetLists(version); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("StockRulesetLists(%q) = %v, want %v", version, got, want)
		}
	}
}
