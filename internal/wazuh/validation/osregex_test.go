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

package validation

import (
	"strings"
	"testing"
)

func TestValidateOSRegex(t *testing.T) {
	valid := []string{
		`^(\d+) (\w+)`,
		`\.+`,
		`user (\S+) from (\d+.\d+.\d+.\d+)`,
		`^sshd|^dropbear`,
		`\(\w+\) \| \$ \\ \t \p \< \W \D \S`,
		`"level":"(\w+)"`,
		`(.+?)`, // not a lazy quantifier in OS_Regex, but it compiles
	}
	for _, p := range valid {
		if err := ValidateOSRegex(p); err != nil {
			t.Errorf("ValidateOSRegex(%q) = %v, want nil", p, err)
		}
	}

	invalid := map[string]string{
		`\"level\":\"(\w+)\"`:      `unsupported escape \"`,
		`\x41`:                     `unsupported escape \x`,
		`abc\`:                     "trailing backslash",
		`((\d+))`:                  "nested parentheses",
		`(\d+`:                     "unbalanced parentheses",
		`\d+)`:                     "unbalanced parentheses",
		`(a|b)`:                    "'|' inside parentheses",
		strings.Repeat("a", 20481): "longer than",
	}
	for p, want := range invalid {
		err := ValidateOSRegex(p)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateOSRegex(%.40q) = %v, want an error containing %q", p, err, want)
		}
	}
}

func TestOSRegexFieldErrors(t *testing.T) {
	decoders := `<decoder name="app">
  <prematch>\<log>\.+\</log></prematch>
</decoder>
<decoder name="app-fields">
  <parent>app</parent>
  <regex offset="after_parent">\"level\":\"(\w+)\"</regex>
  <order>level</order>
</decoder>
<decoder name="app-pcre2">
  <parent>app</parent>
  <regex type="pcre2">"level":"(\w+)"</regex>
  <order>level</order>
</decoder>
<decoder name="app-entities">
  <prematch>^a &amp;&amp; \x</prematch>
</decoder>`
	errs := osRegexFieldErrors(decoders, decoderOSRegexFields, "decoder", "name")
	if len(errs) != 2 {
		t.Fatalf("got %d errors, want 2 (app-fields, app-entities): %v", len(errs), errs)
	}
	if !strings.Contains(errs[0], "decoder app-fields: invalid <regex>") {
		t.Errorf("errs[0] = %q, want it to name decoder app-fields", errs[0])
	}
	if !strings.Contains(errs[1], `decoder app-entities: invalid <prematch> "^a && \\x"`) {
		t.Errorf("errs[1] = %q, want the entity-decoded pattern of app-entities", errs[1])
	}

	rules := `<group name="local,">
  <rule id="100100" level="5">
    <field name="app.level">\"error\"</field>
    <regex type="osmatch">\"ignored\"</regex>
  </rule>
</group>`
	errs = osRegexFieldErrors(rules, ruleOSRegexFields, "rule", "id")
	if len(errs) != 1 || !strings.Contains(errs[0], "rule 100100: invalid <field>") {
		t.Errorf("got %v, want one error on the <field> of rule 100100", errs)
	}
}
