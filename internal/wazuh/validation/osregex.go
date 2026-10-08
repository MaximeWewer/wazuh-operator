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
	"encoding/xml"
	"fmt"
	"strings"
)

// osRegexMaxSize is OS_PATTERN_MAXSIZE from Wazuh's os_regex.h.
const osRegexMaxSize = 20480

// osRegexEscapes are the characters OSRegex_Compile accepts after a backslash.
const osRegexEscapes = `dwspDWS().t$|<\`

// ValidateOSRegex reports the errors Wazuh's OSRegex_Compile (src/os_regex/os_regex_compile.c)
// rejects a pattern for: an unknown escape (e.g. \" or \x), a trailing backslash, nested or
// unbalanced parentheses, a '|' inside parentheses, or an oversized pattern. analysisd stops
// on such a decoder or rule, so the manager crash-loops.
func ValidateOSRegex(pattern string) error {
	if len(pattern) > osRegexMaxSize {
		return fmt.Errorf("pattern longer than %d characters", osRegexMaxSize)
	}
	depth := 0
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '\\':
			i++
			if i == len(pattern) {
				return fmt.Errorf("trailing backslash")
			}
			if !strings.ContainsRune(osRegexEscapes, rune(pattern[i])) {
				return fmt.Errorf("unsupported escape \\%c (OS_Regex only supports \\w \\W \\d \\D \\s \\S \\p \\t \\. \\$ \\( \\) \\| \\< \\\\; "+
					"use type=\"pcre2\" for a full regular expression)", pattern[i])
			}
		case '(':
			depth++
			if depth > 1 {
				return fmt.Errorf("nested parentheses (OS_Regex allows one level)")
			}
		case ')':
			depth--
			if depth < 0 {
				return fmt.Errorf("unbalanced parentheses")
			}
		case '|':
			if depth != 0 {
				return fmt.Errorf("'|' inside parentheses")
			}
		}
	}
	if depth != 0 {
		return fmt.Errorf("unbalanced parentheses")
	}
	return nil
}

// osRegexFieldErrors checks the text of every element named in fields whose type is OS_Regex
// (no type attribute, or type="osregex"). owner is the element that names the errors (decoder
// or rule) and ownerAttr the attribute holding its name or id.
func osRegexFieldErrors(content string, fields map[string]bool, owner, ownerAttr string) []string {
	var errs []string
	ownerName := ""
	wrapped := "<root>" + content + "</root>"
	dec := xml.NewDecoder(strings.NewReader(wrapped))
	for {
		tok, err := dec.Token()
		if err != nil {
			// io.EOF ends the walk; syntax errors are reported by the XML syntax check.
			return errs
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		name := strings.ToLower(start.Name.Local)
		if name == owner {
			ownerName = xmlAttr(start, ownerAttr)
			continue
		}
		if !fields[name] {
			continue
		}
		if t := strings.ToLower(xmlAttr(start, "type")); t != "" && t != "osregex" {
			continue
		}
		// Read the raw element body rather than its XML text: Wazuh's XML parser takes
		// "\<" as an escaped '<' (e.g. <regex>\<log>(\.+)\</log></regex>), where a
		// standard parser would see nested elements.
		bodyStart := dec.InputOffset()
		if err := dec.Skip(); err != nil {
			return errs
		}
		body := wrapped[bodyStart:dec.InputOffset()]
		body = body[:strings.LastIndex(body, "</")]
		text := xmlEntities.Replace(body)
		if err := ValidateOSRegex(text); err != nil {
			errs = append(errs, fmt.Sprintf("%s %s: invalid <%s> %q: %v", owner, ownerName, start.Name.Local, text, err))
		}
	}
}

// xmlEntities decodes the predefined XML entities of a raw element body.
var xmlEntities = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&")

// xmlAttr returns the value of an element attribute, matched case-insensitively.
func xmlAttr(e xml.StartElement, name string) string {
	for _, a := range e.Attr {
		if strings.EqualFold(a.Name.Local, name) {
			return a.Value
		}
	}
	return ""
}
