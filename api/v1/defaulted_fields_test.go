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

package v1

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestNoOmitemptyOnDefaultedFields guards against a silent spec-drift bug.
//
// A field declared as a plain scalar with both `,omitempty` and a non-zero
// +kubebuilder:default cannot hold an explicit zero value: the operator writes
// the whole CR back (when it adds its finalizer, for instance), encoding/json
// drops the zero value from the body, and the API server re-applies the
// default. `enableSSL: false` flips back to true a second after GitOps applies
// it, and nothing reports the drift - the rendered manifest never changes and
// Helm never patches the field again.
//
// Fields whose zero value is a legitimate setting must therefore be pointers,
// read through ptr.Deref(field, <default>). The check covers:
//   - every bool, since false is always a meaningful value;
//   - integers marked +kubebuilder:validation:Minimum=0, which says explicitly
//     that 0 is within range.
//
// Strings are left out on purpose: an empty string means "unset" everywhere in
// this API, so it is not a value a user can lose.
func TestNoOmitemptyOnDefaultedFields(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob api types: %v", err)
	}

	fset := token.NewFileSet()
	for _, file := range files {
		base := filepath.Base(file)
		if strings.HasSuffix(base, "_test.go") || strings.HasPrefix(base, "zz_generated") {
			continue
		}

		parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}

		ast.Inspect(parsed, func(n ast.Node) bool {
			structType, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range structType.Fields.List {
				checkDefaultedField(t, fset, field)
			}
			return true
		})
	}
}

// zeroDefaults maps a scalar type to the marker values equal to its zero value.
// A default equal to the zero value is harmless next to omitempty: dropping the
// key and sending the zero value mean the same thing.
var zeroDefaults = map[string]map[string]bool{
	"bool":  {"false": true},
	"int":   {"0": true},
	"int8":  {"0": true},
	"int16": {"0": true},
	"int32": {"0": true},
	"int64": {"0": true},
}

func checkDefaultedField(t *testing.T, fset *token.FileSet, field *ast.Field) {
	t.Helper()

	ident, ok := field.Type.(*ast.Ident)
	if !ok || field.Tag == nil {
		return
	}
	zeros, checked := zeroDefaults[ident.Name]
	if !checked {
		return
	}

	tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Get("json")
	if !slices.Contains(strings.Split(tag, ",")[1:], "omitempty") {
		return
	}

	markers := fieldMarkers(field.Doc)
	def, hasDefault := markers["default"]
	if !hasDefault || zeros[def] {
		return
	}
	// Integers are only at risk when 0 is a value the schema accepts.
	if ident.Name != "bool" && markers["validation:Minimum"] != "0" {
		return
	}

	name := "<embedded>"
	if len(field.Names) > 0 {
		name = field.Names[0].Name
	}
	t.Errorf("%s: %s (%s) has both `omitempty` and +kubebuilder:default=%s, so an explicit "+
		"zero value cannot survive a write-back of the CR; make it a *%s read through "+
		"ptr.Deref(field, %s)",
		fset.Position(field.Pos()), name, ident.Name, def, ident.Name, def)
}

// fieldMarkers collects the +kubebuilder markers of a field's doc comment,
// keyed without the "+kubebuilder:" prefix.
func fieldMarkers(doc *ast.CommentGroup) map[string]string {
	markers := map[string]string{}
	if doc == nil {
		return markers
	}
	for _, comment := range doc.List {
		text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
		rest, ok := strings.CutPrefix(text, "+kubebuilder:")
		if !ok {
			continue
		}
		key, value, ok := strings.Cut(rest, "=")
		if !ok {
			continue
		}
		markers[key] = strings.TrimSpace(value)
	}
	return markers
}
