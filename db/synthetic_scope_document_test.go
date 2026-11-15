package db

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSyntheticScopeDocumentRejectsAmbiguity(t *testing.T) {
	for _, tc := range []struct {
		name, document string
		valid          bool
	}{
		{"ordinary", `{"targets":["synthetic.invalid"],"methods":["read"]}`, true},
		{"separate objects", `{"items":[{"id":1},{"id":2}]}`, true},
		{"escaped backslash", `{"note":"\\ud800"}`, true},
		{"surrogate pair", `{"note":"\ud83d\ude80"}`, true},
		{"root duplicate", `{"targets":[],"targets":["other"]}`, false},
		{"escaped duplicate", `{"targets":[],"\u0074argets":["other"]}`, false},
		{"nested duplicate", `{"targets":[{"id":1,"id":2}]}`, false},
		{"unicode duplicate", `{"🚀":1,"\ud83d\ude80":2}`, false},
		{"unpaired high surrogate", `{"note":"\ud800"}`, false},
		{"unpaired low surrogate", `{"note":"\udc00"}`, false},
		{"bad surrogate pair", `{"note":"\ud800\u0041"}`, false},
		{"invalid utf8", "{\"note\":\"\xff\"}", false},
		{"empty", `{}`, false},
		{"array root", `[{"id":1}]`, false},
		{"trailing value", `{"id":1}{"id":2}`, false},
		{"incomplete", `{"id":`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validSyntheticScopeDocument([]byte(tc.document)); got != tc.valid {
				t.Fatalf("valid=%v, want %v", got, tc.valid)
			}
		})
	}
	for _, depth := range []struct {
		arrays int
		valid  bool
	}{{maxSyntheticScopeDepth - 1, true}, {maxSyntheticScopeDepth, false}} {
		document := `{"a":` + strings.Repeat("[", depth.arrays) + `null` + strings.Repeat("]", depth.arrays) + `}`
		if got := validSyntheticScopeDocument([]byte(document)); got != depth.valid {
			t.Fatalf("nested arrays=%d valid=%v, want %v", depth.arrays, got, depth.valid)
		}
	}
	const prefix, suffix = `{"note":"`, `"}`
	atLimit := prefix + strings.Repeat("a", 65536-len(prefix)-len(suffix)) + suffix
	if !validSyntheticScopeDocument([]byte(atLimit)) || validSyntheticScopeDocument([]byte(atLimit+" ")) {
		t.Fatal("scope document byte limit not enforced")
	}
}

func FuzzSyntheticScopeDocument(f *testing.F) {
	for _, seed := range []string{
		`{"targets":["synthetic.invalid"]}`,
		`{"a":1,"\u0061":2}`,
		`{"a":"\ud800"}`,
		`{"a":"\ud83d\ude80"}`,
		`{"a":[{"b":true}]}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, document []byte) {
		if !validSyntheticScopeDocument(document) {
			return
		}
		if !utf8.Valid(document) || !json.Valid(document) {
			t.Fatal("accepted document is not valid UTF-8 JSON")
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(document, &object); err != nil || len(object) == 0 {
			t.Fatalf("accepted document is not a nonempty object: %v", err)
		}
	})
}
