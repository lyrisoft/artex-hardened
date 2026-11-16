package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScopeRequestRejectsAmbiguousInputs(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType, path string
		duplicateContentType          bool
		want                          bool
	}{
		{"valid", `{"reason":"fixture"}`, "application/json", "/", false, true},
		{"utf8 charset", `{"reason":"fixture"}`, "application/json; charset=UTF-8", "/", false, true},
		{"duplicate key", `{"reason":"a","reason":"b"}`, "application/json", "/", false, false},
		{"case variant", `{"Reason":"fixture"}`, "application/json", "/", false, false},
		{"unknown field", `{"reason":"fixture","extra":true}`, "application/json", "/", false, false},
		{"unpaired unicode", `{"reason":"\ud800"}`, "application/json", "/", false, false},
		{"other content type", `{"reason":"fixture"}`, "text/plain", "/", false, false},
		{"unknown parameter", `{"reason":"fixture"}`, "application/json; x=y", "/", false, false},
		{"duplicate content type", `{"reason":"fixture"}`, "application/json", "/", true, false},
		{"query", `{"reason":"fixture"}`, "application/json", "/?x=1", false, false},
		{"oversize", `{"reason":"` + strings.Repeat("a", maxTeamScopeRequest) + `"}`, "application/json", "/", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://app.example.test"+tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			if tc.duplicateContentType {
				r.Header.Add("Content-Type", "text/plain")
			}
			_, got := scopeRequest(r, "reason")
			if got != tc.want {
				t.Fatalf("accepted=%v want %v", got, tc.want)
			}
		})
	}
	for _, reason := range []string{"", "  ", "bad\nline", strings.Repeat("x", 1025)} {
		if validScopeReason(reason) {
			t.Fatal("invalid revocation reason accepted")
		}
	}
	if !validScopeReason("synthetic fixture finished") {
		t.Fatal("valid reason rejected")
	}
}
