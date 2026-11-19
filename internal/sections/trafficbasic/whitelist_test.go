package trafficbasic

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/divinelabio/aegis/internal/infra/requestctx"
	"github.com/divinelabio/aegis/internal/sections"
)

func TestWhitelistBypassesTrafficControls(t *testing.T) {
	tests := []struct {
		name   string
		client string
		target string
	}{
		{name: "exact IP", client: "203.0.113.10", target: "203.0.113.10"},
		{name: "CIDR", client: "198.51.100.10", target: "198.51.100.0/24"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			section := New(nil, nil)
			settings := map[string]interface{}{
				"blacklist": map[string]interface{}{
					"enabled": true,
					"ips":     []string{test.client},
				},
				"whitelist": map[string]interface{}{
					"enabled": true,
					"entries": []map[string]interface{}{{"target": test.target}},
				},
			}
			if err := section.Init(sections.SectionConfig{Enabled: true, ProtectionLevel: 3, Settings: settings}); err != nil {
				t.Fatalf("Init() error = %v", err)
			}

			nextCalled := false
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				nextCalled = true
				if !requestctx.HasWhitelistBypass(r.Context()) {
					t.Error("downstream request is missing whitelist bypass marker")
				}
			})
			request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			request.RemoteAddr = test.client + ":12345"
			recorder := httptest.NewRecorder()
			section.Middleware(next).ServeHTTP(recorder, request)

			if !nextCalled {
				t.Fatal("whitelisted request did not reach the next handler")
			}
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
			}
		})
	}
}

func TestExpiredWhitelistEntryDoesNotBypassBlacklist(t *testing.T) {
	section := New(nil, nil)
	client := "203.0.113.10"
	settings := map[string]interface{}{
		"blacklist": map[string]interface{}{
			"enabled": true,
			"ips":     []string{client},
		},
		"whitelist": map[string]interface{}{
			"enabled": true,
			"entries": []map[string]interface{}{{
				"target":     client,
				"expires_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			}},
		},
	}
	if err := section.Init(sections.SectionConfig{Enabled: true, ProtectionLevel: 3, Settings: settings}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	nextCalled := false
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = client + ":12345"
	recorder := httptest.NewRecorder()
	section.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })).ServeHTTP(recorder, request)

	if nextCalled {
		t.Fatal("expired whitelist entry bypassed the blacklist")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}