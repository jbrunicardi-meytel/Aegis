package wafbasic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/divinelabio/aegis/internal/infra/requestctx"
	"github.com/divinelabio/aegis/internal/sections"
)

func TestMiddlewareSkipsWAFForWhitelistedRequest(t *testing.T) {
	section := New(nil)
	if err := section.Init(sections.SectionConfig{
		Enabled:        true,
		ProtectionLevel: 3,
		Settings:       map[string]interface{}{"engine": map[string]interface{}{"enable_crs": false}},
	}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	nextCalled := false
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request = request.WithContext(requestctx.WithWhitelistBypass(context.Background()))
	section.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })).ServeHTTP(httptest.NewRecorder(), request)

	if !nextCalled {
		t.Fatal("whitelisted request did not reach the next handler")
	}
	if got := section.total.Load(); got != 0 {
		t.Fatalf("WAF transaction count = %d, want 0 for bypassed request", got)
	}
}

func TestInitPreservesRuleIDsInExclusionsData(t *testing.T) {
	var settings map[string]interface{}
	err := json.Unmarshal([]byte(`{"engine":{"enable_crs":false},"exclusions_data":[{"id":"first","rule_id":"932235","paths":["/first"],"enabled":true,"created_at":"2026-11-16T15:36:00.697224788Z"},{"id":"second","rule_id":"941100","paths":["/second"],"enabled":true,"created_at":"2026-11-16T15:37:00Z"}]}`), &settings)
	if err != nil {
		t.Fatal(err)
	}

	section := New(nil)
	if err := section.Init(sections.SectionConfig{Enabled: true, Settings: settings}); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if len(section.exclusions) != 2 {
		t.Fatalf("got %d exclusions, want 2", len(section.exclusions))
	}
	for index, want := range []string{"932235", "941100"} {
		if got := section.exclusions[index].RuleID; got != want {
			t.Errorf("exclusions[%d].RuleID = %q, want %q", index, got, want)
		}
	}
}

func TestIsInternalCRSRule(t *testing.T) {
	tests := []struct {
		name string
		id   int
		want bool
	}{
		{name: "initialization rule", id: 900000, want: true},
		{name: "anomaly evaluation rule", id: 949110, want: true},
		{name: "phase one paranoia marker", id: 913013, want: true},
		{name: "phase two paranoia marker", id: 911012, want: true},
		{name: "response paranoia marker", id: 959018, want: true},
		{name: "XSS target optimization control", id: 941010, want: true},
		{name: "inbound score aggregation", id: 949052, want: true},
		{name: "outbound score aggregation", id: 959052, want: true},
		{name: "correlation reporting", id: 980170, want: true},
		{name: "scanner detection rule", id: 913100, want: false},
		{name: "LFI detection rule", id: 930130, want: false},
		{name: "XSS detection rule", id: 941100, want: false},
		{name: "unrelated custom rule", id: 123013, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInternalCRSRule(tt.id); got != tt.want {
				t.Errorf("isInternalCRSRule(%d) = %t, want %t", tt.id, got, tt.want)
			}
		})
	}
}