package storage

import (
	"strings"
	"testing"
)

func TestBuildTrafficEventsWhereDefaultsToTrafficSection(t *testing.T) {
	where, _, err := buildTrafficEventsWhere(TrafficEventsQuery{Window: "24h"})
	if err != nil {
		t.Fatalf("buildTrafficEventsWhere() error = %v", err)
	}
	if !strings.Contains(where, "section = 'traffic'") {
		t.Fatalf("buildTrafficEventsWhere() = %q, want traffic section filter", where)
	}
}