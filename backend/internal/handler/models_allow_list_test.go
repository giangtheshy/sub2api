package handler

import (
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Advertising a model in GET /v1/models and then answering 403 when it is asked
// for is a contradiction the client cannot resolve. The listing has to agree
// with the gate.
func TestModelsListingHidesModelsTheGroupWillReject(t *testing.T) {
	group := &service.Group{AllowedModels: []string{"claude-sonnet-*"}}
	source := []string{"claude-sonnet-4-5", "claude-opus-5", "claude-sonnet-5"}

	got := filterModelsByGroupAllowList(source, group)

	if len(got) != 2 || got[0] != "claude-sonnet-4-5" || got[1] != "claude-sonnet-5" {
		t.Errorf("filtered = %v, want the two sonnet entries in order", got)
	}
}

// An unconfigured group must see the full list unchanged, including groups that
// exist today and have never been touched.
func TestModelsListingUnchangedWithoutAnAllowList(t *testing.T) {
	source := []string{"claude-opus-5", "gpt-5.2"}

	for _, group := range []*service.Group{nil, {}, {AllowedModels: []string{}}} {
		got := filterModelsByGroupAllowList(source, group)
		if strings.Join(got, ",") != strings.Join(source, ",") {
			t.Errorf("filtered = %v, want %v unchanged", got, source)
		}
	}
}

// For OpenAI, GetAvailableModels returns an empty non-nil list when every mapped
// model is retired. That answer is authoritative: falling back to the defaults
// would resurrect retired IDs (gpt-5.5) that dispatch then refuses.
func TestAllowListListingSourceKeepsAuthoritativeEmptyOpenAICatalog(t *testing.T) {
	got := allowListListingSource(service.PlatformOpenAI, []string{})

	if got == nil || len(got) != 0 {
		t.Errorf("source = %v, want the empty catalog kept", got)
	}
}

func TestAllowListListingSourceFallsBackToDefaults(t *testing.T) {
	cases := []struct {
		platform  string
		available []string
	}{
		{service.PlatformOpenAI, nil},
		{service.PlatformAnthropic, nil},
		{service.PlatformAnthropic, []string{}},
	}
	for _, tc := range cases {
		got := allowListListingSource(tc.platform, tc.available)
		want := defaultModelIDsForPlatform(tc.platform)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s %#v: source = %v, want defaults %v", tc.platform, tc.available, got, want)
		}
	}
}

func TestAllowListListingSourceKeepsNonEmptyCatalog(t *testing.T) {
	available := []string{"gpt-5.2"}

	got := allowListListingSource(service.PlatformOpenAI, available)

	if strings.Join(got, ",") != "gpt-5.2" {
		t.Errorf("source = %v, want %v", got, available)
	}
}

// A list that filters everything out must yield an empty list, not fall back to
// the unfiltered one — silently serving what the operator excluded would be the
// worst possible reading of an allow-list.
func TestModelsListingCanFilterEverything(t *testing.T) {
	group := &service.Group{AllowedModels: []string{"gpt-5.2"}}

	got := filterModelsByGroupAllowList([]string{"claude-opus-5"}, group)

	if len(got) != 0 {
		t.Errorf("filtered = %v, want empty", got)
	}
}
