package service

import "testing"

// An empty list must mean "no restriction", not "nothing allowed". Getting this
// backwards would silently break every existing group the moment the column is
// added, because they all start empty.
func TestEmptyAllowedModelsAllowsEverything(t *testing.T) {
	g := &Group{}

	for _, model := range []string{"claude-opus-5", "gpt-5.2", "", "anything"} {
		if !g.AllowsModel(model) {
			t.Errorf("AllowsModel(%q) = false on an unconfigured group; every existing group would break", model)
		}
	}
}

func TestAllowedModelsMatchesExactly(t *testing.T) {
	g := &Group{AllowedModels: []string{"claude-sonnet-4-5", "claude-haiku-4-5"}}

	if !g.AllowsModel("claude-sonnet-4-5") {
		t.Error("listed model was rejected")
	}
	if g.AllowsModel("claude-opus-5") {
		t.Error("unlisted model was allowed")
	}
}

// Wildcards are the reason this list stays correct as Anthropic ships new
// models. A literal list silently excludes every future release.
func TestAllowedModelsSupportsTrailingWildcard(t *testing.T) {
	g := &Group{AllowedModels: []string{"claude-sonnet-*"}}

	for _, model := range []string{"claude-sonnet-4-5", "claude-sonnet-5", "claude-sonnet-9-future"} {
		if !g.AllowsModel(model) {
			t.Errorf("AllowsModel(%q) = false; the wildcard should cover it", model)
		}
	}
	if g.AllowsModel("claude-opus-5") {
		t.Error("wildcard leaked outside its prefix")
	}
}

// Blank and whitespace-only entries are what a textarea produces on a stray
// newline. Treating one as a pattern would match nothing and quietly narrow
// the group; treating the list as empty would quietly widen it. Neither is
// acceptable, so blanks are dropped and the remaining entries still apply.
func TestAllowedModelsIgnoresBlankEntries(t *testing.T) {
	g := &Group{AllowedModels: []string{"", "  ", "claude-opus-5"}}

	if !g.AllowsModel("claude-opus-5") {
		t.Error("real entry stopped working because of a blank neighbour")
	}
	if g.AllowsModel("gpt-5.2") {
		t.Error("a blank entry was treated as a match-all")
	}
}

// A list containing nothing but blanks carries no operator intent at all, so it
// must behave like an unconfigured group rather than locking everyone out.
func TestAllowedModelsOfOnlyBlanksAllowsEverything(t *testing.T) {
	g := &Group{AllowedModels: []string{"", "   "}}

	if !g.AllowsModel("claude-opus-5") {
		t.Error("a list of blanks locked the group out entirely")
	}
}

// Model names arrive from clients in whatever case they typed.
func TestAllowedModelsIsCaseInsensitive(t *testing.T) {
	g := &Group{AllowedModels: []string{"Claude-Opus-5"}}

	if !g.AllowsModel("claude-opus-5") {
		t.Error("case difference rejected a listed model")
	}
}

// A nil group is not a configured restriction.
func TestNilGroupAllowsEverything(t *testing.T) {
	var g *Group
	if !g.AllowsModel("claude-opus-5") {
		t.Error("nil group rejected a model")
	}
}
