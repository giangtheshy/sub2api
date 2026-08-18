package service

import "testing"

func accountWithExclusions(excluded any) *Account {
	return &Account{
		ID:       3,
		Platform: PlatformAnthropic,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key":         "sk-ant-api03-x",
			"excluded_models": excluded,
		},
	}
}

// The point of an exclusion list: keep the account open to everything, minus a
// few. A whitelist cannot express this — it would have to enumerate every other
// model, and would then silently reject each new model on release.
func TestExcludedModelIsRejectedWhileTheRestStayAllowed(t *testing.T) {
	// JSON round-trips through map[string]any, so the stored value is []any.
	account := accountWithExclusions([]any{"claude-opus-5"})

	if account.IsModelSupported("claude-opus-5") {
		t.Error("excluded model was allowed")
	}
	if !account.IsModelSupported("claude-sonnet-4-5") {
		t.Error("an unrelated model was rejected; exclusion must not close the account")
	}
}

func TestExcludedModelsAcceptAStringSlice(t *testing.T) {
	account := accountWithExclusions([]string{"claude-opus-5"})

	if account.IsModelSupported("claude-opus-5") {
		t.Error("excluded model was allowed when stored as []string")
	}
}

func TestExcludedModelsSupportWildcards(t *testing.T) {
	account := accountWithExclusions([]any{"claude-opus-*"})

	for _, model := range []string{"claude-opus-5", "claude-opus-4-6"} {
		if account.IsModelSupported(model) {
			t.Errorf("%s was allowed despite the wildcard exclusion", model)
		}
	}
	if !account.IsModelSupported("claude-sonnet-5") {
		t.Error("wildcard exclusion leaked outside its prefix")
	}
}

func TestEmptyExclusionListChangesNothing(t *testing.T) {
	for _, empty := range []any{nil, []any{}, []string{}, []any{"", "  "}} {
		account := accountWithExclusions(empty)
		if !account.IsModelSupported("claude-opus-5") {
			t.Errorf("empty exclusion list (%v) blocked a model", empty)
		}
	}
}

// Exclusion has to beat the model_mapping whitelist, otherwise an operator who
// lists a model in both gets the opposite of the more specific instruction.
func TestExclusionOverridesTheMappingWhitelist(t *testing.T) {
	account := &Account{
		ID: 4, Platform: PlatformAnthropic, Type: AccountTypeAPIKey,
		Credentials: map[string]any{
			"model_mapping":   map[string]any{"claude-opus-5": "claude-opus-5"},
			"excluded_models": []any{"claude-opus-5"},
		},
	}

	if account.IsModelSupported("claude-opus-5") {
		t.Error("whitelist beat the exclusion; the narrower instruction must win")
	}
}

// Passthrough accounts allow every model by design, because the upstream owns
// the model namespace. An explicit exclusion is a deliberate operator statement
// and outranks that default — otherwise the field would appear to work in the
// panel and quietly do nothing on exactly the accounts that forward everything.
func TestExclusionOverridesOpenAIPassthrough(t *testing.T) {
	account := &Account{
		ID: 5, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key":         "sk-x",
			"excluded_models": []any{"gpt-5.2-pro"},
		},
		Extra: map[string]any{"openai_passthrough": true},
	}
	if !account.IsOpenAIPassthroughEnabled() {
		t.Skip("fixture did not enable passthrough; the override cannot be exercised")
	}

	if account.IsModelSupported("gpt-5.2-pro") {
		t.Error("passthrough overrode an explicit exclusion")
	}
	if !account.IsModelSupported("gpt-5.2") {
		t.Error("passthrough account stopped allowing an unexcluded model")
	}
}
