package oauth

import (
	"strings"
	"testing"
)

// Synthetic tokens — never real credentials.
const (
	batchFirst  = `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-FIRST","refreshToken":"sk-ant-ort01-FIRST","expiresAt":1787183506000,"subscriptionType":"max_20x"}}`
	batchSecond = `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-SECOND","refreshToken":"sk-ant-ort01-SECOND","expiresAt":1787197125235,"subscriptionType":"default_claude_ai"}}`
	batchBare   = `{"accessToken":"sk-ant-oat01-THIRD","refreshToken":"sk-ant-ort01-THIRD","expiresAt":1787197125235}`
)

func refreshTokensOf(t *testing.T, raw string) []string {
	t.Helper()
	parsed, err := ParseClaudeOAuthCredentialsMany(raw)
	if err != nil {
		t.Fatalf("ParseClaudeOAuthCredentialsMany() error = %v", err)
	}
	tokens := make([]string, 0, len(parsed))
	for _, credentials := range parsed {
		tokens = append(tokens, credentials.RefreshToken)
	}
	return tokens
}

func TestParseClaudeOAuthCredentialsManyAcceptsBatchShapes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "single wrapped object stays a one-item batch",
			raw:  batchFirst,
			want: []string{"sk-ant-ort01-FIRST"},
		},
		{
			name: "json array",
			raw:  "[" + batchFirst + "," + batchSecond + "]",
			want: []string{"sk-ant-ort01-FIRST", "sk-ant-ort01-SECOND"},
		},
		{
			name: "one object per line",
			raw:  batchFirst + "\n" + batchSecond,
			want: []string{"sk-ant-ort01-FIRST", "sk-ant-ort01-SECOND"},
		},
		{
			name: "blank lines between objects",
			raw:  batchFirst + "\n\n\n" + batchSecond + "\n",
			want: []string{"sk-ant-ort01-FIRST", "sk-ant-ort01-SECOND"},
		},
		{
			name: "concatenated without separators",
			raw:  batchFirst + batchSecond,
			want: []string{"sk-ant-ort01-FIRST", "sk-ant-ort01-SECOND"},
		},
		{
			name: "wrapped and bare objects mixed",
			raw:  batchFirst + "\n" + batchBare,
			want: []string{"sk-ant-ort01-FIRST", "sk-ant-ort01-THIRD"},
		},
		{
			name: "surrounding whitespace ignored",
			raw:  "  \n\t" + batchFirst + "\n  " + batchSecond + "  \n",
			want: []string{"sk-ant-ort01-FIRST", "sk-ant-ort01-SECOND"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := refreshTokensOf(t, tt.raw)
			if len(got) != len(tt.want) {
				t.Fatalf("parsed %d credentials, want %d (%v)", len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("credential %d refresh token = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// The same account pasted twice must not become two accounts racing over one
// upstream identity, so duplicates collapse on the refresh token.
func TestParseClaudeOAuthCredentialsManyCollapsesDuplicates(t *testing.T) {
	got := refreshTokensOf(t, batchFirst+"\n"+batchSecond+"\n"+batchFirst)

	if len(got) != 2 {
		t.Fatalf("parsed %d credentials, want 2 (%v)", len(got), got)
	}
	if got[0] != "sk-ant-ort01-FIRST" || got[1] != "sk-ant-ort01-SECOND" {
		t.Errorf("unexpected order/content: %v", got)
	}
}

func TestParseClaudeOAuthCredentialsManyPreservesFields(t *testing.T) {
	parsed, err := ParseClaudeOAuthCredentialsMany("[" + batchFirst + "," + batchSecond + "]")
	if err != nil {
		t.Fatalf("ParseClaudeOAuthCredentialsMany() error = %v", err)
	}

	if parsed[0].AccessToken != "sk-ant-oat01-FIRST" {
		t.Errorf("first access token = %q", parsed[0].AccessToken)
	}
	// 1787183506000 ms normalizes to seconds.
	if parsed[0].ExpiresAt != 1787183506 {
		t.Errorf("first expiry = %d, want 1787183506", parsed[0].ExpiresAt)
	}
	if parsed[0].SubscriptionType != "max_20x" {
		t.Errorf("first subscription = %q", parsed[0].SubscriptionType)
	}
	if parsed[1].SubscriptionType != "default_claude_ai" {
		t.Errorf("second subscription = %q", parsed[1].SubscriptionType)
	}
}

// A bad entry fails the whole call and names its position: creating fewer
// accounts than pasted without saying which one vanished is worse than an error.
func TestParseClaudeOAuthCredentialsManyRejectsBadEntry(t *testing.T) {
	const missingRefresh = `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-NOREFRESH","expiresAt":1787183506000}}`

	_, err := ParseClaudeOAuthCredentialsMany(batchFirst + "\n" + missingRefresh)
	if err == nil {
		t.Fatal("expected an error for the incomplete second credential")
	}
	if !strings.Contains(err.Error(), "#2") {
		t.Errorf("error should name the failing position, got %q", err)
	}
	if !strings.Contains(err.Error(), "refreshToken") {
		t.Errorf("error should explain what is missing, got %q", err)
	}
}

func TestParseClaudeOAuthCredentialsManyRejectsEmptyInput(t *testing.T) {
	for _, raw := range []string{"", "   \n\t ", "[]"} {
		if _, err := ParseClaudeOAuthCredentialsMany(raw); err == nil {
			t.Errorf("expected an error for input %q", raw)
		}
	}
}

// A single malformed paste keeps the plain message — position numbering would
// only be noise when there is nothing to disambiguate.
func TestParseClaudeOAuthCredentialsManySingleErrorHasNoPosition(t *testing.T) {
	_, err := ParseClaudeOAuthCredentialsMany(`{"accessToken":"sk-ant-oat01-ONLY"}`)
	if err == nil {
		t.Fatal("expected an error for the incomplete credential")
	}
	if strings.Contains(err.Error(), "#") {
		t.Errorf("single-entry error should not be numbered, got %q", err)
	}
}
