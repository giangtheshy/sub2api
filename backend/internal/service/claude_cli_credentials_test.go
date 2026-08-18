package service

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func anthropicOAuthAccountForExport() *Account {
	return &Account{
		ID:       5,
		Name:     "acc share",
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"access_token":  "sk-ant-oat01-export-test",
			"refresh_token": "sk-ant-ort01-export-test",
			"expires_at":    strconv.FormatInt(time.Now().Add(8*time.Hour).Unix(), 10),
			"scope":         "user:profile user:inference user:sessions:claude_code",
		},
	}
}

// The single most damaging way to get this wrong. sub2api stores expires_at in
// Unix seconds; Claude CLI reads expiresAt as milliseconds. Emit seconds and
// the CLI resolves 1970, treats the token as long expired, and refreshes
// immediately — rotating the refresh token and killing the sub2api account for
// no reason at all.
func TestExportConvertsExpiryToMilliseconds(t *testing.T) {
	account := anthropicOAuthAccountForExport()
	seconds, err := strconv.ParseInt(account.GetCredential("expires_at"), 10, 64)
	if err != nil {
		t.Fatalf("fixture expires_at: %v", err)
	}

	export, err := BuildClaudeCLICredentials(account, ClaudeCLIExportOptions{})
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	if got, want := export.Credentials.ClaudeAiOauth.ExpiresAt, seconds*1000; got != want {
		t.Errorf("ExpiresAt = %d, want %d (seconds x 1000)", got, want)
	}
}

// Defence against the same bug arriving from the other side: if a stored value
// is already in milliseconds, multiplying again lands the expiry ~50,000 years
// out, so the CLI would never refresh and would fail with a dead token instead.
func TestExportDoesNotRescaleAValueAlreadyInMilliseconds(t *testing.T) {
	account := anthropicOAuthAccountForExport()
	millis := time.Now().Add(8 * time.Hour).UnixMilli()
	account.Credentials["expires_at"] = strconv.FormatInt(millis, 10)

	export, err := BuildClaudeCLICredentials(account, ClaudeCLIExportOptions{})
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	if got := export.Credentials.ClaudeAiOauth.ExpiresAt; got != millis {
		t.Errorf("ExpiresAt = %d, want %d unchanged", got, millis)
	}
}

// sub2api stores scope as one space-separated string; the CLI wants an array.
func TestExportSplitsScopeIntoArray(t *testing.T) {
	export, err := BuildClaudeCLICredentials(anthropicOAuthAccountForExport(), ClaudeCLIExportOptions{})
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	want := []string{"user:profile", "user:inference", "user:sessions:claude_code"}
	got := export.Credentials.ClaudeAiOauth.Scopes
	if len(got) != len(want) {
		t.Fatalf("Scopes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Scopes = %v, want %v", got, want)
		}
	}
	if export.Credentials.ClaudeAiOauth.AccessToken != "sk-ant-oat01-export-test" {
		t.Error("AccessToken was not carried through")
	}
}

// We do not store the subscription tier, and inventing one tells the CLI
// something we do not know. Absent is honest; "max" would be a guess.
func TestExportOmitsSubscriptionTypeItDoesNotKnow(t *testing.T) {
	export, err := BuildClaudeCLICredentials(anthropicOAuthAccountForExport(), ClaudeCLIExportOptions{})
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	if export.Credentials.ClaudeAiOauth.SubscriptionType != nil {
		t.Errorf("SubscriptionType = %q, want nil", *export.Credentials.ClaudeAiOauth.SubscriptionType)
	}
}

// A missing scope must not silently become an empty array — the CLI would then
// hold a credential whose permissions it cannot describe. Fall back to the
// scope the account type was granted, and say out loud that it was inferred.
func TestExportFlagsAnInferredScope(t *testing.T) {
	account := anthropicOAuthAccountForExport()
	delete(account.Credentials, "scope")

	export, err := BuildClaudeCLICredentials(account, ClaudeCLIExportOptions{})
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	if len(export.Credentials.ClaudeAiOauth.Scopes) == 0 {
		t.Error("Scopes is empty; the CLI needs something to work with")
	}
	if !hasWarning(export.Warnings, ClaudeCLIWarningInferredScopes) {
		t.Errorf("warnings = %v, want %q", export.Warnings, ClaudeCLIWarningInferredScopes)
	}
}

// A setup-token account only ever held user:inference. Exporting it is allowed,
// but the CLI will be missing the scopes some of its features need, so the
// operator has to be told rather than left to discover it mid-session.
func TestExportWarnsOnSetupTokenScope(t *testing.T) {
	account := anthropicOAuthAccountForExport()
	account.Type = AccountTypeSetupToken
	account.Credentials["scope"] = "user:inference"

	export, err := BuildClaudeCLICredentials(account, ClaudeCLIExportOptions{})
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	if !hasWarning(export.Warnings, ClaudeCLIWarningLimitedScopes) {
		t.Errorf("warnings = %v, want %q", export.Warnings, ClaudeCLIWarningLimitedScopes)
	}
}

// "We withheld it" and "the account does not have one" produce the same file
// but call for opposite responses. Withheld means re-export when it expires —
// sub2api will have refreshed by then. Missing means sub2api cannot refresh
// either, so re-exporting yields another dead token and the account itself
// needs re-authorizing. Collapsing the two would send the operator in circles.
func TestExportDistinguishesAMissingRefreshTokenFromAWithheldOne(t *testing.T) {
	account := anthropicOAuthAccountForExport()
	delete(account.Credentials, "refresh_token")

	for _, include := range []bool{false, true} {
		export, err := BuildClaudeCLICredentials(account, ClaudeCLIExportOptions{IncludeRefreshToken: include})
		if err != nil {
			t.Fatalf("BuildClaudeCLICredentials(include=%v): %v", include, err)
		}

		if export.Credentials.ClaudeAiOauth.RefreshToken != "" {
			t.Error("RefreshToken should be empty, not fabricated")
		}
		if !hasWarning(export.Warnings, ClaudeCLIWarningNoRefreshToken) {
			t.Errorf("include=%v: warnings = %v, want %q", include, export.Warnings, ClaudeCLIWarningNoRefreshToken)
		}
		if hasWarning(export.Warnings, ClaudeCLIWarningRefreshTokenWithheld) {
			t.Errorf("include=%v: warnings = %v claims we withheld a token the account never had",
				include, export.Warnings)
		}
	}
}

// The default withholds the refresh token, and that default is the whole
// safety property: a CLI that never receives one cannot rotate the credential,
// so sub2api stays the sole owner and the account cannot be broken from
// outside. This is enforced by absence of capability, not by asking the CLI
// to behave.
func TestExportWithholdsTheRefreshTokenByDefault(t *testing.T) {
	export, err := BuildClaudeCLICredentials(anthropicOAuthAccountForExport(), ClaudeCLIExportOptions{})
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	if got := export.Credentials.ClaudeAiOauth.RefreshToken; got != "" {
		t.Errorf("RefreshToken = %q, want it withheld by default", got)
	}
	if !hasWarning(export.Warnings, ClaudeCLIWarningRefreshTokenWithheld) {
		t.Errorf("warnings = %v, want %q", export.Warnings, ClaudeCLIWarningRefreshTokenWithheld)
	}
	// Rotation cannot happen without a refresh token, so warning about it here
	// would be noise — and noise is what stops operators reading warnings.
	if hasWarning(export.Warnings, ClaudeCLIWarningRefreshRotation) {
		t.Errorf("warnings = %v must not mention rotation when nothing can rotate", export.Warnings)
	}
}

// The serialized file must not carry the secret either — a struct field left
// empty is worthless if omitempty is missing and the key ships as "".
func TestWithheldRefreshTokenIsAbsentFromTheSerializedFile(t *testing.T) {
	account := anthropicOAuthAccountForExport()
	export, err := BuildClaudeCLICredentials(account, ClaudeCLIExportOptions{})
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	encoded, err := json.Marshal(export.Credentials)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "sk-ant-ort01-export-test") {
		t.Errorf("refresh token leaked into the file: %s", encoded)
	}
	if strings.Contains(string(encoded), "refreshToken") {
		t.Errorf("refreshToken key should be absent entirely: %s", encoded)
	}
	if !strings.Contains(string(encoded), "sk-ant-oat01-export-test") {
		t.Errorf("access token missing from the file: %s", encoded)
	}
}

// Opting in is still supported — some operators want a CLI that survives past
// expiry — but then the rotation collision is real and must be stated.
func TestExportIncludesRefreshTokenOnlyWhenAsked(t *testing.T) {
	export, err := BuildClaudeCLICredentials(
		anthropicOAuthAccountForExport(),
		ClaudeCLIExportOptions{IncludeRefreshToken: true},
	)
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	if got := export.Credentials.ClaudeAiOauth.RefreshToken; got != "sk-ant-ort01-export-test" {
		t.Errorf("RefreshToken = %q, want it carried through when requested", got)
	}
	if !hasWarning(export.Warnings, ClaudeCLIWarningRefreshRotation) {
		t.Errorf("warnings = %v, want %q", export.Warnings, ClaudeCLIWarningRefreshRotation)
	}
	if hasWarning(export.Warnings, ClaudeCLIWarningRefreshTokenWithheld) {
		t.Errorf("warnings = %v claims the token was withheld while sending it", export.Warnings)
	}
}

// Exporting a token that has already expired is allowed — the refresh token
// still recovers it — but it means the CLI refreshes on first use, which fires
// the rotation collision immediately instead of hours later. That difference
// decides whether the operator should export now or refresh the account first.
func TestExportWarnsWhenTheAccessTokenHasAlreadyExpired(t *testing.T) {
	account := anthropicOAuthAccountForExport()
	account.Credentials["expires_at"] = strconv.FormatInt(time.Now().Add(-2*time.Hour).Unix(), 10)

	export, err := BuildClaudeCLICredentials(account, ClaudeCLIExportOptions{})
	if err != nil {
		t.Fatalf("BuildClaudeCLICredentials: %v", err)
	}

	if !hasWarning(export.Warnings, ClaudeCLIWarningAlreadyExpired) {
		t.Errorf("warnings = %v, want %q", export.Warnings, ClaudeCLIWarningAlreadyExpired)
	}
	if export.ExpiresInSeconds != 0 {
		t.Errorf("ExpiresInSeconds = %d, want 0 rather than a negative countdown", export.ExpiresInSeconds)
	}
}

// Only an Anthropic OAuth or setup-token account holds the token pair the CLI
// expects. Cookie accounts hold a claude.ai browser session, and the other
// platforms' oauth accounts hold tokens for entirely different upstreams —
// exporting either produces a file that cannot work and leaks a credential for
// nothing.
func TestExportRejectsAccountsWithoutAnAnthropicOAuthToken(t *testing.T) {
	cases := []struct {
		name    string
		account *Account
	}{
		{"cookie", cookieAccountForUpstreamTest()},
		{
			"openai oauth",
			&Account{
				ID: 9, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
				Credentials: map[string]any{"access_token": "openai-token"},
			},
		},
		{
			"anthropic apikey",
			&Account{
				ID: 10, Platform: PlatformAnthropic, Type: AccountTypeAPIKey,
				Credentials: map[string]any{"api_key": "sk-ant-api03-x"},
			},
		},
		{
			"anthropic oauth with no access token",
			&Account{
				ID: 11, Platform: PlatformAnthropic, Type: AccountTypeOAuth,
				Credentials: map[string]any{},
			},
		},
		{"nil", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			export, err := BuildClaudeCLICredentials(tc.account, ClaudeCLIExportOptions{})
			if err == nil {
				t.Fatalf("BuildClaudeCLICredentials returned an export for a %s account", tc.name)
			}
			if export != nil {
				t.Error("an export was returned alongside the error")
			}
		})
	}
}

func hasWarning(warnings []string, want string) bool {
	for _, w := range warnings {
		if w == want {
			return true
		}
	}
	return false
}
