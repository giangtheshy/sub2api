package service

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
)

// ClaudeCLICredentialsFileName is the file Claude Code reads on startup. The
// leading dot is part of the name — ".credentials.json", not "credentials.json"
// — and getting it wrong produces a file the CLI silently ignores.
const ClaudeCLICredentialsFileName = ".credentials.json"

// Warning codes returned alongside an export. They are codes rather than
// sentences so the panel can translate them; the operator has to be able to
// read this in their own language or they will not read it at all.
const (
	// ClaudeCLIWarningRefreshRotation applies only to opt-in exports that
	// carry the refresh token. Anthropic rotates refresh tokens, so once the
	// CLI refreshes, the copy sub2api holds is dead and this account starts
	// failing with invalid_grant — and vice versa. Two holders, one credential.
	ClaudeCLIWarningRefreshRotation = "refresh_token_rotation"
	// ClaudeCLIWarningRefreshTokenWithheld is the default outcome: the file
	// carries an access token only. The CLI works until that token expires
	// and then asks for a login; the operator exports again, by which point
	// sub2api has refreshed. sub2api remains the sole owner throughout.
	ClaudeCLIWarningRefreshTokenWithheld = "refresh_token_withheld"
	// ClaudeCLIWarningNoRefreshToken means the account itself holds no refresh
	// token. This looks identical in the produced file but calls for the
	// opposite response: sub2api cannot refresh either, so exporting again
	// later yields another dead token and the account needs re-authorizing.
	ClaudeCLIWarningNoRefreshToken = "no_refresh_token"
	// ClaudeCLIWarningInferredScopes means the account had no stored scope
	// and we substituted the one its type is granted. It is a reasonable
	// guess, not a fact, so it is declared as such.
	ClaudeCLIWarningInferredScopes = "inferred_scopes"
	// ClaudeCLIWarningLimitedScopes means the credential lacks user:profile,
	// so parts of the CLI that need it will not work.
	ClaudeCLIWarningLimitedScopes = "limited_scopes"
	// ClaudeCLIWarningAlreadyExpired means the access token is already past
	// its expiry, so the CLI will refresh on first use — immediately
	// triggering the rotation collision above.
	ClaudeCLIWarningAlreadyExpired = "access_token_expired"
)

// millisecondEpochFloor separates a second-based timestamp from a millisecond
// one. As milliseconds this is 2001-09-09; as seconds it is the year 33658.
// Anything at or above it can only be milliseconds.
const millisecondEpochFloor int64 = 1_000_000_000_000

// ClaudeCLIOAuth mirrors the claudeAiOauth object inside Claude Code's
// credentials file. Field names are camelCase because that file is not ours —
// it is read by another program and its spelling is the contract.
type ClaudeCLIOAuth struct {
	AccessToken  string   `json:"accessToken"`
	RefreshToken string   `json:"refreshToken,omitempty"`
	ExpiresAt    int64    `json:"expiresAt,omitempty"`
	Scopes       []string `json:"scopes"`
	// SubscriptionType is a pointer so an unknown tier is omitted rather
	// than asserted. sub2api does not store the tier, and writing "max"
	// would be telling the CLI something we do not know.
	SubscriptionType *string `json:"subscriptionType,omitempty"`
}

// ClaudeCLICredentials is the whole file: one key, one object.
type ClaudeCLICredentials struct {
	ClaudeAiOauth ClaudeCLIOAuth `json:"claudeAiOauth"`
}

// ClaudeCLIExportOptions selects what the produced file is allowed to contain.
//
// The zero value is the safe one on purpose: it withholds the refresh token,
// which is what keeps sub2api the sole owner of the credential. Every caller
// therefore has to opt in explicitly to the sharing behaviour, and a caller
// that forgets to think about it gets the conservative outcome.
type ClaudeCLIExportOptions struct {
	// IncludeRefreshToken hands the CLI the ability to refresh — and so to
	// rotate the token out from under this account. Off unless asked.
	IncludeRefreshToken bool
}

// ClaudeCLIExport carries the file plus what the panel needs to explain it.
type ClaudeCLIExport struct {
	Credentials      ClaudeCLICredentials `json:"credentials"`
	FileName         string               `json:"file_name"`
	ExpiresAtMs      int64                `json:"expires_at_ms,omitempty"`
	ExpiresInSeconds int64                `json:"expires_in_seconds,omitempty"`
	Warnings         []string             `json:"warnings,omitempty"`
}

// BuildClaudeCLICredentials renders an account's stored OAuth token as the
// credentials file Claude Code expects.
//
// It is deliberately pure: no repository, no context, no clock injection
// beyond time.Now for the remaining-lifetime hint. The mapping is where the
// bugs live (unit and shape mismatches between what sub2api stores and what
// the CLI reads), so it is worth testing on its own.
func BuildClaudeCLICredentials(account *Account, opts ClaudeCLIExportOptions) (*ClaudeCLIExport, error) {
	if account == nil {
		return nil, fmt.Errorf("account not found")
	}
	// Only an Anthropic OAuth or setup-token account holds the token pair the
	// CLI expects. A cookie account holds a claude.ai browser session, and the
	// other platforms' oauth accounts hold tokens for entirely different
	// upstreams — either would produce a file that cannot work while still
	// putting a live credential on screen.
	if !account.IsAnthropicOAuthOrSetupToken() {
		return nil, fmt.Errorf(
			"account %d is %s/%s; only Anthropic OAuth and setup-token accounts hold credentials Claude CLI can use",
			account.ID, account.Platform, account.Type)
	}

	accessToken := strings.TrimSpace(account.GetCredential("access_token"))
	if accessToken == "" {
		return nil, fmt.Errorf("account %d has no access token to export", account.ID)
	}

	// Three distinct situations that must not be collapsed into one message,
	// because the operator's next move differs in each:
	//   - the account has no refresh token  -> re-authorize the account here
	//   - we withheld it (default)          -> re-export when this one expires
	//   - the caller asked for it           -> one owner only; expect a break
	var (
		storedRefreshToken = strings.TrimSpace(account.GetCredential("refresh_token"))
		exportedRefresh    string
		warnings           []string
	)
	switch {
	case storedRefreshToken == "":
		warnings = append(warnings, ClaudeCLIWarningNoRefreshToken)
	case opts.IncludeRefreshToken:
		exportedRefresh = storedRefreshToken
		warnings = append(warnings, ClaudeCLIWarningRefreshRotation)
	default:
		warnings = append(warnings, ClaudeCLIWarningRefreshTokenWithheld)
	}

	scopes, inferred := claudeCLIScopes(account)
	if inferred {
		warnings = append(warnings, ClaudeCLIWarningInferredScopes)
	}
	if !containsScope(scopes, "user:profile") {
		warnings = append(warnings, ClaudeCLIWarningLimitedScopes)
	}

	expiresAtMs := claudeCLIExpiryMillis(account.GetCredential("expires_at"))
	var expiresInSeconds int64
	if expiresAtMs > 0 {
		expiresInSeconds = (expiresAtMs - time.Now().UnixMilli()) / 1000
		if expiresInSeconds <= 0 {
			expiresInSeconds = 0
			warnings = append(warnings, ClaudeCLIWarningAlreadyExpired)
		}
	}

	return &ClaudeCLIExport{
		Credentials: ClaudeCLICredentials{
			ClaudeAiOauth: ClaudeCLIOAuth{
				AccessToken:  accessToken,
				RefreshToken: exportedRefresh,
				ExpiresAt:    expiresAtMs,
				Scopes:       scopes,
			},
		},
		FileName:         ClaudeCLICredentialsFileName,
		ExpiresAtMs:      expiresAtMs,
		ExpiresInSeconds: expiresInSeconds,
		Warnings:         warnings,
	}, nil
}

// claudeCLIExpiryMillis normalizes a stored expiry to milliseconds.
//
// sub2api writes expires_at as Unix seconds (oauth_service.go), but the CLI
// reads milliseconds. Emitting seconds puts the expiry in 1970, so the CLI
// refreshes on first use and rotates the refresh token out from under this
// account. Historical rows and imported backups may already hold milliseconds,
// and multiplying those again would push the expiry ~50,000 years out, so the
// scale is detected rather than assumed.
func claudeCLIExpiryMillis(raw string) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0
	}
	if value >= millisecondEpochFloor {
		return value
	}
	return value * 1000
}

// claudeCLIScopes splits the stored space-separated scope string into the
// array the CLI reads. When nothing is stored it falls back to the scope the
// account's type was granted and reports that the answer was inferred, so the
// caller can say so rather than presenting a guess as a record.
func claudeCLIScopes(account *Account) (scopes []string, inferred bool) {
	if fields := strings.Fields(account.GetCredential("scope")); len(fields) > 0 {
		return fields, false
	}
	if account.Type == AccountTypeSetupToken {
		return strings.Fields(oauth.ScopeInference), true
	}
	return strings.Fields(oauth.ScopeAPI), true
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
