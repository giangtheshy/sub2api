package service

import (
	"context"
	"io"
)

// Credential and extra keys for claude.ai cookie accounts.
const (
	CredentialKeyCookieJar  = "cookie_jar"
	CredentialKeySessionKey = "session_key"
	CredentialKeyOrgUUID    = "org_uuid"

	ExtraKeyCookiePlan         = "claude_plan"
	ExtraKeyCookieCapabilities = "claude_capabilities"
	ExtraKeyCookieImportedAt   = "cookie_imported_at"
)

// Paprika (extended thinking) modes accepted by claude.ai conversations.
const (
	PaprikaModeExtended = "extended"
)

// IsClaudeCookie reports whether this account drives claude.ai through a browser
// cookie instead of an OAuth token.
func (a *Account) IsClaudeCookie() bool {
	return a != nil && a.Platform == PlatformAnthropic && a.Type == AccountTypeCookie
}

// CookieJar returns the Cookie header to replay for a cookie account.
func (a *Account) CookieJar() string {
	if a == nil {
		return ""
	}
	return a.GetCredential(CredentialKeyCookieJar)
}

// ClaudeOrgUUID returns the claude.ai organization this account talks to.
func (a *Account) ClaudeOrgUUID() string {
	if a == nil {
		return ""
	}
	return a.GetCredential(CredentialKeyOrgUUID)
}

// ClaudePlan returns the detected subscription plan ("max", "pro", "free"), or "".
func (a *Account) ClaudePlan() string {
	if a == nil || a.Extra == nil {
		return ""
	}
	plan, _ := a.Extra[ExtraKeyCookiePlan].(string)
	return plan
}

// SupportsExtendedThinking reports whether the plan can use paprika extended mode.
func (a *Account) SupportsExtendedThinking() bool {
	switch a.ClaudePlan() {
	case "max", "pro", "team", "enterprise":
		return true
	default:
		return false
	}
}

// ClaudeWebOrganization describes one claude.ai organization.
type ClaudeWebOrganization struct {
	UUID         string
	Name         string
	Capabilities []string
}

// ClaudeWebConversation is a freshly created claude.ai conversation.
type ClaudeWebConversation struct {
	UUID        string
	PaprikaMode string
}

// ClaudeWebStream is an open SSE response from the completion endpoint.
type ClaudeWebStream struct {
	Body      io.ReadCloser
	RequestID string
}

// ClaudeWebClient talks to the claude.ai web API using a browser cookie.
//
// It mirrors the endpoints the claude.ai frontend itself calls, so a cookie that
// works in the browser works here without any OAuth grant.
type ClaudeWebClient interface {
	// ListOrganizations returns the organizations the cookie can see.
	ListOrganizations(ctx context.Context, cookieJar, proxyURL string) ([]ClaudeWebOrganization, error)
	// AccountEmail returns the signed-in account's email address, or "" when
	// claude.ai does not report one.
	AccountEmail(ctx context.Context, cookieJar, proxyURL string) (string, error)
	CreateConversation(ctx context.Context, cookieJar, orgUUID, proxyURL string) (*ClaudeWebConversation, error)
	SetPaprikaMode(ctx context.Context, cookieJar, orgUUID, convUUID, mode, proxyURL string) error
	UploadFile(ctx context.Context, cookieJar, orgUUID, filename, contentType string, data []byte, proxyURL string) (string, error)
	// SendMessage opens the completion SSE stream. The caller closes Body.
	SendMessage(ctx context.Context, cookieJar, orgUUID, convUUID string, payload map[string]any, proxyURL string) (*ClaudeWebStream, error)
	SendToolResult(ctx context.Context, cookieJar, orgUUID, convUUID string, payload map[string]any, proxyURL string) error
	DeleteConversation(ctx context.Context, cookieJar, orgUUID, convUUID, proxyURL string) error
}

// DetectClaudePlan maps organization capabilities to a plan label.
func DetectClaudePlan(capabilities []string) string {
	has := func(want string) bool {
		for _, c := range capabilities {
			if c == want {
				return true
			}
		}
		return false
	}

	switch {
	case has("claude_max"):
		return "max"
	case has("claude_pro"):
		return "pro"
	case has("raven"):
		return "team"
	case has("chat"):
		return "free"
	default:
		return ""
	}
}

// SelectClaudeWebOrganization picks the chat-capable organization to drive.
// API-only organizations cannot serve chat completions and are skipped.
func SelectClaudeWebOrganization(orgs []ClaudeWebOrganization) (ClaudeWebOrganization, bool) {
	hasCap := func(org ClaudeWebOrganization, want string) bool {
		for _, c := range org.Capabilities {
			if c == want {
				return true
			}
		}
		return false
	}

	for _, org := range orgs {
		if hasCap(org, "chat") && (hasCap(org, "claude_max") || hasCap(org, "claude_pro")) {
			return org, true
		}
	}
	for _, org := range orgs {
		if hasCap(org, "chat") {
			return org, true
		}
	}
	return ClaudeWebOrganization{}, false
}
