package service

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/util/claudecookie"
)

// ClaudeCookieAccountService validates a pasted claude.ai cookie and prepares the
// credentials for a cookie account.
//
// Unlike the OAuth flow it never calls /v1/oauth/{org}/authorize, so it is not
// subject to Anthropic's session-freshness check: a cookie that still works in
// the browser is enough.
type ClaudeCookieAccountService struct {
	proxyRepo ProxyRepository
	web       ClaudeWebClient
}

// NewClaudeCookieAccountService creates the service.
func NewClaudeCookieAccountService(proxyRepo ProxyRepository, web ClaudeWebClient) *ClaudeCookieAccountService {
	return &ClaudeCookieAccountService{proxyRepo: proxyRepo, web: web}
}

// ClaudeCookieAccountInput is the raw operator input.
type ClaudeCookieAccountInput struct {
	// Cookie is anything ParseOne accepts: a Netscape export, a JSON export, a
	// Cookie header, or a bare sessionKey.
	Cookie  string
	ProxyID *int64
}

// ClaudeCookieAccountInfo is what the panel needs to persist the account.
//
// CookieJar and SessionKey are deliberately not serialized: the credential
// reaches the panel once, through Credentials(), which is what the create
// request posts back. Restating it in this struct would put a live claude.ai
// session into devtools history and any reverse-proxy response log for no gain.
type ClaudeCookieAccountInfo struct {
	CookieJar    string   `json:"-"`
	SessionKey   string   `json:"-"`
	OrgUUID      string   `json:"org_uuid"`
	OrgName      string   `json:"org_name"`
	Plan         string   `json:"claude_plan"`
	Capabilities []string `json:"claude_capabilities"`
	EmailAddress string   `json:"email_address,omitempty"`
	ImportedAt   string   `json:"cookie_imported_at"`
	CookieCount  int      `json:"cookie_count"`
}

// Validate checks the cookie against claude.ai and resolves the organization,
// plan and identity to store alongside it.
func (s *ClaudeCookieAccountService) Validate(ctx context.Context, input *ClaudeCookieAccountInput) (*ClaudeCookieAccountInfo, error) {
	parsed, err := claudecookie.ParseOne(input.Cookie)
	if err != nil {
		return nil, err
	}

	proxyURL := ""
	if input.ProxyID != nil && s.proxyRepo != nil {
		if proxy, err := s.proxyRepo.GetByID(ctx, *input.ProxyID); err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	orgs, err := s.web.ListOrganizations(ctx, parsed.Jar, proxyURL)
	if err != nil {
		return nil, err
	}
	org, ok := SelectClaudeWebOrganization(orgs)
	if !ok {
		return nil, ErrClaudeOrgUnavailable
	}

	info := &ClaudeCookieAccountInfo{
		CookieJar:    parsed.Jar,
		SessionKey:   parsed.SessionKey,
		OrgUUID:      org.UUID,
		OrgName:      org.Name,
		Plan:         DetectClaudePlan(org.Capabilities),
		Capabilities: org.Capabilities,
		ImportedAt:   time.Now().UTC().Format(time.RFC3339),
		CookieCount:  len(parsed.Names),
	}

	// The email is a convenience label; a failure here must not block the import.
	if email, err := s.web.AccountEmail(ctx, parsed.Jar, proxyURL); err == nil {
		info.EmailAddress = email
	}

	return info, nil
}

// Credentials returns the account credentials map to persist.
func (info *ClaudeCookieAccountInfo) Credentials() map[string]any {
	return map[string]any{
		CredentialKeyCookieJar:  info.CookieJar,
		CredentialKeySessionKey: info.SessionKey,
		CredentialKeyOrgUUID:    info.OrgUUID,
	}
}

// Extra returns the account extra map to persist.
func (info *ClaudeCookieAccountInfo) Extra() map[string]any {
	extra := map[string]any{
		ExtraKeyCookiePlan:         info.Plan,
		ExtraKeyCookieCapabilities: info.Capabilities,
		ExtraKeyCookieImportedAt:   info.ImportedAt,
		"org_uuid":                 info.OrgUUID,
	}
	if info.EmailAddress != "" {
		extra["email_address"] = info.EmailAddress
	}
	return extra
}
