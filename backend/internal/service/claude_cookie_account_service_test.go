package service

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// cookieOrgClient serves a configurable organization list; only the calls
// ClaudeCookieAccountService makes are implemented.
type cookieOrgClient struct {
	orgs     []ClaudeWebOrganization
	orgsErr  error
	email    string
	emailErr error

	jarsSeen []string
}

func (c *cookieOrgClient) ListOrganizations(_ context.Context, jar, _ string) ([]ClaudeWebOrganization, error) {
	c.jarsSeen = append(c.jarsSeen, jar)
	return c.orgs, c.orgsErr
}

func (c *cookieOrgClient) AccountEmail(context.Context, string, string) (string, error) {
	return c.email, c.emailErr
}

func (c *cookieOrgClient) CreateConversation(context.Context, string, string, string) (*ClaudeWebConversation, error) {
	return nil, errors.New("not used")
}
func (c *cookieOrgClient) SetPaprikaMode(context.Context, string, string, string, string, string) error {
	return errors.New("not used")
}
func (c *cookieOrgClient) UploadFile(context.Context, string, string, string, string, []byte, string) (string, error) {
	return "", errors.New("not used")
}
func (c *cookieOrgClient) SendMessage(context.Context, string, string, string, map[string]any, string) (*ClaudeWebStream, error) {
	return nil, errors.New("not used")
}
func (c *cookieOrgClient) SendToolResult(context.Context, string, string, string, map[string]any, string) error {
	return errors.New("not used")
}
func (c *cookieOrgClient) DeleteConversation(context.Context, string, string, string, string) error {
	return errors.New("not used")
}

// A Netscape export, the format a browser cookie extension produces. The
// sessionKey value is fabricated.
const netscapeCookieExport = "# Netscape HTTP Cookie File\n" +
	"#HttpOnly_.claude.ai\tTRUE\t/\tTRUE\t1789199243\tsessionKey\tsk-ant-sid02-testvalue\n" +
	".claude.ai\tTRUE\t/\tTRUE\t1818337664\tlastActiveOrg\t16f945da-3cc2-413b-be20-3681008d4613\n" +
	".claude.ai\tTRUE\t/\tTRUE\t1818337664\tuser-sidebar-visible-on-load\ttrue\n"

func TestClaudeCookieAccountServiceValidate(t *testing.T) {
	client := &cookieOrgClient{
		orgs: []ClaudeWebOrganization{
			// A real Max account lists its API-only org first; picking it would
			// leave the account unable to serve chat.
			{UUID: "api-org", Name: "API", Capabilities: []string{"api", "api_individual"}},
			{UUID: "max-org", Name: "Personal", Capabilities: []string{"chat", "claude_max"}},
		},
		email: "operator@example.com",
	}

	svc := NewClaudeCookieAccountService(nil, client)
	info, err := svc.Validate(context.Background(), &ClaudeCookieAccountInput{Cookie: netscapeCookieExport})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if info.OrgUUID != "max-org" {
		t.Errorf("OrgUUID = %q, want max-org", info.OrgUUID)
	}
	if info.Plan != "max" {
		t.Errorf("Plan = %q, want max", info.Plan)
	}
	if info.SessionKey != "sk-ant-sid02-testvalue" {
		t.Errorf("SessionKey = %q", info.SessionKey)
	}
	if info.CookieCount != 3 {
		t.Errorf("CookieCount = %d, want 3", info.CookieCount)
	}
	if info.EmailAddress != "operator@example.com" {
		t.Errorf("EmailAddress = %q", info.EmailAddress)
	}

	// claude.ai is authenticated with the whole jar, not just the sessionKey.
	if len(client.jarsSeen) != 1 || !strings.Contains(client.jarsSeen[0], "lastActiveOrg=") {
		t.Errorf("jar sent upstream = %q, want the full cookie header", client.jarsSeen)
	}
}

// An email lookup failure must not block the import: the address is only a label.
func TestClaudeCookieAccountServiceValidateToleratesEmailFailure(t *testing.T) {
	client := &cookieOrgClient{
		orgs:     []ClaudeWebOrganization{{UUID: "max-org", Capabilities: []string{"chat", "claude_max"}}},
		emailErr: errors.New("boom"),
	}

	info, err := newCookieAccountService(client).Validate(context.Background(), &ClaudeCookieAccountInput{Cookie: netscapeCookieExport})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if info.EmailAddress != "" {
		t.Errorf("EmailAddress = %q, want empty", info.EmailAddress)
	}
}

func TestClaudeCookieAccountServiceValidateRejectsChatlessOrg(t *testing.T) {
	client := &cookieOrgClient{
		orgs: []ClaudeWebOrganization{{UUID: "api-org", Capabilities: []string{"api", "api_individual"}}},
	}

	_, err := newCookieAccountService(client).Validate(context.Background(), &ClaudeCookieAccountInput{Cookie: netscapeCookieExport})
	if !errors.Is(err, ErrClaudeOrgUnavailable) {
		t.Fatalf("error = %v, want ErrClaudeOrgUnavailable", err)
	}
}

// The account is only usable if the credentials Validate produces survive the
// path to the database. SanitizeStoredCredentials strips a key literally named
// "cookie" (an ephemeral SSO secret), so a cookie credential named too close to
// it would be silently dropped and the account would fail at request time with a
// missing cookie_jar instead of at import.
func TestCookieCredentialsSurviveSanitization(t *testing.T) {
	client := &cookieOrgClient{
		orgs: []ClaudeWebOrganization{{UUID: "max-org", Capabilities: []string{"chat", "claude_max"}}},
	}
	info, err := newCookieAccountService(client).Validate(context.Background(), &ClaudeCookieAccountInput{Cookie: netscapeCookieExport})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	sanitized := SanitizeStoredCredentials(PlatformAnthropic, info.Credentials())
	account := &Account{
		Platform:    PlatformAnthropic,
		Type:        AccountTypeCookie,
		Credentials: sanitized,
		Extra:       info.Extra(),
	}

	if !account.IsClaudeCookie() {
		t.Fatal("IsClaudeCookie() = false")
	}
	if account.CookieJar() == "" {
		t.Error("cookie_jar was dropped on the way to storage")
	}
	if account.ClaudeOrgUUID() != "max-org" {
		t.Errorf("org_uuid = %q after sanitization", account.ClaudeOrgUUID())
	}
	if !account.SupportsExtendedThinking() {
		t.Error("SupportsExtendedThinking() = false for a max plan; the extra map did not carry the plan")
	}
}

func newCookieAccountService(client ClaudeWebClient) *ClaudeCookieAccountService {
	return NewClaudeCookieAccountService(nil, client)
}
