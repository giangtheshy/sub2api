package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

const (
	usagePolicy403Body = `{"type":"error","error":{"type":"permission_error","message":"This request violates our Usage Policy"}}`
	orgLevel403Body    = `{"type":"error","error":{"type":"permission_error","message":"Your organization has been disabled"}}`
)

// usagePolicyUpstream answers every call with a fresh copy of the same error, so
// retries and failovers are counted instead of reading an already-drained body.
type usagePolicyUpstream struct {
	status int
	body   string
	calls  int
}

func (u *usagePolicyUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	u.calls++
	if req != nil && req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	return &http.Response{
		StatusCode: u.status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(u.body)),
	}, nil
}

func (u *usagePolicyUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(req, proxyURL, accountID, accountConcurrency)
}

func newUsagePolicyGatewayService(upstream HTTPUpstream) (*GatewayService, *refusalErrorPathAccountRepo) {
	repo := &refusalErrorPathAccountRepo{}
	cfg := &config.Config{Gateway: config.GatewayConfig{MaxLineSize: defaultMaxLineSize}}
	return &GatewayService{
		cfg:                  cfg,
		responseHeaderFilter: compileResponseHeaderFilter(cfg),
		httpUpstream:         upstream,
		rateLimitService:     &RateLimitService{accountRepo: repo, cfg: cfg},
		deferredService:      &DeferredService{},
	}, repo
}

// newUsagePolicyClaudeCodeRequest builds a real Claude Code request so the OAuth
// path forwards it as-is instead of going through the mimic rewrite.
func newUsagePolicyClaudeCodeRequest(t *testing.T) (*gin.Context, *httptest.ResponseRecorder, *ParsedRequest) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	metadataUserID := FormatMetadataUserID(
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		"550e8400-e29b-41d4-a716-446655440000",
		"123e4567-e89b-42d3-a456-426614174000",
		claude.CLICurrentVersion,
	)
	body := []byte(`{"model":"claude-sonnet-4-6","metadata":{"user_id":` + strconvQuote(metadataUserID) + `},"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed, err := ParseGatewayRequest(NewRequestBodyRef(body), PlatformAnthropic)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	c.Request.Header.Set("User-Agent", "claude-cli/"+claude.CLICurrentVersion+" (external, cli)")
	c.Request.Header.Set("Anthropic-Beta", strings.Join([]string{claude.BetaClaudeCode, claude.BetaOAuth}, ","))
	return c, rec, parsed
}

func requireUsagePolicyRejectionIsTerminal(t *testing.T, err error, upstream *usagePolicyUpstream, repo *refusalErrorPathAccountRepo, c *gin.Context, rec *httptest.ResponseRecorder, accountID int64) {
	t.Helper()
	require.Error(t, err)
	var failoverErr *UpstreamFailoverError
	require.False(t, errors.As(err, &failoverErr), "a usage-policy verdict on the request content must not fail over to other accounts")
	require.Equal(t, 1, upstream.calls, "the violating request must not be retried")
	require.Zero(t, repo.setErrorCalls, "the upstream account did nothing wrong and must stay usable")

	mark := GetAnthropicRefusalMark(c)
	require.NotNil(t, mark, "the handler needs the mark to record the violation and apply the ban")
	require.Equal(t, AnthropicRefusalSignalPermissionError, mark.Signal)
	require.Equal(t, accountID, mark.AccountID)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "permission_error", gjson.Get(rec.Body.String(), "error.type").String())
	require.Equal(t, "This request violates our Usage Policy", gjson.Get(rec.Body.String(), "error.message").String())
}

func TestForward_AnthropicOAuthUsagePolicy403IsTerminal(t *testing.T) {
	upstream := &usagePolicyUpstream{status: http.StatusForbidden, body: usagePolicy403Body}
	svc, repo := newUsagePolicyGatewayService(upstream)
	c, rec, parsed := newUsagePolicyClaudeCodeRequest(t)
	account := &Account{
		ID: 303, Name: "anthropic-oauth", Platform: PlatformAnthropic, Type: AccountTypeOAuth, Concurrency: 1,
		Credentials: map[string]any{"access_token": "oauth-token"}, Status: StatusActive, Schedulable: true,
	}

	_, err := svc.Forward(context.Background(), c, account, parsed)

	requireUsagePolicyRejectionIsTerminal(t, err, upstream, repo, c, rec, 303)
}

func TestForward_AnthropicAPIKeyUsagePolicy403IsTerminal(t *testing.T) {
	upstream := &usagePolicyUpstream{status: http.StatusForbidden, body: usagePolicy403Body}
	svc, repo := newUsagePolicyGatewayService(upstream)
	c, rec, parsed := newUsagePolicyClaudeCodeRequest(t)
	account := &Account{
		ID: 304, Name: "anthropic-apikey", Platform: PlatformAnthropic, Type: AccountTypeAPIKey, Concurrency: 1,
		Credentials: map[string]any{"api_key": "upstream-key", "base_url": "https://api.anthropic.com"},
		Status:      StatusActive, Schedulable: true,
	}

	_, err := svc.Forward(context.Background(), c, account, parsed)

	requireUsagePolicyRejectionIsTerminal(t, err, upstream, repo, c, rec, 304)
}

func TestAnthropicPassthrough_UsagePolicy403IsTerminal(t *testing.T) {
	upstream := &usagePolicyUpstream{status: http.StatusForbidden, body: usagePolicy403Body}
	svc, repo := newUsagePolicyGatewayService(upstream)
	c, rec, _ := newUsagePolicyClaudeCodeRequest(t)
	account := newAnthropicAPIKeyAccountForTest()

	_, err := svc.forwardAnthropicAPIKeyPassthrough(context.Background(), c, account, []byte(`{"model":"claude-sonnet-4-6"}`), "claude-sonnet-4-6", "claude-sonnet-4-6", false, time.Now())

	requireUsagePolicyRejectionIsTerminal(t, err, upstream, repo, c, rec, account.ID)
}

// An organisation-level 403 is an account fault: it must keep failing over and
// penalising the account, and must never be counted against the end user.
func TestForward_AnthropicOrgLevel403StillFailsOver(t *testing.T) {
	upstream := &usagePolicyUpstream{status: http.StatusForbidden, body: orgLevel403Body}
	svc, repo := newUsagePolicyGatewayService(upstream)
	c, _, parsed := newUsagePolicyClaudeCodeRequest(t)
	account := &Account{
		ID: 305, Name: "anthropic-apikey", Platform: PlatformAnthropic, Type: AccountTypeAPIKey, Concurrency: 1,
		Credentials: map[string]any{"api_key": "upstream-key", "base_url": "https://api.anthropic.com"},
		Status:      StatusActive, Schedulable: true,
	}

	_, err := svc.Forward(context.Background(), c, account, parsed)

	var failoverErr *UpstreamFailoverError
	require.True(t, errors.As(err, &failoverErr), "account-level 403 must still fail over")
	require.Equal(t, 1, repo.setErrorCalls, "account-level 403 must still penalise the account")
	require.Nil(t, GetAnthropicRefusalMark(c), "account-level 403 must not be recorded as an end-user violation")
}
