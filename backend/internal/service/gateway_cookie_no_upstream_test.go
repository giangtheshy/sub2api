package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func cookieAccountForUpstreamTest() *Account {
	return &Account{
		ID:       1,
		Name:     "cookie-acc",
		Platform: PlatformAnthropic,
		Type:     AccountTypeCookie,
		Credentials: map[string]any{
			"cookie_jar":  fakeCookieJar,
			"session_key": "sk-ant-sid02-testvalue",
			"org_uuid":    "max-org",
		},
	}
}

// A cookie jar is a claude.ai browser session, not an Anthropic API key. Every
// caller of GetAccessToken places the result in an Authorization or x-api-key
// header aimed at api.anthropic.com; forwardClaudeWebCookie reads
// account.CookieJar() directly and never calls this. So returning the jar here
// can only ever leak it, and the 401 that follows trips handleAuthError, which
// permanently disables a healthy account.
func TestGetAccessTokenRefusesCookieAccounts(t *testing.T) {
	s := &GatewayService{}

	token, tokenType, err := s.GetAccessToken(context.Background(), cookieAccountForUpstreamTest())

	if err == nil {
		t.Fatalf("GetAccessToken returned (%q, %q, nil) for a cookie account; the jar would be sent upstream", token, tokenType)
	}
	if strings.Contains(err.Error(), fakeCookieJar) || strings.Contains(err.Error(), "sk-ant-sid02") {
		t.Errorf("the error message leaks the credential: %v", err)
	}
	if token != "" {
		t.Errorf("token = %q, want empty", token)
	}
}

// count_tokens must answer without any upstream call. The gateway here has no
// HTTP upstream configured, so an attempt to reach api.anthropic.com fails
// loudly rather than silently leaking.
func TestCountTokensCookieAnswersLocally(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", nil)

	body := `{"model":"claude-sonnet-4-5-20250929","messages":[{"role":"user","content":"hello world, this is a token counting probe"}]}`
	parsed, err := ParseGatewayRequest(NewRequestBodyRef([]byte(body)), PlatformAnthropic)
	if err != nil {
		t.Fatalf("parse gateway request: %v", err)
	}

	s := &GatewayService{}
	if err := s.ForwardCountTokens(context.Background(), c, cookieAccountForUpstreamTest(), parsed); err != nil {
		t.Fatalf("ForwardCountTokens: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, "input_tokens") {
		t.Errorf("not a count_tokens response: %s", out)
	}
	if strings.Contains(out, "sk-ant-sid02") {
		t.Errorf("the response leaked the credential: %s", out)
	}
}
