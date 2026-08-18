//go:build e2e

package integration

// In-process end-to-end test for claude.ai cookie accounts.
//
// Unlike the other tests in this package it needs no running server: it wires
// the real claude.ai web client into a real GatewayService and drives
// GatewayService.Forward directly, so the whole cookie path is exercised —
// cookie parsing, organization selection, prompt building, conversation
// lifecycle, the live SSE stream, and the relay into an Anthropic response.
//
// It talks to claude.ai for real, so it is opt-in:
//
//	CLAUDE_COOKIE_FILE=/path/to/claude-cookies.txt \
//	  go test -tags e2e ./internal/integration/ -run ClaudeCookie -v
//
// The cookie never appears in this file; it is read from the path in the env
// var so no live sessionKey enters the repository.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// claudeCookieFileEnv points at a claude.ai cookie export (Netscape, JSON, a
// Cookie header, or a bare sessionKey — anything claudecookie.ParseOne accepts).
const claudeCookieFileEnv = "CLAUDE_COOKIE_FILE"

// e2eCookieModel is what a client would ask for. claude.ai uses its own model
// slugs, so the request model is not necessarily what answers; the forward path
// falls back to the claude.ai default when the slug is unknown upstream.
const e2eCookieModel = "claude-sonnet-4-5-20250929"

func loadCookieExport(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(claudeCookieFileEnv))
	if path == "" {
		t.Skipf("%s is not set; skipping the live claude.ai cookie test", claudeCookieFileEnv)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cookie export %q: %v", path, err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		t.Fatalf("cookie export %q is empty", path)
	}
	return string(raw)
}

// newCookieAccount runs the same validation the admin panel runs when an
// operator imports a cookie, then builds the account those credentials produce.
func newCookieAccount(t *testing.T, ctx context.Context, web service.ClaudeWebClient) *service.Account {
	t.Helper()

	cookieSvc := service.NewClaudeCookieAccountService(nil, web)
	info, err := cookieSvc.Validate(ctx, &service.ClaudeCookieAccountInput{Cookie: loadCookieExport(t)})
	if err != nil {
		t.Fatalf("validate cookie against claude.ai: %v", err)
	}

	if info.OrgUUID == "" {
		t.Fatal("no organization was selected for this cookie")
	}
	if info.CookieCount == 0 {
		t.Fatal("no cookies were parsed from the export")
	}
	// An API-only organization cannot serve chat, so selecting one would leave
	// the account unable to answer. Plan detection proves a chat org was picked.
	if info.Plan == "" {
		t.Fatalf("no plan detected; capabilities=%v suggest a non-chat organization", info.Capabilities)
	}
	t.Logf("cookie validated: org=%s plan=%s cookies=%d email_present=%t",
		info.OrgUUID, info.Plan, info.CookieCount, info.EmailAddress != "")

	return &service.Account{
		ID:          1,
		Name:        "e2e-claude-cookie",
		Platform:    service.PlatformAnthropic,
		Type:        service.AccountTypeCookie,
		Credentials: info.Credentials(),
		Extra:       info.Extra(),
	}
}

func newCookieGateway(web service.ClaudeWebClient) *service.GatewayService {
	// Every collaborator the cookie path does not touch is nil on purpose: it
	// proves forwardClaudeWebCookie reaches claude.ai without the Anthropic API
	// machinery, and any accidental dependency shows up as a panic rather than
	// passing silently.
	return service.NewGatewayService(
		nil, nil, nil, nil, nil, nil, nil, // repositories
		nil,      // cache
		nil,      // cfg
		nil, nil, // schedulerSnapshot, concurrencyService
		nil, nil, nil, nil, // billing, rateLimit, billingCache, identity
		nil, nil, nil, // httpUpstream, deferred, claudeTokenProvider
		nil, nil, nil, // sessionLimitCache, rpmCache, digestStore
		nil, nil, nil, // settingService, tlsFPProfileService, channelService
		nil, nil, nil, // resolver, compositeResolver, balanceNotifyService
		nil, // userPlatformQuotaRepo
		web,
	)
}

func forwardCookieRequest(t *testing.T, svc *service.GatewayService, account *service.Account, body string) (*service.ForwardResult, *httptest.ResponseRecorder) {
	t.Helper()

	parsed, err := service.ParseGatewayRequest(service.NewRequestBodyRef([]byte(body)), service.PlatformAnthropic)
	if err != nil {
		t.Fatalf("parse gateway request: %v", err)
	}

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	result, err := svc.Forward(ctx, c, account, parsed)
	if err != nil {
		t.Fatalf("Forward through the claude.ai cookie path: %v", err)
	}
	return result, rec
}

// TestClaudeCookieNonStreaming is the core proof: a cookie too stale for OAuth
// still answers a Messages request end to end.
func TestClaudeCookieNonStreaming(t *testing.T) {
	web := repository.NewClaudeWebClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	account := newCookieAccount(t, ctx, web)

	body := `{"model":"` + e2eCookieModel + `","max_tokens":64,"messages":[` +
		`{"role":"user","content":"Reply with exactly one word: PONG"}]}`

	result, rec := forwardCookieRequest(t, newCookieGateway(web), account, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Type       string `json:"type"`
		Role       string `json:"role"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not a Messages object: %v\nbody: %s", err, rec.Body.String())
	}
	if resp.Type != "message" || resp.Role != "assistant" {
		t.Errorf("type/role = %q/%q, want message/assistant", resp.Type, resp.Role)
	}

	var answer strings.Builder
	for _, block := range resp.Content {
		if block.Type == "text" {
			answer.WriteString(block.Text)
		}
	}
	if !strings.Contains(strings.ToUpper(answer.String()), "PONG") {
		t.Errorf("claude.ai did not answer the prompt; text = %q", answer.String())
	}

	// Usage drives billing and quota. claude.ai does not meter input tokens, so
	// a zero here means the local estimate never ran.
	if result.Usage.InputTokens <= 0 {
		t.Error("input tokens = 0; the token estimate did not run")
	}
	if result.Usage.OutputTokens <= 0 {
		t.Error("output tokens = 0; neither the upstream count nor the estimate landed")
	}
	if result.FirstTokenMs == nil {
		t.Error("first token latency was never recorded")
	}
	t.Logf("answered %q via upstream model %q (in=%d out=%d first_token=%v)",
		strings.TrimSpace(answer.String()), resp.Model,
		result.Usage.InputTokens, result.Usage.OutputTokens, result.FirstTokenMs)
}

// TestClaudeCookieStreaming checks the relayed SSE is something a strict
// Messages client can consume: the required events are present and claude.ai's
// own message_limit event is filtered out.
func TestClaudeCookieStreaming(t *testing.T) {
	web := repository.NewClaudeWebClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	account := newCookieAccount(t, ctx, web)

	body := `{"model":"` + e2eCookieModel + `","max_tokens":64,"stream":true,"messages":[` +
		`{"role":"user","content":"Count from 1 to 5, digits only."}]}`

	result, rec := forwardCookieRequest(t, newCookieGateway(web), account, body)

	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}
	out := rec.Body.String()
	for _, want := range []string{"event: content_block_delta", "event: message_stop"} {
		if !strings.Contains(out, want) {
			t.Errorf("relayed stream is missing %q", want)
		}
	}
	if strings.Contains(out, "message_limit") {
		t.Error("claude.ai's message_limit event leaked into the relayed stream")
	}
	if result.Usage.OutputTokens <= 0 {
		t.Error("output tokens = 0 for a streamed turn")
	}
	t.Logf("streamed %d bytes of SSE (out=%d tokens)", len(out), result.Usage.OutputTokens)
}

// TestClaudeCookieMultiTurnHistory pins the part that is easy to get wrong:
// earlier turns travel as a conversation.txt attachment while only the live turn
// goes in the prompt. If the attachment were dropped or ignored, the model could
// not name the colour from turn one.
func TestClaudeCookieMultiTurnHistory(t *testing.T) {
	web := repository.NewClaudeWebClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	account := newCookieAccount(t, ctx, web)

	body := `{"model":"` + e2eCookieModel + `","max_tokens":64,"messages":[` +
		`{"role":"user","content":"Remember this colour: teal."},` +
		`{"role":"assistant","content":"Noted."},` +
		`{"role":"user","content":"Which colour did I ask you to remember? Answer with the single word."}]}`

	_, rec := forwardCookieRequest(t, newCookieGateway(web), account, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "teal") {
		t.Errorf("the model could not recall the colour from the attached history; body = %s", rec.Body.String())
	}
}
