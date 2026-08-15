package service

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// fakeClaudeWebClient records the calls forwardClaudeWebCookie makes and replays
// a canned SSE stream.
type fakeClaudeWebClient struct {
	sse string

	createdConversations int
	deletedConversations int
	paprikaModes         []string
	uploads              []string
	sentPayloads         []map[string]any

	// sendErrs is consumed one entry per SendMessage call; a nil entry succeeds.
	sendErrs []error
}

func (f *fakeClaudeWebClient) ListOrganizations(context.Context, string, string) ([]ClaudeWebOrganization, error) {
	return []ClaudeWebOrganization{{UUID: "org-1", Capabilities: []string{"chat", "claude_max"}}}, nil
}

func (f *fakeClaudeWebClient) AccountEmail(context.Context, string, string) (string, error) {
	return "operator@example.com", nil
}

func (f *fakeClaudeWebClient) CreateConversation(context.Context, string, string, string) (*ClaudeWebConversation, error) {
	f.createdConversations++
	return &ClaudeWebConversation{UUID: "conv-1"}, nil
}

func (f *fakeClaudeWebClient) SetPaprikaMode(_ context.Context, _, _, _, mode, _ string) error {
	f.paprikaModes = append(f.paprikaModes, mode)
	return nil
}

func (f *fakeClaudeWebClient) UploadFile(_ context.Context, _, _, filename, _ string, _ []byte, _ string) (string, error) {
	f.uploads = append(f.uploads, filename)
	return "file-" + filename, nil
}

func (f *fakeClaudeWebClient) SendMessage(_ context.Context, _, _, _ string, payload map[string]any, _ string) (*ClaudeWebStream, error) {
	f.sentPayloads = append(f.sentPayloads, payload)

	if len(f.sendErrs) > 0 {
		err := f.sendErrs[0]
		f.sendErrs = f.sendErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	return &ClaudeWebStream{
		Body:      readCloser{strings.NewReader(f.sse)},
		RequestID: "req_fake",
	}, nil
}

func (f *fakeClaudeWebClient) SendToolResult(context.Context, string, string, string, map[string]any, string) error {
	return nil
}

func (f *fakeClaudeWebClient) DeleteConversation(context.Context, string, string, string, string) error {
	f.deletedConversations++
	return nil
}

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }

func newCookieAccountForTest() *Account {
	return &Account{
		ID:       7,
		Name:     "claude-cookie",
		Platform: PlatformAnthropic,
		Type:     AccountTypeCookie,
		Credentials: map[string]any{
			CredentialKeyCookieJar:  "sessionKey=sk-ant-sid02-x; lastActiveOrg=org-1",
			CredentialKeySessionKey: "sk-ant-sid02-x",
			CredentialKeyOrgUUID:    "org-1",
		},
		Extra: map[string]any{ExtraKeyCookiePlan: "max"},
	}
}

func loadRelayFixture(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/claude_web_stream.sse")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(raw)
}

func newForwardContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	return c, rec
}

func TestForwardClaudeWebCookieHappyPath(t *testing.T) {
	fake := &fakeClaudeWebClient{sse: loadRelayFixture(t)}
	svc := &GatewayService{claudeWebClient: fake}
	c, rec := newForwardContext()

	body := []byte(`{"model":"claude-opus-4-5-20251101","max_tokens":2000,"system":"Be terse.","messages":[{"role":"user","content":"Reply with exactly: PONG"}]}`)
	parsed := &ParsedRequest{
		Body:  NewRequestBodyRef(body),
		Model: "claude-opus-4-5-20251101",
	}

	accepted := false
	parsed.OnUpstreamAccepted = func() { accepted = true }

	got, err := svc.forwardClaudeWebCookie(context.Background(), c, newCookieAccountForTest(), parsed, time.Now())
	if err != nil {
		t.Fatalf("forwardClaudeWebCookie() error = %v", err)
	}

	if !accepted {
		t.Error("OnUpstreamAccepted was not called")
	}
	if fake.createdConversations != 1 {
		t.Errorf("createdConversations = %d, want 1", fake.createdConversations)
	}
	// The conversation must be cleaned up even though the request succeeded.
	if fake.deletedConversations != 1 {
		t.Errorf("deletedConversations = %d, want 1", fake.deletedConversations)
	}
	if got.RequestID != "req_fake" {
		t.Errorf("RequestID = %q", got.RequestID)
	}
	if got.Model != "claude-opus-4-5-20251101" {
		t.Errorf("Model = %q", got.Model)
	}
	if got.UpstreamResponseModel != "claude-opus-5" {
		t.Errorf("UpstreamResponseModel = %q, want the model claude.ai reported", got.UpstreamResponseModel)
	}
	// claude.ai does not meter input tokens, so they must be estimated.
	if got.Usage.InputTokens <= 0 {
		t.Errorf("Usage.InputTokens = %d, want an estimate", got.Usage.InputTokens)
	}
	if got.Usage.OutputTokens <= 0 {
		t.Errorf("Usage.OutputTokens = %d, want an estimate", got.Usage.OutputTokens)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "PONG") {
		t.Errorf("body = %q", rec.Body.String())
	}

	// The live turn belongs in the prompt, never only in the attachment.
	payload := fake.sentPayloads[0]
	if prompt, _ := payload["prompt"].(string); !strings.Contains(prompt, "Reply with exactly: PONG") {
		t.Errorf("prompt = %q", prompt)
	}
}

func TestForwardClaudeWebCookieFallsBackWhenModelUnavailable(t *testing.T) {
	// claude.ai reports an unavailable model as a 403; falling back to its own
	// default is better than failing the request.
	fake := &fakeClaudeWebClient{
		sse:      loadRelayFixture(t),
		sendErrs: []error{ErrClaudeWebModelUnavailable, nil},
	}
	svc := &GatewayService{claudeWebClient: fake}
	c, _ := newForwardContext()

	parsed := &ParsedRequest{
		Body:  NewRequestBodyRef([]byte(`{"model":"claude-sonnet-4-5","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`)),
		Model: "claude-sonnet-4-5",
	}

	got, err := svc.forwardClaudeWebCookie(context.Background(), c, newCookieAccountForTest(), parsed, time.Now())
	if err != nil {
		t.Fatalf("error = %v", err)
	}

	if len(fake.sentPayloads) != 2 {
		t.Fatalf("SendMessage calls = %d, want a retry", len(fake.sentPayloads))
	}
	if _, present := fake.sentPayloads[1]["model"]; present {
		t.Error("retry payload still carries a model field")
	}
	if got.UpstreamModel != "" {
		t.Errorf("UpstreamModel = %q, want empty after falling back to the default", got.UpstreamModel)
	}
	if fake.deletedConversations != 1 {
		t.Errorf("deletedConversations = %d, want 1", fake.deletedConversations)
	}
}

func TestForwardClaudeWebCookiePropagatesNonModelErrors(t *testing.T) {
	fake := &fakeClaudeWebClient{sendErrs: []error{ErrClaudeCookieInvalid}}
	svc := &GatewayService{claudeWebClient: fake}
	c, _ := newForwardContext()

	parsed := &ParsedRequest{
		Body:  NewRequestBodyRef([]byte(`{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`)),
		Model: "m",
	}

	_, err := svc.forwardClaudeWebCookie(context.Background(), c, newCookieAccountForTest(), parsed, time.Now())
	if !errors.Is(err, ErrClaudeCookieInvalid) {
		t.Errorf("error = %v, want ErrClaudeCookieInvalid", err)
	}
	if len(fake.sentPayloads) != 1 {
		t.Errorf("SendMessage calls = %d, want no retry", len(fake.sentPayloads))
	}
	// A failed request must still not leak the conversation.
	if fake.deletedConversations != 1 {
		t.Errorf("deletedConversations = %d, want 1", fake.deletedConversations)
	}
}

func TestForwardClaudeWebCookieEnablesThinkingForMaxPlan(t *testing.T) {
	fake := &fakeClaudeWebClient{sse: loadRelayFixture(t)}
	svc := &GatewayService{claudeWebClient: fake}
	c, _ := newForwardContext()

	parsed := &ParsedRequest{
		Body: NewRequestBodyRef([]byte(`{"model":"m","max_tokens":2000,"thinking":{"type":"enabled","budget_tokens":1024},` +
			`"messages":[{"role":"user","content":"think"}]}`)),
		Model: "m",
	}

	if _, err := svc.forwardClaudeWebCookie(context.Background(), c, newCookieAccountForTest(), parsed, time.Now()); err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(fake.paprikaModes) != 1 || fake.paprikaModes[0] != PaprikaModeExtended {
		t.Errorf("paprikaModes = %v, want [%s]", fake.paprikaModes, PaprikaModeExtended)
	}
}

func TestForwardClaudeWebCookieSkipsThinkingForFreePlan(t *testing.T) {
	fake := &fakeClaudeWebClient{sse: loadRelayFixture(t)}
	svc := &GatewayService{claudeWebClient: fake}
	c, _ := newForwardContext()

	account := newCookieAccountForTest()
	account.Extra[ExtraKeyCookiePlan] = "free"

	parsed := &ParsedRequest{
		Body: NewRequestBodyRef([]byte(`{"model":"m","max_tokens":2000,"thinking":{"type":"enabled"},` +
			`"messages":[{"role":"user","content":"think"}]}`)),
		Model: "m",
	}

	if _, err := svc.forwardClaudeWebCookie(context.Background(), c, account, parsed, time.Now()); err != nil {
		t.Fatalf("error = %v", err)
	}
	for _, mode := range fake.paprikaModes {
		if mode == PaprikaModeExtended {
			t.Errorf("paprikaModes = %v, want no extended mode on the free plan", fake.paprikaModes)
		}
	}
}

func TestForwardClaudeWebCookieUploadsInlineImages(t *testing.T) {
	fake := &fakeClaudeWebClient{sse: loadRelayFixture(t)}
	svc := &GatewayService{claudeWebClient: fake}
	c, _ := newForwardContext()

	payload := base64.StdEncoding.EncodeToString([]byte("png-bytes"))
	parsed := &ParsedRequest{
		Body: NewRequestBodyRef([]byte(`{"model":"m","max_tokens":100,"messages":[{"role":"user","content":[` +
			`{"type":"text","text":"look"},` +
			`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + payload + `"}}]}]}`)),
		Model: "m",
	}

	if _, err := svc.forwardClaudeWebCookie(context.Background(), c, newCookieAccountForTest(), parsed, time.Now()); err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(fake.uploads) != 1 || fake.uploads[0] != "image_0.png" {
		t.Fatalf("uploads = %v", fake.uploads)
	}
	files, _ := fake.sentPayloads[0]["files"].([]string)
	if len(files) != 1 || files[0] != "file-image_0.png" {
		t.Errorf("files = %v, want the uploaded id", files)
	}
}

func TestForwardClaudeWebCookieRejectsMissingCredentials(t *testing.T) {
	svc := &GatewayService{claudeWebClient: &fakeClaudeWebClient{}}
	c, _ := newForwardContext()
	parsed := &ParsedRequest{
		Body:  NewRequestBodyRef([]byte(`{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`)),
		Model: "m",
	}

	tests := []struct {
		name    string
		mutate  func(*Account)
		wantErr string
	}{
		{
			name:    "no cookie jar",
			mutate:  func(a *Account) { delete(a.Credentials, CredentialKeyCookieJar) },
			wantErr: "cookie_jar",
		},
		{
			name:    "no org uuid",
			mutate:  func(a *Account) { delete(a.Credentials, CredentialKeyOrgUUID) },
			wantErr: "org_uuid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account := newCookieAccountForTest()
			tt.mutate(account)
			_, err := svc.forwardClaudeWebCookie(context.Background(), c, account, parsed, time.Now())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want one mentioning %q", err, tt.wantErr)
			}
		})
	}
}

func TestGetAccessTokenForCookieAccount(t *testing.T) {
	svc := &GatewayService{}
	account := newCookieAccountForTest()

	token, kind, err := svc.GetAccessToken(context.Background(), account)
	if err != nil {
		t.Fatalf("GetAccessToken() error = %v", err)
	}
	if kind != "cookie" {
		t.Errorf("kind = %q, want cookie", kind)
	}
	if token != account.CookieJar() {
		t.Errorf("token = %q, want the cookie jar", token)
	}

	delete(account.Credentials, CredentialKeyCookieJar)
	if _, _, err := svc.GetAccessToken(context.Background(), account); err == nil {
		t.Error("expected an error when the cookie jar is missing")
	}
}
