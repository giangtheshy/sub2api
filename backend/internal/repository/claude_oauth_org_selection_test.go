package repository

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/imroc/req/v3"
	"github.com/stretchr/testify/require"
)

func strptr(s string) *string { return &s }

func TestSelectOrganization(t *testing.T) {
	tests := []struct {
		name       string
		orgs       []claudeOrganization
		wantUUID   string
		wantReason string
	}{
		{
			name: "prefers subscription org over api only org",
			// Real shape observed on a Claude Max account: the API-only org can be
			// returned first, and authorizing against it fails.
			orgs: []claudeOrganization{
				{UUID: "api-org", Capabilities: []string{"api", "api_individual"}},
				{UUID: "max-org", Capabilities: []string{"chat", "claude_max"}},
			},
			wantUUID:   "max-org",
			wantReason: "subscription",
		},
		{
			name: "prefers subscription org even when listed last",
			orgs: []claudeOrganization{
				{UUID: "plain-chat", Capabilities: []string{"chat"}},
				{UUID: "pro-org", Capabilities: []string{"chat", "claude_pro"}},
			},
			wantUUID:   "pro-org",
			wantReason: "subscription",
		},
		{
			name: "falls back to team org",
			orgs: []claudeOrganization{
				{UUID: "personal", Capabilities: []string{"chat"}},
				{UUID: "team", Capabilities: []string{"chat"}, RavenType: strptr("team")},
			},
			wantUUID:   "team",
			wantReason: "team",
		},
		{
			name: "falls back to any chat org",
			orgs: []claudeOrganization{
				{UUID: "api-org", Capabilities: []string{"api"}},
				{UUID: "chat-org", Capabilities: []string{"chat"}},
			},
			wantUUID:   "chat-org",
			wantReason: "chat",
		},
		{
			name: "falls back to first org when nothing is chat capable",
			orgs: []claudeOrganization{
				{UUID: "api-org", Capabilities: []string{"api", "api_individual"}},
			},
			wantUUID:   "api-org",
			wantReason: "fallback",
		},
		{
			name:       "single org with no capabilities reported",
			orgs:       []claudeOrganization{{UUID: "only"}},
			wantUUID:   "only",
			wantReason: "fallback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := selectOrganization(tt.orgs)
			require.Equal(t, tt.wantUUID, got.UUID)
			require.Equal(t, tt.wantReason, reason)
		})
	}
}

func TestClassifyAuthorizeError(t *testing.T) {
	staleBody := []byte(`{"type":"error","error":{"type":"permission_error",` +
		`"message":"Session is not fresh enough to grant elevated access. Sign in again to continue.",` +
		`"details":{"error_code":"session_stale_relogin"}},"request_id":"req_1"}`)

	tests := []struct {
		name    string
		status  int
		body    []byte
		wantErr error
	}{
		{"stale session", http.StatusForbidden, staleBody, service.ErrClaudeSessionStale},
		{
			name:    "stale session detected by message alone",
			status:  http.StatusForbidden,
			body:    []byte(`{"error":{"message":"Session is not fresh enough to grant elevated access."}}`),
			wantErr: service.ErrClaudeSessionStale,
		},
		{
			name:    "wrong organization",
			status:  http.StatusForbidden,
			body:    []byte(`{"error":{"message":"Invalid authorization for organization"}}`),
			wantErr: service.ErrClaudeOrgUnavailable,
		},
		{
			name:    "dead cookie",
			status:  http.StatusForbidden,
			body:    []byte(`{"error":{"message":"Invalid authorization"}}`),
			wantErr: service.ErrClaudeCookieInvalid,
		},
		{"unrelated 403 falls through", http.StatusForbidden, []byte(`{"error":{"message":"nope"}}`), nil},
		{"non json 403 falls through", http.StatusForbidden, []byte(`<html>blocked</html>`), nil},
		{"non 403 falls through", http.StatusUnauthorized, staleBody, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAuthorizeError(tt.status, tt.body)
			if tt.wantErr == nil {
				require.NoError(t, got)
				return
			}
			require.ErrorIs(t, got, tt.wantErr)
		})
	}
}

// TestGetAuthorizationCodeSurfacesStaleSession pins the end-to-end mapping: the
// live 403 body must reach callers as the typed, actionable error.
func TestGetAuthorizationCodeSurfacesStaleSession(t *testing.T) {
	rt := newInProcessTransport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"permission_error",` +
			`"message":"Session is not fresh enough to grant elevated access. Sign in again to continue.",` +
			`"details":{"error_code":"session_stale_relogin"}}}`))
	}), nil)

	client, ok := NewClaudeOAuthClient().(*claudeOAuthService)
	require.True(t, ok)
	client.baseURL = "http://in-process"
	client.clientFactory = func(string) (*req.Client, error) { return newTestReqClient(rt), nil }

	_, err := client.GetAuthorizationCode(context.Background(), "sessionKey=sess", "org-1", oauth.ScopeAPI, "cc", "st", "")

	require.Error(t, err)
	require.True(t, errors.Is(err, service.ErrClaudeSessionStale), "got %v", err)
}

// TestGetOrganizationUUIDSkipsAPIOnlyOrg is the regression guard for the bug
// where orgs[0] was used blindly.
func TestGetOrganizationUUIDSkipsAPIOnlyOrg(t *testing.T) {
	rt := newInProcessTransport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"uuid":"api-org","name":"Individual Org","capabilities":["api","api_individual"]},
			{"uuid":"max-org","name":"Max Org","capabilities":["chat","claude_max"]}
		]`))
	}), nil)

	client, ok := NewClaudeOAuthClient().(*claudeOAuthService)
	require.True(t, ok)
	client.baseURL = "http://in-process"
	client.clientFactory = func(string) (*req.Client, error) { return newTestReqClient(rt), nil }

	got, err := client.GetOrganizationUUID(context.Background(), "sessionKey=sess", "")

	require.NoError(t, err)
	require.Equal(t, "max-org", got)
}
