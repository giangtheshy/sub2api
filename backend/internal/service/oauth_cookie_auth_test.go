//go:build unit

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
	"github.com/Wei-Shaw/sub2api/internal/util/claudecookie"
)

// TestCookieAuthSendsCookieJar pins the contract with claude.ai: whatever jar the
// caller supplies is replayed verbatim to both the organizations lookup and the
// authorize call.
func TestCookieAuthSendsCookieJar(t *testing.T) {
	const jar = "anthropic-device-id=dev-1; sessionKey=sk-ant-sid02-x; sessionKeyV3=sk-ant-sid02-v3"

	var orgJar, authJar string
	client := &mockClaudeOAuthClient{
		getOrgUUIDFunc: func(_ context.Context, cookieHeader, _ string) (string, error) {
			orgJar = cookieHeader
			return "org-1", nil
		},
		getAuthCodeFunc: func(_ context.Context, cookieHeader, _, _, _, _, _ string) (string, error) {
			authJar = cookieHeader
			return "AUTH#STATE", nil
		},
		exchangeCodeFunc: func(_ context.Context, _, _, _, _ string, _ bool) (*oauth.TokenResponse, error) {
			return &oauth.TokenResponse{AccessToken: "at", RefreshToken: "rt", ExpiresIn: 3600}, nil
		},
	}

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
	defer svc.sessionStore.Stop()

	got, err := svc.CookieAuth(context.Background(), &CookieAuthInput{
		SessionKey:   "sk-ant-sid02-x",
		CookieHeader: jar,
		Scope:        "full",
	})
	if err != nil {
		t.Fatalf("CookieAuth() error = %v", err)
	}
	if got.AccessToken != "at" {
		t.Errorf("AccessToken = %q", got.AccessToken)
	}
	if got.OrgUUID != "org-1" {
		t.Errorf("OrgUUID = %q, want the org from step 1", got.OrgUUID)
	}
	if orgJar != jar {
		t.Errorf("organizations jar = %q, want %q", orgJar, jar)
	}
	if authJar != jar {
		t.Errorf("authorize jar = %q, want %q", authJar, jar)
	}
}

// TestCookieAuthDerivesJarFromSessionKey keeps the pre-existing single-key
// callers working: no CookieHeader means send just the sessionKey.
func TestCookieAuthDerivesJarFromSessionKey(t *testing.T) {
	var orgJar string
	client := &mockClaudeOAuthClient{
		getOrgUUIDFunc: func(_ context.Context, cookieHeader, _ string) (string, error) {
			orgJar = cookieHeader
			return "", errors.New("stop here")
		},
	}

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
	defer svc.sessionStore.Stop()

	_, err := svc.CookieAuth(context.Background(), &CookieAuthInput{
		SessionKey: "sk-ant-sid02-bare",
		Scope:      "full",
	})
	if err == nil {
		t.Fatal("expected the mock error to propagate")
	}
	if orgJar != "sessionKey=sk-ant-sid02-bare" {
		t.Errorf("jar = %q, want a jar synthesised from the sessionKey", orgJar)
	}
}

func TestCookieAuthRejectsEmptyInput(t *testing.T) {
	svc := NewOAuthService(&mockProxyRepoForOAuth{}, &mockClaudeOAuthClient{})
	defer svc.sessionStore.Stop()

	_, err := svc.CookieAuth(context.Background(), &CookieAuthInput{Scope: "full"})
	if !errors.Is(err, claudecookie.ErrNoSessionKey) {
		t.Errorf("error = %v, want ErrNoSessionKey", err)
	}
}

// TestCookieAuthScopeSelection guards the setup-token path, which must request
// inference-only scope.
func TestCookieAuthScopeSelection(t *testing.T) {
	tests := []struct {
		name      string
		scope     string
		wantScope string
	}{
		{"full", "full", oauth.ScopeAPI},
		{"inference", "inference", oauth.ScopeInference},
		{"unset defaults to full", "", oauth.ScopeAPI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotScope string
			client := &mockClaudeOAuthClient{
				getOrgUUIDFunc: func(_ context.Context, _, _ string) (string, error) { return "org-1", nil },
				getAuthCodeFunc: func(_ context.Context, _, _, scope, _, _, _ string) (string, error) {
					gotScope = scope
					return "", errors.New("stop here")
				},
			}
			svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
			defer svc.sessionStore.Stop()

			_, _ = svc.CookieAuth(context.Background(), &CookieAuthInput{
				SessionKey: "sk-ant-sid02-x",
				Scope:      tt.scope,
			})

			if gotScope != tt.wantScope {
				t.Errorf("scope = %q, want %q", gotScope, tt.wantScope)
			}
		})
	}
}
