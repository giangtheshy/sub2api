//go:build unit

package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
)

// --- mock: ClaudeOAuthClient ---

type mockClaudeOAuthClient struct {
	getOrgUUIDFunc   func(ctx context.Context, cookieHeader, proxyURL string) (string, error)
	getAuthCodeFunc  func(ctx context.Context, cookieHeader, orgUUID, scope, codeChallenge, state, proxyURL string) (string, error)
	exchangeCodeFunc func(ctx context.Context, code, codeVerifier, state, proxyURL string, isSetupToken bool) (*oauth.TokenResponse, error)
	refreshTokenFunc func(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error)
	bootstrapFunc    func(ctx context.Context, accessToken, proxyURL string) (*ClaudeBootstrapInfo, error)
}

func (m *mockClaudeOAuthClient) GetOrganizationUUID(ctx context.Context, cookieHeader, proxyURL string) (string, error) {
	if m.getOrgUUIDFunc != nil {
		return m.getOrgUUIDFunc(ctx, cookieHeader, proxyURL)
	}
	panic("GetOrganizationUUID not implemented")
}

func (m *mockClaudeOAuthClient) GetAuthorizationCode(ctx context.Context, cookieHeader, orgUUID, scope, codeChallenge, state, proxyURL string) (string, error) {
	if m.getAuthCodeFunc != nil {
		return m.getAuthCodeFunc(ctx, cookieHeader, orgUUID, scope, codeChallenge, state, proxyURL)
	}
	panic("GetAuthorizationCode not implemented")
}

func (m *mockClaudeOAuthClient) ExchangeCodeForToken(ctx context.Context, code, codeVerifier, state, proxyURL string, isSetupToken bool) (*oauth.TokenResponse, error) {
	if m.exchangeCodeFunc != nil {
		return m.exchangeCodeFunc(ctx, code, codeVerifier, state, proxyURL, isSetupToken)
	}
	panic("ExchangeCodeForToken not implemented")
}

func (m *mockClaudeOAuthClient) RefreshToken(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error) {
	if m.refreshTokenFunc != nil {
		return m.refreshTokenFunc(ctx, refreshToken, proxyURL)
	}
	panic("RefreshToken not implemented")
}

func (m *mockClaudeOAuthClient) BootstrapAccount(ctx context.Context, accessToken, proxyURL string) (*ClaudeBootstrapInfo, error) {
	if m.bootstrapFunc != nil {
		return m.bootstrapFunc(ctx, accessToken, proxyURL)
	}
	// Default: no enrichment available (mirrors an expired access token).
	return nil, fmt.Errorf("bootstrap not available")
}

// --- mock: ProxyRepository (最小实现，仅覆盖 OAuthService 依赖的方法) ---

type mockProxyRepoForOAuth struct {
	getByIDFunc func(ctx context.Context, id int64) (*Proxy, error)
}

func (m *mockProxyRepoForOAuth) Create(ctx context.Context, proxy *Proxy) error {
	panic("Create not implemented")
}
func (m *mockProxyRepoForOAuth) GetByID(ctx context.Context, id int64) (*Proxy, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}
	return nil, fmt.Errorf("proxy not found")
}
func (m *mockProxyRepoForOAuth) ListByIDs(ctx context.Context, ids []int64) ([]Proxy, error) {
	panic("ListByIDs not implemented")
}
func (m *mockProxyRepoForOAuth) Update(ctx context.Context, proxy *Proxy) error {
	panic("Update not implemented")
}
func (m *mockProxyRepoForOAuth) Delete(ctx context.Context, id int64) error {
	panic("Delete not implemented")
}
func (m *mockProxyRepoForOAuth) List(ctx context.Context, params pagination.PaginationParams) ([]Proxy, *pagination.PaginationResult, error) {
	panic("List not implemented")
}
func (m *mockProxyRepoForOAuth) ListWithFilters(ctx context.Context, params pagination.PaginationParams, protocol, status, search string) ([]Proxy, *pagination.PaginationResult, error) {
	panic("ListWithFilters not implemented")
}
func (m *mockProxyRepoForOAuth) ListWithFiltersAndAccountCount(ctx context.Context, params pagination.PaginationParams, protocol, status, search string) ([]ProxyWithAccountCount, *pagination.PaginationResult, error) {
	panic("ListWithFiltersAndAccountCount not implemented")
}
func (m *mockProxyRepoForOAuth) ListActive(ctx context.Context) ([]Proxy, error) {
	panic("ListActive not implemented")
}
func (m *mockProxyRepoForOAuth) ListActiveWithAccountCount(ctx context.Context) ([]ProxyWithAccountCount, error) {
	panic("ListActiveWithAccountCount not implemented")
}
func (m *mockProxyRepoForOAuth) ExistsByHostPortAuth(ctx context.Context, host string, port int, username, password string) (bool, error) {
	panic("ExistsByHostPortAuth not implemented")
}
func (m *mockProxyRepoForOAuth) CountAccountsByProxyID(ctx context.Context, proxyID int64) (int64, error) {
	panic("CountAccountsByProxyID not implemented")
}
func (m *mockProxyRepoForOAuth) ListAccountSummariesByProxyID(ctx context.Context, proxyID int64) ([]ProxyAccountSummary, error) {
	panic("ListAccountSummariesByProxyID not implemented")
}
func (m *mockProxyRepoForOAuth) SweepExpiredProxies(ctx context.Context, now time.Time) (int64, error) {
	panic("SweepExpiredProxies not implemented")
}
func (m *mockProxyRepoForOAuth) ListAllForFallback(ctx context.Context) ([]Proxy, error) {
	panic("ListAllForFallback not implemented")
}
func (m *mockProxyRepoForOAuth) CountExpired(ctx context.Context) (int64, error) {
	panic("CountExpired not implemented")
}
func (m *mockProxyRepoForOAuth) CountExpiringSoon(ctx context.Context, now time.Time) (int64, error) {
	panic("CountExpiringSoon not implemented")
}

// =====================
// 测试用例
// =====================

func TestNewOAuthService(t *testing.T) {
	t.Parallel()

	proxyRepo := &mockProxyRepoForOAuth{}
	client := &mockClaudeOAuthClient{}
	svc := NewOAuthService(proxyRepo, client)

	if svc == nil {
		t.Fatal("NewOAuthService 返回 nil")
	}
	if svc.proxyRepo != proxyRepo {
		t.Fatal("proxyRepo 未正确设置")
	}
	if svc.oauthClient != client {
		t.Fatal("oauthClient 未正确设置")
	}
	if svc.sessionStore == nil {
		t.Fatal("sessionStore 应被自动初始化")
	}

	// 清理
	svc.Stop()
}

func TestOAuthService_GenerateAuthURL(t *testing.T) {
	t.Parallel()

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, &mockClaudeOAuthClient{})
	defer svc.Stop()

	result, err := svc.GenerateAuthURL(context.Background(), nil)
	if err != nil {
		t.Fatalf("GenerateAuthURL 返回错误: %v", err)
	}
	if result == nil {
		t.Fatal("GenerateAuthURL 返回 nil")
	}
	if result.AuthURL == "" {
		t.Fatal("AuthURL 为空")
	}
	if result.SessionID == "" {
		t.Fatal("SessionID 为空")
	}

	// 验证 session 已存储
	session, ok := svc.sessionStore.Get(result.SessionID)
	if !ok {
		t.Fatal("session 未在 sessionStore 中找到")
	}
	if session.Scope != oauth.ScopeOAuth {
		t.Fatalf("scope 不匹配: got=%q want=%q", session.Scope, oauth.ScopeOAuth)
	}
}

func TestOAuthService_GenerateAuthURL_WithProxy(t *testing.T) {
	t.Parallel()

	proxyRepo := &mockProxyRepoForOAuth{
		getByIDFunc: func(ctx context.Context, id int64) (*Proxy, error) {
			return &Proxy{
				ID:       1,
				Protocol: "http",
				Host:     "proxy.example.com",
				Port:     8080,
			}, nil
		},
	}
	svc := NewOAuthService(proxyRepo, &mockClaudeOAuthClient{})
	defer svc.Stop()

	proxyID := int64(1)
	result, err := svc.GenerateAuthURL(context.Background(), &proxyID)
	if err != nil {
		t.Fatalf("GenerateAuthURL 返回错误: %v", err)
	}

	session, ok := svc.sessionStore.Get(result.SessionID)
	if !ok {
		t.Fatal("session 未在 sessionStore 中找到")
	}
	if session.ProxyURL != "http://proxy.example.com:8080" {
		t.Fatalf("ProxyURL 不匹配: got=%q", session.ProxyURL)
	}
}

func TestOAuthService_GenerateSetupTokenURL(t *testing.T) {
	t.Parallel()

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, &mockClaudeOAuthClient{})
	defer svc.Stop()

	result, err := svc.GenerateSetupTokenURL(context.Background(), nil)
	if err != nil {
		t.Fatalf("GenerateSetupTokenURL 返回错误: %v", err)
	}
	if result == nil {
		t.Fatal("GenerateSetupTokenURL 返回 nil")
	}

	// 验证 scope 是 inference
	session, ok := svc.sessionStore.Get(result.SessionID)
	if !ok {
		t.Fatal("session 未在 sessionStore 中找到")
	}
	if session.Scope != oauth.ScopeInference {
		t.Fatalf("scope 不匹配: got=%q want=%q", session.Scope, oauth.ScopeInference)
	}
}

func TestOAuthService_ExchangeCode_SessionNotFound(t *testing.T) {
	t.Parallel()

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, &mockClaudeOAuthClient{})
	defer svc.Stop()

	_, err := svc.ExchangeCode(context.Background(), &ExchangeCodeInput{
		SessionID: "nonexistent-session",
		Code:      "test-code",
	})
	if err == nil {
		t.Fatal("ExchangeCode 应返回错误（session 不存在）")
	}
	if err.Error() != "session not found or expired" {
		t.Fatalf("错误信息不匹配: got=%q", err.Error())
	}
}

func TestOAuthService_ExchangeCode_Success(t *testing.T) {
	t.Parallel()

	exchangeCalled := false
	client := &mockClaudeOAuthClient{
		exchangeCodeFunc: func(ctx context.Context, code, codeVerifier, state, proxyURL string, isSetupToken bool) (*oauth.TokenResponse, error) {
			exchangeCalled = true
			if code != "auth-code-123" {
				t.Errorf("code 不匹配: got=%q", code)
			}
			if isSetupToken {
				t.Error("isSetupToken 应为 false（ScopeOAuth）")
			}
			return &oauth.TokenResponse{
				AccessToken:  "access-token-abc",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				RefreshToken: "refresh-token-xyz",
				Scope:        oauth.ScopeOAuth,
				Organization: &oauth.OrgInfo{UUID: "org-uuid-111"},
				Account:      &oauth.AccountInfo{UUID: "acc-uuid-222", EmailAddress: "test@example.com"},
			}, nil
		},
	}

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
	defer svc.Stop()

	// 先生成 URL 以创建 session
	result, err := svc.GenerateAuthURL(context.Background(), nil)
	if err != nil {
		t.Fatalf("GenerateAuthURL 返回错误: %v", err)
	}

	// 交换 code
	tokenInfo, err := svc.ExchangeCode(context.Background(), &ExchangeCodeInput{
		SessionID: result.SessionID,
		Code:      "auth-code-123",
	})
	if err != nil {
		t.Fatalf("ExchangeCode 返回错误: %v", err)
	}

	if !exchangeCalled {
		t.Fatal("ExchangeCodeForToken 未被调用")
	}
	if tokenInfo.AccessToken != "access-token-abc" {
		t.Fatalf("AccessToken 不匹配: got=%q", tokenInfo.AccessToken)
	}
	if tokenInfo.TokenType != "Bearer" {
		t.Fatalf("TokenType 不匹配: got=%q", tokenInfo.TokenType)
	}
	if tokenInfo.RefreshToken != "refresh-token-xyz" {
		t.Fatalf("RefreshToken 不匹配: got=%q", tokenInfo.RefreshToken)
	}
	if tokenInfo.OrgUUID != "org-uuid-111" {
		t.Fatalf("OrgUUID 不匹配: got=%q", tokenInfo.OrgUUID)
	}
	if tokenInfo.AccountUUID != "acc-uuid-222" {
		t.Fatalf("AccountUUID 不匹配: got=%q", tokenInfo.AccountUUID)
	}
	if tokenInfo.EmailAddress != "test@example.com" {
		t.Fatalf("EmailAddress 不匹配: got=%q", tokenInfo.EmailAddress)
	}
	if tokenInfo.ExpiresIn != 3600 {
		t.Fatalf("ExpiresIn 不匹配: got=%d", tokenInfo.ExpiresIn)
	}
	if tokenInfo.ExpiresAt == 0 {
		t.Fatal("ExpiresAt 不应为 0")
	}

	// 验证 session 已被删除
	_, ok := svc.sessionStore.Get(result.SessionID)
	if ok {
		t.Fatal("session 应在交换成功后被删除")
	}
}

func TestOAuthService_ExchangeCode_SetupToken(t *testing.T) {
	t.Parallel()

	client := &mockClaudeOAuthClient{
		exchangeCodeFunc: func(ctx context.Context, code, codeVerifier, state, proxyURL string, isSetupToken bool) (*oauth.TokenResponse, error) {
			if !isSetupToken {
				t.Error("isSetupToken 应为 true（ScopeInference）")
			}
			return &oauth.TokenResponse{
				AccessToken: "setup-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
				Scope:       oauth.ScopeInference,
			}, nil
		},
	}

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
	defer svc.Stop()

	// 使用 SetupToken URL（inference scope）
	result, err := svc.GenerateSetupTokenURL(context.Background(), nil)
	if err != nil {
		t.Fatalf("GenerateSetupTokenURL 返回错误: %v", err)
	}

	tokenInfo, err := svc.ExchangeCode(context.Background(), &ExchangeCodeInput{
		SessionID: result.SessionID,
		Code:      "setup-code",
	})
	if err != nil {
		t.Fatalf("ExchangeCode 返回错误: %v", err)
	}
	if tokenInfo.AccessToken != "setup-token" {
		t.Fatalf("AccessToken 不匹配: got=%q", tokenInfo.AccessToken)
	}
}

func TestOAuthService_ExchangeCode_ClientError(t *testing.T) {
	t.Parallel()

	client := &mockClaudeOAuthClient{
		exchangeCodeFunc: func(ctx context.Context, code, codeVerifier, state, proxyURL string, isSetupToken bool) (*oauth.TokenResponse, error) {
			return nil, fmt.Errorf("upstream error: invalid code")
		},
	}

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
	defer svc.Stop()

	result, _ := svc.GenerateAuthURL(context.Background(), nil)
	_, err := svc.ExchangeCode(context.Background(), &ExchangeCodeInput{
		SessionID: result.SessionID,
		Code:      "bad-code",
	})
	if err == nil {
		t.Fatal("ExchangeCode 应返回错误")
	}
	if err.Error() != "upstream error: invalid code" {
		t.Fatalf("错误信息不匹配: got=%q", err.Error())
	}
}

func TestOAuthService_RefreshToken(t *testing.T) {
	t.Parallel()

	client := &mockClaudeOAuthClient{
		refreshTokenFunc: func(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error) {
			if refreshToken != "my-refresh-token" {
				t.Errorf("refreshToken 不匹配: got=%q", refreshToken)
			}
			if proxyURL != "" {
				t.Errorf("proxyURL 应为空: got=%q", proxyURL)
			}
			return &oauth.TokenResponse{
				AccessToken:  "new-access-token",
				TokenType:    "Bearer",
				ExpiresIn:    7200,
				RefreshToken: "new-refresh-token",
				Scope:        oauth.ScopeOAuth,
			}, nil
		},
	}

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
	defer svc.Stop()

	tokenInfo, err := svc.RefreshToken(context.Background(), "my-refresh-token", "")
	if err != nil {
		t.Fatalf("RefreshToken 返回错误: %v", err)
	}
	if tokenInfo.AccessToken != "new-access-token" {
		t.Fatalf("AccessToken 不匹配: got=%q", tokenInfo.AccessToken)
	}
	if tokenInfo.RefreshToken != "new-refresh-token" {
		t.Fatalf("RefreshToken 不匹配: got=%q", tokenInfo.RefreshToken)
	}
	if tokenInfo.ExpiresIn != 7200 {
		t.Fatalf("ExpiresIn 不匹配: got=%d", tokenInfo.ExpiresIn)
	}
	if tokenInfo.ExpiresAt == 0 {
		t.Fatal("ExpiresAt 不应为 0")
	}
}

func TestOAuthService_RefreshToken_Error(t *testing.T) {
	t.Parallel()

	client := &mockClaudeOAuthClient{
		refreshTokenFunc: func(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error) {
			return nil, fmt.Errorf("invalid_grant: token expired")
		},
	}

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
	defer svc.Stop()

	_, err := svc.RefreshToken(context.Background(), "expired-token", "")
	if err == nil {
		t.Fatal("RefreshToken 应返回错误")
	}
}

func TestOAuthService_RefreshAccountToken_NoRefreshToken(t *testing.T) {
	t.Parallel()

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, &mockClaudeOAuthClient{})
	defer svc.Stop()

	// 无 refresh_token 的账号
	account := &Account{
		ID:       1,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"access_token": "some-token",
		},
	}
	_, err := svc.RefreshAccountToken(context.Background(), account)
	if err == nil {
		t.Fatal("RefreshAccountToken 应返回错误（无 refresh_token）")
	}
	if err.Error() != "no refresh token available" {
		t.Fatalf("错误信息不匹配: got=%q", err.Error())
	}
}

func TestOAuthService_RefreshAccountToken_EmptyRefreshToken(t *testing.T) {
	t.Parallel()

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, &mockClaudeOAuthClient{})
	defer svc.Stop()

	account := &Account{
		ID:       2,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"access_token":  "some-token",
			"refresh_token": "",
		},
	}
	_, err := svc.RefreshAccountToken(context.Background(), account)
	if err == nil {
		t.Fatal("RefreshAccountToken 应返回错误（refresh_token 为空）")
	}
}

func TestOAuthService_RefreshAccountToken_Success(t *testing.T) {
	t.Parallel()

	client := &mockClaudeOAuthClient{
		refreshTokenFunc: func(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error) {
			if refreshToken != "account-refresh-token" {
				t.Errorf("refreshToken 不匹配: got=%q", refreshToken)
			}
			return &oauth.TokenResponse{
				AccessToken:  "refreshed-access",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				RefreshToken: "new-refresh",
			}, nil
		},
	}

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
	defer svc.Stop()

	account := &Account{
		ID:       3,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"access_token":  "old-access",
			"refresh_token": "account-refresh-token",
		},
	}

	tokenInfo, err := svc.RefreshAccountToken(context.Background(), account)
	if err != nil {
		t.Fatalf("RefreshAccountToken 返回错误: %v", err)
	}
	if tokenInfo.AccessToken != "refreshed-access" {
		t.Fatalf("AccessToken 不匹配: got=%q", tokenInfo.AccessToken)
	}
}

func TestOAuthService_RefreshAccountToken_WithProxy(t *testing.T) {
	t.Parallel()

	proxyRepo := &mockProxyRepoForOAuth{
		getByIDFunc: func(ctx context.Context, id int64) (*Proxy, error) {
			return &Proxy{
				Protocol: "socks5",
				Host:     "socks.example.com",
				Port:     1080,
				Username: "user",
				Password: "pass",
			}, nil
		},
	}

	client := &mockClaudeOAuthClient{
		refreshTokenFunc: func(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error) {
			if proxyURL != "socks5://user:pass@socks.example.com:1080" {
				t.Errorf("proxyURL 不匹配: got=%q", proxyURL)
			}
			return &oauth.TokenResponse{
				AccessToken: "refreshed",
				ExpiresIn:   3600,
			}, nil
		},
	}

	svc := NewOAuthService(proxyRepo, client)
	defer svc.Stop()

	proxyID := int64(10)
	account := &Account{
		ID:       4,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		ProxyID:  &proxyID,
		Credentials: map[string]any{
			"refresh_token": "rt-with-proxy",
		},
	}

	_, err := svc.RefreshAccountToken(context.Background(), account)
	if err != nil {
		t.Fatalf("RefreshAccountToken 返回错误: %v", err)
	}
}

func TestOAuthService_ExchangeCode_NilOrg(t *testing.T) {
	t.Parallel()

	client := &mockClaudeOAuthClient{
		exchangeCodeFunc: func(ctx context.Context, code, codeVerifier, state, proxyURL string, isSetupToken bool) (*oauth.TokenResponse, error) {
			return &oauth.TokenResponse{
				AccessToken:  "token-no-org",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				Organization: nil,
				Account:      nil,
			}, nil
		},
	}

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
	defer svc.Stop()

	result, _ := svc.GenerateAuthURL(context.Background(), nil)
	tokenInfo, err := svc.ExchangeCode(context.Background(), &ExchangeCodeInput{
		SessionID: result.SessionID,
		Code:      "code",
	})
	if err != nil {
		t.Fatalf("ExchangeCode 返回错误: %v", err)
	}
	if tokenInfo.OrgUUID != "" {
		t.Fatalf("OrgUUID 应为空: got=%q", tokenInfo.OrgUUID)
	}
	if tokenInfo.AccountUUID != "" {
		t.Fatalf("AccountUUID 应为空: got=%q", tokenInfo.AccountUUID)
	}
}

func TestOAuthService_Stop_NoPanic(t *testing.T) {
	t.Parallel()

	svc := NewOAuthService(&mockProxyRepoForOAuth{}, &mockClaudeOAuthClient{})

	// 调用 Stop 不应 panic
	svc.Stop()

	// 多次调用也不应 panic
	svc.Stop()
}

// rotatingRefresh returns a refresh mock that rotates every refresh token it is
// handed, the way Anthropic's token endpoint does: "sk-ant-ort01-X" becomes
// access "sk-ant-oat01-X-NEW" and refresh "sk-ant-ort01-X-NEW".
func rotatingRefresh(calls *[]string) func(context.Context, string, string) (*oauth.TokenResponse, error) {
	return func(_ context.Context, refreshToken, _ string) (*oauth.TokenResponse, error) {
		if calls != nil {
			*calls = append(*calls, refreshToken)
		}
		suffix := strings.TrimPrefix(refreshToken, "sk-ant-ort01-")
		return &oauth.TokenResponse{
			AccessToken:  "sk-ant-oat01-" + suffix + "-NEW",
			TokenType:    "Bearer",
			ExpiresIn:    28800,
			RefreshToken: "sk-ant-ort01-" + suffix + "-NEW",
			Scope:        "user:inference user:profile",
		}, nil
	}
}

const importDeadRefreshErr = `token refresh failed: status 400, body: {"error": "invalid_grant"}`

func TestOAuthService_ImportOAuthCredentials(t *testing.T) {
	t.Parallel()

	// Synthetic tokens — never a real credential.
	const raw = `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-IMPORT","refreshToken":"sk-ant-ort01-IMPORT","expiresAt":1787183506000,"subscriptionType":"max_20x"}}`

	// The imported refresh token is shared with the Claude Code install it was
	// exported from. Whichever side refreshes first rotates it and the other is
	// left holding a dead token (invalid_grant). Rotating once at import makes
	// sub2api the sole owner of the chain from the start.
	t.Run("rotates the imported refresh token so sub2api owns the chain", func(t *testing.T) {
		var refreshCalls []string
		var bootTokens []string
		client := &mockClaudeOAuthClient{
			refreshTokenFunc: rotatingRefresh(&refreshCalls),
			bootstrapFunc: func(_ context.Context, accessToken, _ string) (*ClaudeBootstrapInfo, error) {
				bootTokens = append(bootTokens, accessToken)
				return &ClaudeBootstrapInfo{
					AccountUUID:      "acc-123",
					OrganizationUUID: "org-456",
					EmailAddress:     "user@example.com",
				}, nil
			},
		}
		svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
		defer svc.Stop()

		before := time.Now().Unix()
		info, err := svc.ImportOAuthCredentials(context.Background(), &ImportOAuthCredentialsInput{Raw: raw})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(refreshCalls) != 1 || refreshCalls[0] != "sk-ant-ort01-IMPORT" {
			t.Fatalf("expected one refresh with the imported token, got %v", refreshCalls)
		}
		if info.AccessToken != "sk-ant-oat01-IMPORT-NEW" || info.RefreshToken != "sk-ant-ort01-IMPORT-NEW" {
			t.Fatalf("account must store the rotated tokens, got %q / %q", info.AccessToken, info.RefreshToken)
		}
		if info.ExpiresIn != 28800 || info.ExpiresAt < before+28800 {
			t.Errorf("expiry must come from the refresh response: in=%d at=%d", info.ExpiresIn, info.ExpiresAt)
		}
		if info.TokenType != "Bearer" {
			t.Errorf("TokenType = %q, want Bearer", info.TokenType)
		}
		if info.Scope != "user:inference user:profile" {
			t.Errorf("Scope = %q, want the granted scope", info.Scope)
		}
		if len(bootTokens) != 1 || bootTokens[0] != "sk-ant-oat01-IMPORT-NEW" {
			t.Errorf("bootstrap must use the fresh access token, got %v", bootTokens)
		}
		if info.OrgUUID != "org-456" || info.AccountUUID != "acc-123" || info.EmailAddress != "user@example.com" {
			t.Errorf("identity not enriched: %+v", info)
		}
	})

	t.Run("keeps the imported refresh token and scope when the response omits them", func(t *testing.T) {
		const withScopes = `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-IMPORT","refreshToken":"sk-ant-ort01-IMPORT","expiresAt":1787183506000,"scopes":["user:inference","user:profile"]}}`
		client := &mockClaudeOAuthClient{
			refreshTokenFunc: func(_ context.Context, _, _ string) (*oauth.TokenResponse, error) {
				return &oauth.TokenResponse{AccessToken: "sk-ant-oat01-FRESH", ExpiresIn: 28800}, nil
			},
		}
		svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
		defer svc.Stop()

		info, err := svc.ImportOAuthCredentials(context.Background(), &ImportOAuthCredentialsInput{Raw: withScopes})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info.AccessToken != "sk-ant-oat01-FRESH" || info.RefreshToken != "sk-ant-ort01-IMPORT" {
			t.Fatalf("tokens = %q / %q", info.AccessToken, info.RefreshToken)
		}
		if info.TokenType != "Bearer" {
			t.Errorf("TokenType = %q, want Bearer fallback", info.TokenType)
		}
		if info.Scope != "user:inference user:profile" {
			t.Errorf("Scope = %q, want the imported scopes", info.Scope)
		}
	})

	t.Run("bootstrap failure does not fail import", func(t *testing.T) {
		client := &mockClaudeOAuthClient{
			refreshTokenFunc: rotatingRefresh(nil),
			bootstrapFunc: func(_ context.Context, _, _ string) (*ClaudeBootstrapInfo, error) {
				return nil, fmt.Errorf("bootstrap unavailable")
			},
		}
		svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
		defer svc.Stop()

		info, err := svc.ImportOAuthCredentials(context.Background(), &ImportOAuthCredentialsInput{Raw: raw})
		if err != nil {
			t.Fatalf("import must not fail on bootstrap error: %v", err)
		}
		if info.RefreshToken != "sk-ant-ort01-IMPORT-NEW" {
			t.Fatalf("refresh token lost: %q", info.RefreshToken)
		}
		if info.OrgUUID != "" || info.AccountUUID != "" {
			t.Errorf("identity should be empty on bootstrap failure: %+v", info)
		}
	})

	// A credential whose refresh token is already dead would otherwise become an
	// account that works until its access token expires and then fails with
	// invalid_grant hours later. Reject it at import, where the operator can act.
	t.Run("rejects a credential whose refresh token is already dead", func(t *testing.T) {
		client := &mockClaudeOAuthClient{
			refreshTokenFunc: func(_ context.Context, _, _ string) (*oauth.TokenResponse, error) {
				return nil, fmt.Errorf(importDeadRefreshErr)
			},
		}
		svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
		defer svc.Stop()

		_, err := svc.ImportOAuthCredentials(context.Background(), &ImportOAuthCredentialsInput{Raw: raw})
		if err == nil {
			t.Fatal("expected a dead refresh token to be rejected")
		}
		if !strings.Contains(err.Error(), "invalid_grant") {
			t.Errorf("error should carry the upstream reason, got %v", err)
		}
	})

	t.Run("rejects invalid credential blob", func(t *testing.T) {
		svc := NewOAuthService(&mockProxyRepoForOAuth{}, &mockClaudeOAuthClient{})
		defer svc.Stop()

		if _, err := svc.ImportOAuthCredentials(context.Background(), &ImportOAuthCredentialsInput{Raw: "garbage"}); err == nil {
			t.Fatal("expected error for invalid blob")
		}
	})
}

func TestOAuthService_ImportOAuthCredentialsBatch(t *testing.T) {
	t.Parallel()

	// Synthetic tokens — never real credentials.
	const first = `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-ONE","refreshToken":"sk-ant-ort01-ONE","expiresAt":1787183506000,"subscriptionType":"max_20x"}}`
	const second = `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-TWO","refreshToken":"sk-ant-ort01-TWO","expiresAt":1787197125235,"subscriptionType":"default_claude_ai"}}`

	t.Run("returns one token info per pasted credential, enriched individually", func(t *testing.T) {
		emailsByToken := map[string]string{
			"sk-ant-oat01-ONE-NEW": "one@example.com",
			"sk-ant-oat01-TWO-NEW": "two@example.com",
		}
		client := &mockClaudeOAuthClient{
			refreshTokenFunc: rotatingRefresh(nil),
			bootstrapFunc: func(_ context.Context, accessToken, _ string) (*ClaudeBootstrapInfo, error) {
				return &ClaudeBootstrapInfo{EmailAddress: emailsByToken[accessToken]}, nil
			},
		}
		svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
		defer svc.Stop()

		result, err := svc.ImportOAuthCredentialsBatch(context.Background(), &ImportOAuthCredentialsInput{
			Raw: first + "\n" + second,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		infos := result.Accounts
		if len(infos) != 2 || len(result.Failed) != 0 {
			t.Fatalf("got %d token infos / %d failures, want 2 / 0", len(infos), len(result.Failed))
		}
		if infos[0].RefreshToken != "sk-ant-ort01-ONE-NEW" || infos[1].RefreshToken != "sk-ant-ort01-TWO-NEW" {
			t.Fatalf("order or content wrong: %q / %q", infos[0].RefreshToken, infos[1].RefreshToken)
		}
		if infos[0].EmailAddress != "one@example.com" || infos[1].EmailAddress != "two@example.com" {
			t.Errorf("each credential must be enriched with its own identity: %q / %q",
				infos[0].EmailAddress, infos[1].EmailAddress)
		}
	})

	// One dead refresh token in the batch must not cost the other accounts their
	// import; it is reported by position so the operator knows which one to redo.
	t.Run("a dead credential is reported without sinking the batch", func(t *testing.T) {
		client := &mockClaudeOAuthClient{
			refreshTokenFunc: func(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error) {
				if refreshToken == "sk-ant-ort01-ONE" {
					return nil, fmt.Errorf(importDeadRefreshErr)
				}
				return rotatingRefresh(nil)(ctx, refreshToken, proxyURL)
			},
		}
		svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
		defer svc.Stop()

		result, err := svc.ImportOAuthCredentialsBatch(context.Background(), &ImportOAuthCredentialsInput{
			Raw: "[" + first + "," + second + "]",
		})
		if err != nil {
			t.Fatalf("batch must not fail when only one credential is dead: %v", err)
		}
		if len(result.Accounts) != 1 || result.Accounts[0].RefreshToken != "sk-ant-ort01-TWO-NEW" {
			t.Fatalf("unexpected accounts: %+v", result.Accounts)
		}
		if len(result.Failed) != 1 || result.Failed[0].Index != 1 {
			t.Fatalf("expected credential #1 reported as failed, got %+v", result.Failed)
		}
		if !strings.Contains(result.Failed[0].Error, "invalid_grant") {
			t.Errorf("failure should carry the upstream reason, got %q", result.Failed[0].Error)
		}
	})

	t.Run("fails the call when every credential is dead", func(t *testing.T) {
		client := &mockClaudeOAuthClient{
			refreshTokenFunc: func(_ context.Context, _, _ string) (*oauth.TokenResponse, error) {
				return nil, fmt.Errorf(importDeadRefreshErr)
			},
		}
		svc := NewOAuthService(&mockProxyRepoForOAuth{}, client)
		defer svc.Stop()

		if _, err := svc.ImportOAuthCredentialsBatch(context.Background(), &ImportOAuthCredentialsInput{
			Raw: first + "\n" + second,
		}); err == nil {
			t.Fatal("expected an error when no credential could be imported")
		}
	})

	t.Run("refreshes through the selected proxy", func(t *testing.T) {
		var proxies []string
		client := &mockClaudeOAuthClient{
			refreshTokenFunc: func(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error) {
				proxies = append(proxies, proxyURL)
				return rotatingRefresh(nil)(ctx, refreshToken, proxyURL)
			},
		}
		proxyRepo := &mockProxyRepoForOAuth{
			getByIDFunc: func(_ context.Context, id int64) (*Proxy, error) {
				return &Proxy{ID: id, Protocol: "http", Host: "proxy.local", Port: 8080}, nil
			},
		}
		svc := NewOAuthService(proxyRepo, client)
		defer svc.Stop()

		proxyID := int64(9)
		if _, err := svc.ImportOAuthCredentialsBatch(context.Background(), &ImportOAuthCredentialsInput{
			Raw:     first,
			ProxyID: &proxyID,
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(proxies) != 1 || !strings.Contains(proxies[0], "proxy.local:8080") {
			t.Fatalf("refresh must use the account proxy, got %v", proxies)
		}
	})

	t.Run("rejects a batch containing an incomplete credential", func(t *testing.T) {
		svc := NewOAuthService(&mockProxyRepoForOAuth{}, &mockClaudeOAuthClient{})
		defer svc.Stop()

		_, err := svc.ImportOAuthCredentialsBatch(context.Background(), &ImportOAuthCredentialsInput{
			Raw: first + "\n" + `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-NOREFRESH"}}`,
		})
		if err == nil {
			t.Fatal("expected an error naming the bad credential")
		}
	})
}
