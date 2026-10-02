package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/Wei-Shaw/sub2api/internal/util/claudecookie"
)

// OpenAIOAuthClient interface for OpenAI OAuth operations
type OpenAIOAuthClient interface {
	ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, proxyURL, clientID string) (*openai.TokenResponse, error)
	RefreshToken(ctx context.Context, refreshToken, proxyURL string) (*openai.TokenResponse, error)
	RefreshTokenWithClientID(ctx context.Context, refreshToken, proxyURL string, clientID string) (*openai.TokenResponse, error)
}

// GrokOAuthClient interface for xAI/Grok OAuth operations.
type GrokOAuthClient interface {
	ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, proxyURL, clientID string) (*xai.TokenResponse, error)
	RefreshToken(ctx context.Context, refreshToken, proxyURL, clientID string) (*xai.TokenResponse, error)
	// LoginWithPassword exchanges email/password for a short-lived Web SSO cookie.
	// Callers must convert via ConvertSSOToBuild and must not persist password or raw SSO.
	LoginWithPassword(ctx context.Context, email, password, proxyURL string) (*GrokPasswordLoginResult, error)
	ConvertSSOToBuild(ctx context.Context, ssoToken, proxyURL string) (*xai.TokenResponse, error)
}

// GrokOAuthTokenService is the narrow refresh port used by Grok token providers.
type GrokOAuthTokenService interface {
	RefreshAccountToken(ctx context.Context, account *Account) (*GrokTokenInfo, error)
	BuildAccountCredentials(tokenInfo *GrokTokenInfo) map[string]any
}

// ClaudeOAuthClient handles HTTP requests for Claude OAuth flows.
//
// cookieHeader is a full "name=value; name=value" Cookie header rather than a
// bare sessionKey, so an operator's browser cookie export can be replayed as-is.
type ClaudeOAuthClient interface {
	GetOrganizationUUID(ctx context.Context, cookieHeader, proxyURL string) (string, error)
	GetAuthorizationCode(ctx context.Context, cookieHeader, orgUUID, scope, codeChallenge, state, proxyURL string) (string, error)
	ExchangeCodeForToken(ctx context.Context, code, codeVerifier, state, proxyURL string, isSetupToken bool) (*oauth.TokenResponse, error)
	RefreshToken(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error)
	// BootstrapAccount enriches an OAuth access token with account identity
	// (org UUID, account UUID, email) via Anthropic's claude_cli bootstrap
	// endpoint. It is best-effort: callers treat a nil result as "unknown"
	// rather than a failure, so importing a valid token never blocks on it.
	BootstrapAccount(ctx context.Context, accessToken, proxyURL string) (*ClaudeBootstrapInfo, error)
}

// ClaudeBootstrapInfo is the account identity Anthropic returns for an access token.
type ClaudeBootstrapInfo struct {
	AccountUUID      string
	OrganizationUUID string
	EmailAddress     string
	SubscriptionType string
}

// OAuthService handles OAuth authentication flows
type OAuthService struct {
	sessionStore *oauth.SessionStore
	proxyRepo    ProxyRepository
	oauthClient  ClaudeOAuthClient
}

// NewOAuthService creates a new OAuth service
func NewOAuthService(proxyRepo ProxyRepository, oauthClient ClaudeOAuthClient) *OAuthService {
	return &OAuthService{
		sessionStore: oauth.NewSessionStore(),
		proxyRepo:    proxyRepo,
		oauthClient:  oauthClient,
	}
}

// GenerateAuthURLResult contains the authorization URL and session info
type GenerateAuthURLResult struct {
	AuthURL   string `json:"auth_url"`
	SessionID string `json:"session_id"`
}

// GenerateAuthURL generates an OAuth authorization URL with full scope
func (s *OAuthService) GenerateAuthURL(ctx context.Context, proxyID *int64) (*GenerateAuthURLResult, error) {
	return s.generateAuthURLWithScope(ctx, oauth.ScopeOAuth, proxyID)
}

// GenerateSetupTokenURL generates an OAuth authorization URL for setup token (inference only)
func (s *OAuthService) GenerateSetupTokenURL(ctx context.Context, proxyID *int64) (*GenerateAuthURLResult, error) {
	scope := oauth.ScopeInference
	return s.generateAuthURLWithScope(ctx, scope, proxyID)
}

func (s *OAuthService) generateAuthURLWithScope(ctx context.Context, scope string, proxyID *int64) (*GenerateAuthURLResult, error) {
	// Generate PKCE values
	state, err := oauth.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	codeChallenge := oauth.GenerateCodeChallenge(codeVerifier)

	// Generate session ID
	sessionID, err := oauth.GenerateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Get proxy URL if specified
	var proxyURL string
	if proxyID != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *proxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	// Store session
	session := &oauth.OAuthSession{
		State:        state,
		CodeVerifier: codeVerifier,
		Scope:        scope,
		ProxyURL:     proxyURL,
		CreatedAt:    time.Now(),
	}
	s.sessionStore.Set(sessionID, session)

	// Build authorization URL
	authURL := oauth.BuildAuthorizationURL(state, codeChallenge, scope)

	return &GenerateAuthURLResult{
		AuthURL:   authURL,
		SessionID: sessionID,
	}, nil
}

// ExchangeCodeInput represents the input for code exchange
type ExchangeCodeInput struct {
	SessionID string
	Code      string
	ProxyID   *int64
}

// TokenInfo represents the token information stored in credentials
type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	OrgUUID      string `json:"org_uuid,omitempty"`
	AccountUUID  string `json:"account_uuid,omitempty"`
	EmailAddress string `json:"email_address,omitempty"`
}

// ExchangeCode exchanges authorization code for tokens
func (s *OAuthService) ExchangeCode(ctx context.Context, input *ExchangeCodeInput) (*TokenInfo, error) {
	// Get session
	session, ok := s.sessionStore.Get(input.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found or expired")
	}

	// Get proxy URL
	proxyURL := session.ProxyURL
	if input.ProxyID != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *input.ProxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	// Determine if this is a setup token (scope is inference only)
	isSetupToken := session.Scope == oauth.ScopeInference

	// Exchange code for token
	tokenInfo, err := s.exchangeCodeForToken(ctx, input.Code, session.CodeVerifier, session.State, proxyURL, isSetupToken)
	if err != nil {
		return nil, err
	}

	// Delete session after successful exchange
	s.sessionStore.Delete(input.SessionID)

	return tokenInfo, nil
}

// ImportOAuthCredentialsInput carries pasted Claude Code credential files.
type ImportOAuthCredentialsInput struct {
	// Raw is the credential blob: either {"claudeAiOauth":{...}} as written by
	// Claude Code, or a bare {...} object with the same fields. Several such
	// objects may be supplied at once — as a JSON array, one per line, or simply
	// concatenated — to import a batch of accounts in one call.
	Raw     string
	ProxyID *int64
}

// ImportOAuthCredentialFailure names a pasted credential that could not be
// imported. Index is 1-based in paste order (after duplicate collapsing).
type ImportOAuthCredentialFailure struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

// ImportOAuthCredentialsResult holds the accounts ready to be created and the
// credentials that were rejected, so one dead credential never sinks a batch.
type ImportOAuthCredentialsResult struct {
	Accounts []*TokenInfo                   `json:"accounts"`
	Failed   []ImportOAuthCredentialFailure `json:"failed"`
}

// ImportOAuthCredentials imports an already-issued OAuth credential bundle into
// a TokenInfo usable by the account-creation flow.
//
// It mints nothing and runs no authorization step: it accepts a credential the
// operator already holds (from a genuine Claude Code login), rotates its refresh
// token once and returns the same shape ExchangeCode does, so the rest of the
// OAuth account pipeline is reused unchanged. See ImportOAuthCredentialsBatch
// for why the rotation is required.
//
// When the blob holds several credentials only the first imported one is
// returned; callers that support batches use ImportOAuthCredentialsBatch.
func (s *OAuthService) ImportOAuthCredentials(ctx context.Context, input *ImportOAuthCredentialsInput) (*TokenInfo, error) {
	result, err := s.ImportOAuthCredentialsBatch(ctx, input)
	if err != nil {
		return nil, err
	}
	return result.Accounts[0], nil
}

// ImportOAuthCredentialsBatch imports every credential found in the blob and
// returns one TokenInfo per account, in the order pasted. Duplicates sharing a
// refresh token are collapsed by the parser.
//
// Each credential's refresh token is rotated immediately. Anthropic refresh
// tokens are single-use: the exported token is still held by the Claude Code
// install it came from, and whichever side refreshes first leaves the other
// with invalid_grant — which surfaced as imported accounts dying at their first
// refresh, ~8h after import. Rotating here makes sub2api the sole owner of a
// fresh token, and a token that is already dead is rejected now instead of
// hours later. Credentials that fail are reported in Failed; the call errors
// only when nothing could be imported, so Accounts is never empty on success.
func (s *OAuthService) ImportOAuthCredentialsBatch(ctx context.Context, input *ImportOAuthCredentialsInput) (*ImportOAuthCredentialsResult, error) {
	parsedCredentials, err := oauth.ParseClaudeOAuthCredentialsMany(input.Raw)
	if err != nil {
		return nil, fmt.Errorf("invalid OAuth credentials: %w", err)
	}
	if len(parsedCredentials) == 0 {
		return nil, fmt.Errorf("invalid OAuth credentials: no credential object found")
	}

	var proxyURL string
	if input.ProxyID != nil {
		proxy, errProxy := s.proxyRepo.GetByID(ctx, *input.ProxyID)
		if errProxy == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	result := &ImportOAuthCredentialsResult{
		Accounts: make([]*TokenInfo, 0, len(parsedCredentials)),
		Failed:   []ImportOAuthCredentialFailure{},
	}
	for i, parsed := range parsedCredentials {
		tokenInfo, errRefresh := s.claimImportedCredential(ctx, parsed, proxyURL)
		if errRefresh != nil {
			log.Printf("[OAuth] Import credential #%d rejected: %v", i+1, errRefresh)
			result.Failed = append(result.Failed, ImportOAuthCredentialFailure{
				Index: i + 1,
				Error: errRefresh.Error(),
			})
			continue
		}

		// Best-effort identity enrichment. A failure here (network error, endpoint
		// change) must not fail the import — identity fields are optional on the
		// account. One credential failing must not sink the others.
		if info, errBoot := s.oauthClient.BootstrapAccount(ctx, tokenInfo.AccessToken, proxyURL); errBoot == nil && info != nil {
			tokenInfo.OrgUUID = info.OrganizationUUID
			tokenInfo.AccountUUID = info.AccountUUID
			tokenInfo.EmailAddress = info.EmailAddress
		} else if errBoot != nil {
			log.Printf("[OAuth] Import bootstrap enrichment skipped: %v", errBoot)
		}

		result.Accounts = append(result.Accounts, tokenInfo)
	}

	if len(result.Accounts) == 0 {
		if len(result.Failed) == 1 {
			return nil, fmt.Errorf("import OAuth credentials: %s", result.Failed[0].Error)
		}
		return nil, fmt.Errorf("import OAuth credentials: all %d credentials were rejected; first: %s",
			len(result.Failed), result.Failed[0].Error)
	}
	return result, nil
}

// claimImportedCredential rotates an imported refresh token and returns the
// fresh token set. The rotated refresh token is the only one that stays valid,
// so it — not the pasted one — must be what the account stores.
func (s *OAuthService) claimImportedCredential(ctx context.Context, parsed *oauth.ParsedOAuthCredentials, proxyURL string) (*TokenInfo, error) {
	tokenInfo, err := s.RefreshToken(ctx, parsed.RefreshToken, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("refresh token rejected by Anthropic (already used or revoked; export a fresh credential): %w", err)
	}
	if tokenInfo.AccessToken == "" {
		return nil, fmt.Errorf("refresh response carried no access token")
	}
	// The token endpoint may omit fields it did not change; fall back to the
	// imported values so the account never loses its refresh token or scope.
	if tokenInfo.RefreshToken == "" {
		tokenInfo.RefreshToken = parsed.RefreshToken
	}
	if tokenInfo.Scope == "" {
		tokenInfo.Scope = parsed.Scope
	}
	if tokenInfo.TokenType == "" {
		tokenInfo.TokenType = "Bearer"
	}
	return tokenInfo, nil
}

// CookieAuthInput represents the input for cookie-based authentication
type CookieAuthInput struct {
	SessionKey string
	// CookieHeader is the full Cookie header to replay against claude.ai. When
	// empty it is derived from SessionKey, preserving the single-key callers.
	CookieHeader string
	ProxyID      *int64
	Scope        string // "full" or "inference"
}

// cookieHeader returns the jar to send, falling back to the bare sessionKey.
func (in *CookieAuthInput) cookieHeader() string {
	if in.CookieHeader != "" {
		return in.CookieHeader
	}
	return claudecookie.JarForSessionKey(in.SessionKey)
}

// CookieAuth performs OAuth using sessionKey (cookie-based auto-auth)
func (s *OAuthService) CookieAuth(ctx context.Context, input *CookieAuthInput) (*TokenInfo, error) {
	// Get proxy URL if specified
	var proxyURL string
	if input.ProxyID != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *input.ProxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	// Determine scope and if this is a setup token
	// Internal API call uses ScopeAPI (org:create_api_key not supported)
	scope := oauth.ScopeAPI
	isSetupToken := false
	if input.Scope == "inference" {
		scope = oauth.ScopeInference
		isSetupToken = true
	}

	cookieHeader := input.cookieHeader()
	if cookieHeader == "" {
		return nil, claudecookie.ErrNoSessionKey
	}

	// Step 1: Get organization info using the cookie jar
	orgUUID, err := s.getOrganizationUUID(ctx, cookieHeader, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization info: %w", err)
	}

	// Step 2: Generate PKCE values
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	codeChallenge := oauth.GenerateCodeChallenge(codeVerifier)

	state, err := oauth.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Step 3: Get authorization code using cookie
	authCode, err := s.getAuthorizationCode(ctx, cookieHeader, orgUUID, scope, codeChallenge, state, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get authorization code: %w", err)
	}

	// Step 4: Exchange code for token
	tokenInfo, err := s.exchangeCodeForToken(ctx, authCode, codeVerifier, state, proxyURL, isSetupToken)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Ensure org_uuid is set (from step 1 if not from token response)
	if tokenInfo.OrgUUID == "" && orgUUID != "" {
		tokenInfo.OrgUUID = orgUUID
		log.Printf("[OAuth] Set org_uuid from cookie auth")
	}

	return tokenInfo, nil
}

// getOrganizationUUID gets the organization UUID from claude.ai using the cookie jar
func (s *OAuthService) getOrganizationUUID(ctx context.Context, cookieHeader, proxyURL string) (string, error) {
	return s.oauthClient.GetOrganizationUUID(ctx, cookieHeader, proxyURL)
}

// getAuthorizationCode gets the authorization code using the cookie jar
func (s *OAuthService) getAuthorizationCode(ctx context.Context, cookieHeader, orgUUID, scope, codeChallenge, state, proxyURL string) (string, error) {
	return s.oauthClient.GetAuthorizationCode(ctx, cookieHeader, orgUUID, scope, codeChallenge, state, proxyURL)
}

// exchangeCodeForToken exchanges authorization code for tokens
func (s *OAuthService) exchangeCodeForToken(ctx context.Context, code, codeVerifier, state, proxyURL string, isSetupToken bool) (*TokenInfo, error) {
	tokenResp, err := s.oauthClient.ExchangeCodeForToken(ctx, code, codeVerifier, state, proxyURL, isSetupToken)
	if err != nil {
		return nil, err
	}

	tokenInfo := &TokenInfo{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		ExpiresAt:    time.Now().Unix() + tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
	}

	if tokenResp.Organization != nil && tokenResp.Organization.UUID != "" {
		tokenInfo.OrgUUID = tokenResp.Organization.UUID
		log.Printf("[OAuth] Got org_uuid")
	}
	if tokenResp.Account != nil {
		if tokenResp.Account.UUID != "" {
			tokenInfo.AccountUUID = tokenResp.Account.UUID
			log.Printf("[OAuth] Got account_uuid")
		}
		if tokenResp.Account.EmailAddress != "" {
			tokenInfo.EmailAddress = tokenResp.Account.EmailAddress
			log.Printf("[OAuth] Got email_address")
		}
	}

	return tokenInfo, nil
}

// RefreshToken refreshes an OAuth token
func (s *OAuthService) RefreshToken(ctx context.Context, refreshToken string, proxyURL string) (*TokenInfo, error) {
	tokenResp, err := s.oauthClient.RefreshToken(ctx, refreshToken, proxyURL)
	if err != nil {
		return nil, err
	}

	return &TokenInfo{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		ExpiresAt:    time.Now().Unix() + tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
	}, nil
}

// RefreshAccountToken refreshes token for an account
func (s *OAuthService) RefreshAccountToken(ctx context.Context, account *Account) (*TokenInfo, error) {
	refreshToken := account.GetCredential("refresh_token")
	if refreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	var proxyURL string
	if account.ProxyID != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *account.ProxyID)
		if err == nil && proxy != nil {
			proxyURL = proxy.URL()
		}
	}

	return s.RefreshToken(ctx, refreshToken, proxyURL)
}

// Stop stops the session store cleanup goroutine
func (s *OAuthService) Stop() {
	s.sessionStore.Stop()
}
