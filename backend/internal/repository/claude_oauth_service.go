package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/pkg/oauth"
	"github.com/Wei-Shaw/sub2api/internal/pkg/proxyurl"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/internal/util/logredact"

	"github.com/imroc/req/v3"
)

func NewClaudeOAuthClient() service.ClaudeOAuthClient {
	return &claudeOAuthService{
		baseURL:       "https://claude.ai",
		tokenURL:      oauth.TokenURL,
		clientFactory: createReqClient,
	}
}

type claudeOAuthService struct {
	baseURL       string
	tokenURL      string
	clientFactory func(proxyURL string) (*req.Client, error)
}

// classifyAuthorizeError turns a failed /v1/oauth/{org}/authorize response into
// a typed error the panel can render as an actionable message. It returns nil
// when the failure is not one of the known cases.
func classifyAuthorizeError(statusCode int, body []byte) error {
	if statusCode != http.StatusForbidden {
		return nil
	}

	var parsed struct {
		Error struct {
			Message string `json:"message"`
			Details struct {
				ErrorCode string `json:"error_code"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}

	switch {
	case parsed.Error.Details.ErrorCode == "session_stale_relogin",
		strings.Contains(parsed.Error.Message, "not fresh enough"):
		return service.ErrClaudeSessionStale
	case strings.Contains(parsed.Error.Message, "Invalid authorization for organization"):
		return service.ErrClaudeOrgUnavailable
	case strings.Contains(parsed.Error.Message, "Invalid authorization"):
		return service.ErrClaudeCookieInvalid
	}
	return nil
}

// claudeOrganization is the subset of /api/organizations we rely on.
type claudeOrganization struct {
	UUID         string   `json:"uuid"`
	Name         string   `json:"name"`
	RavenType    *string  `json:"raven_type"` // nil for personal, "team" for team organization
	Capabilities []string `json:"capabilities"`
}

func (o claudeOrganization) hasCapability(want string) bool {
	for _, c := range o.Capabilities {
		if c == want {
			return true
		}
	}
	return false
}

// isChatOrg reports whether the org can drive claude.ai chat. API-only orgs
// (capabilities ["api","api_individual"]) cannot, and asking them for an OAuth
// code returns "Invalid authorization for organization".
func (o claudeOrganization) isChatOrg() bool {
	return o.hasCapability("chat")
}

// selectOrganization picks the org an OAuth grant should target.
//
// Preference order: a subscription org (claude_max/claude_pro), then a team org,
// then any chat-capable org, then the first org as a last resort. Ordering
// matters because /api/organizations returns API-only orgs alongside the
// subscription one and their order is not guaranteed.
func selectOrganization(orgs []claudeOrganization) (claudeOrganization, string) {
	for _, org := range orgs {
		if org.isChatOrg() && (org.hasCapability("claude_max") || org.hasCapability("claude_pro")) {
			return org, "subscription"
		}
	}
	for _, org := range orgs {
		if org.isChatOrg() && org.RavenType != nil && *org.RavenType == "team" {
			return org, "team"
		}
	}
	for _, org := range orgs {
		if org.isChatOrg() {
			return org, "chat"
		}
	}
	return orgs[0], "fallback"
}

func (s *claudeOAuthService) GetOrganizationUUID(ctx context.Context, cookieHeader, proxyURL string) (string, error) {
	client, err := s.clientFactory(proxyURL)
	if err != nil {
		return "", fmt.Errorf("create HTTP client: %w", err)
	}

	var orgs []claudeOrganization

	targetURL := s.baseURL + "/api/organizations"
	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 1: Getting organization UUID from %s", targetURL)

	resp, err := client.R().
		SetContext(ctx).
		SetHeader("Cookie", cookieHeader).
		SetHeader("Accept", "application/json").
		SetSuccessResult(&orgs).
		Get(targetURL)

	if err != nil {
		logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 1 FAILED - Request error: %v", err)
		return "", fmt.Errorf("request failed: %w", err)
	}

	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 1 Response - Status: %d", resp.StatusCode)

	if !resp.IsSuccessState() {
		return "", fmt.Errorf("failed to get organizations: status %d, body: %s", resp.StatusCode, resp.String())
	}

	if len(orgs) == 0 {
		return "", fmt.Errorf("no organizations found")
	}

	selected, reason := selectOrganization(orgs)
	logger.LegacyPrintf("repository.claude_oauth",
		"[OAuth] Step 1 SUCCESS - Selected org (%s of %d), UUID: %s, Name: %s, Capabilities: %v",
		reason, len(orgs), selected.UUID, selected.Name, selected.Capabilities)
	return selected.UUID, nil
}

func (s *claudeOAuthService) GetAuthorizationCode(ctx context.Context, cookieHeader, orgUUID, scope, codeChallenge, state, proxyURL string) (string, error) {
	client, err := s.clientFactory(proxyURL)
	if err != nil {
		return "", fmt.Errorf("create HTTP client: %w", err)
	}

	authURL := fmt.Sprintf("%s/v1/oauth/%s/authorize", s.baseURL, orgUUID)

	reqBody := map[string]any{
		"response_type":         "code",
		"client_id":             oauth.ClientID,
		"organization_uuid":     orgUUID,
		"redirect_uri":          oauth.RedirectURI,
		"scope":                 scope,
		"state":                 state,
		"code_challenge":        codeChallenge,
		"code_challenge_method": "S256",
	}

	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 2: Getting authorization code from %s", authURL)
	reqBodyJSON, _ := json.Marshal(logredact.RedactMap(reqBody))
	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 2 Request Body: %s", string(reqBodyJSON))

	var result struct {
		RedirectURI string `json:"redirect_uri"`
	}

	resp, err := client.R().
		SetContext(ctx).
		SetHeader("Cookie", cookieHeader).
		SetHeader("Accept", "application/json").
		SetHeader("Accept-Language", "en-US,en;q=0.9").
		SetHeader("Cache-Control", "no-cache").
		SetHeader("Origin", "https://claude.ai").
		SetHeader("Referer", "https://claude.ai/new").
		SetHeader("Content-Type", "application/json").
		SetBody(reqBody).
		SetSuccessResult(&result).
		Post(authURL)

	if err != nil {
		logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 2 FAILED - Request error: %v", err)
		return "", fmt.Errorf("request failed: %w", err)
	}

	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 2 Response - Status: %d, Body: %s", resp.StatusCode, logredact.RedactJSON(resp.Bytes()))

	if !resp.IsSuccessState() {
		if err := classifyAuthorizeError(resp.StatusCode, resp.Bytes()); err != nil {
			return "", err
		}
		return "", fmt.Errorf("failed to get authorization code: status %d, body: %s", resp.StatusCode, resp.String())
	}

	if result.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri in response")
	}

	parsedURL, err := url.Parse(result.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse redirect_uri: %w", err)
	}

	queryParams := parsedURL.Query()
	authCode := queryParams.Get("code")
	responseState := queryParams.Get("state")

	if authCode == "" {
		return "", fmt.Errorf("no authorization code in redirect_uri")
	}

	fullCode := authCode
	if responseState != "" {
		fullCode = authCode + "#" + responseState
	}

	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 2 SUCCESS - Got authorization code")
	return fullCode, nil
}

func (s *claudeOAuthService) ExchangeCodeForToken(ctx context.Context, code, codeVerifier, state, proxyURL string, isSetupToken bool) (*oauth.TokenResponse, error) {
	client, err := s.clientFactory(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("create HTTP client: %w", err)
	}

	// Parse code which may contain state in format "authCode#state"
	authCode := code
	codeState := ""
	if idx := strings.Index(code, "#"); idx != -1 {
		authCode = code[:idx]
		codeState = code[idx+1:]
	}

	reqBody := map[string]any{
		"code":          authCode,
		"grant_type":    "authorization_code",
		"client_id":     oauth.ClientID,
		"redirect_uri":  oauth.RedirectURI,
		"code_verifier": codeVerifier,
	}

	if codeState != "" {
		reqBody["state"] = codeState
	}

	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 3: Exchanging code for token at %s", s.tokenURL)
	reqBodyJSON, _ := json.Marshal(logredact.RedactMap(reqBody))
	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 3 Request Body: %s", string(reqBodyJSON))

	var tokenResp oauth.TokenResponse

	resp, err := client.R().
		SetContext(ctx).
		SetHeader("Accept", "application/json, text/plain, */*").
		SetHeader("Content-Type", "application/json").
		SetHeader("User-Agent", "axios/1.13.6").
		SetBody(reqBody).
		SetSuccessResult(&tokenResp).
		Post(s.tokenURL)

	if err != nil {
		logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 3 FAILED - Request error: %v", err)
		return nil, fmt.Errorf("request failed: %w", err)
	}

	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 3 Response - Status: %d, Body: %s", resp.StatusCode, logredact.RedactJSON(resp.Bytes()))

	if !resp.IsSuccessState() {
		return nil, fmt.Errorf("token exchange failed: status %d, body: %s", resp.StatusCode, resp.String())
	}

	logger.LegacyPrintf("repository.claude_oauth", "[OAuth] Step 3 SUCCESS - Got access token")
	return &tokenResp, nil
}

func (s *claudeOAuthService) RefreshToken(ctx context.Context, refreshToken, proxyURL string) (*oauth.TokenResponse, error) {
	client, err := s.clientFactory(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("create HTTP client: %w", err)
	}

	reqBody := map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     oauth.ClientID,
	}

	var tokenResp oauth.TokenResponse

	resp, err := client.R().
		SetContext(ctx).
		SetHeader("Accept", "application/json, text/plain, */*").
		SetHeader("Content-Type", "application/json").
		SetHeader("User-Agent", "axios/1.13.6").
		SetBody(reqBody).
		SetSuccessResult(&tokenResp).
		Post(s.tokenURL)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if !resp.IsSuccessState() {
		return nil, fmt.Errorf("token refresh failed: status %d, body: %s", resp.StatusCode, resp.String())
	}

	return &tokenResp, nil
}

// BootstrapAccount enriches an OAuth access token with account identity via
// Anthropic's claude_cli bootstrap endpoint. Best-effort: any non-200 or parse
// failure returns an error the caller may ignore, never a partial identity.
func (s *claudeOAuthService) BootstrapAccount(ctx context.Context, accessToken, proxyURL string) (*service.ClaudeBootstrapInfo, error) {
	client, err := s.clientFactory(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("create HTTP client: %w", err)
	}

	var body struct {
		AccountUUID      string `json:"account_uuid"`
		OrganizationUUID string `json:"organization_uuid"`
		AccountEmail     string `json:"account_email"`
		OrganizationName string `json:"organization_name"`
		SubscriptionType string `json:"subscription_type"`
	}

	resp, err := client.R().
		SetContext(ctx).
		SetHeader("Authorization", "Bearer "+accessToken).
		SetHeader("anthropic-version", "2023-06-01").
		SetHeader("Content-Type", "application/json").
		SetSuccessResult(&body).
		Get("https://api.anthropic.com/api/claude_cli/bootstrap")
	if err != nil {
		return nil, fmt.Errorf("bootstrap request failed: %w", err)
	}
	if !resp.IsSuccessState() {
		return nil, fmt.Errorf("bootstrap failed: status %d", resp.StatusCode)
	}

	return &service.ClaudeBootstrapInfo{
		AccountUUID:      body.AccountUUID,
		OrganizationUUID: body.OrganizationUUID,
		EmailAddress:     body.AccountEmail,
		SubscriptionType: body.SubscriptionType,
	}, nil
}

func createReqClient(proxyURL string) (*req.Client, error) {
	// 禁用 CookieJar，确保每次授权都是干净的会话
	client := req.C().
		SetTimeout(60 * time.Second).
		ImpersonateChrome().
		SetCookieJar(nil) // 禁用 CookieJar

	trimmed, _, err := proxyurl.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	if trimmed != "" {
		client.SetProxyURL(trimmed)
	}

	return instrumentReqClient(client), nil
}
