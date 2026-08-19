package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/imroc/req/v3"
)

const (
	sessionKey = "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"

	// Clove flow endpoints
	cloveClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	cloveRedirectURI = "http://localhost:54545/callback"
	cloveScope       = "user:profile user:inference"
	cloveTokenURL    = "https://console.anthropic.com/v1/oauth/token"

	// Sub2api current endpoints
	sub2apiClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	sub2apiRedirectURI = "https://platform.claude.com/oauth/code/callback"
	sub2apiScope       = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	sub2apiTokenURL    = "https://platform.claude.com/v1/oauth/token"
)

type Organization struct {
	UUID         string   `json:"uuid"`
	Name         string   `json:"name"`
	RavenType    *string  `json:"raven_type"`
	Capabilities []string `json:"capabilities"`
}

func generatePKCE() (verifier, challenge string, err error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	verifier = base64URLEncode(bytes)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64URLEncode(hash[:])
	return verifier, challenge, nil
}

func base64URLEncode(data []byte) string {
	encoded := base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(encoded, "=")
}

func printJSON(title string, data interface{}) {
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	fmt.Printf("\n%s:\n%s\n", title, string(jsonBytes))
}

func testStep1GetOrgInfo(client *req.Client) (*Organization, error) {
	fmt.Println("\n========== STEP 1: Get Organization Info ==========")

	var orgs []Organization
	resp, err := client.R().
		SetHeader("Cookie", "sessionKey="+sessionKey).
		SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36").
		SetSuccessResult(&orgs).
		Get("https://claude.ai/api/organizations")

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	if !resp.IsSuccessState() {
		return nil, fmt.Errorf("failed with status %d, body: %s", resp.StatusCode, resp.String())
	}

	if len(orgs) == 0 {
		return nil, fmt.Errorf("no organizations found")
	}

	printJSON("Organizations", orgs)

	// Select first chat-capable org
	for _, org := range orgs {
		for _, cap := range org.Capabilities {
			if cap == "chat" {
				fmt.Printf("\n✅ Selected org: %s (UUID: %s)\n", org.Name, org.UUID)
				return &org, nil
			}
		}
	}

	return &orgs[0], nil
}

func testStep2AuthorizeClove(client *req.Client, orgUUID, verifier, challenge string) (string, error) {
	fmt.Println("\n========== STEP 2A: Authorize with Clove Flow ==========")

	authURL := fmt.Sprintf("https://claude.ai/v1/oauth/%s/authorize", orgUUID)
	reqBody := map[string]interface{}{
		"response_type":         "code",
		"client_id":             cloveClientID,
		"organization_uuid":     orgUUID,
		"redirect_uri":          cloveRedirectURI,
		"scope":                 cloveScope,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}

	printJSON("Request Body (Clove)", reqBody)

	var result struct {
		RedirectURI string `json:"redirect_uri"`
		Error       struct {
			Message string `json:"message"`
			Details struct {
				ErrorCode string `json:"error_code"`
			} `json:"details"`
		} `json:"error"`
	}

	resp, err := client.R().
		SetHeader("Cookie", "sessionKey="+sessionKey).
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetHeader("Origin", "https://claude.ai").
		SetBody(reqBody).
		SetSuccessResult(&result).
		Post(authURL)

	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Response: %s\n", resp.String())

	if !resp.IsSuccessState() {
		if result.Error.Details.ErrorCode != "" {
			return "", fmt.Errorf("❌ Error: %s (code: %s)", result.Error.Message, result.Error.Details.ErrorCode)
		}
		return "", fmt.Errorf("failed with status %d", resp.StatusCode)
	}

	if result.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri in response")
	}

	parsedURL, err := url.Parse(result.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse redirect_uri: %w", err)
	}

	authCode := parsedURL.Query().Get("code")
	if authCode == "" {
		return "", fmt.Errorf("no authorization code in redirect_uri")
	}

	fmt.Printf("✅ Got authorization code: %s...\n", authCode[:20])
	return authCode, nil
}

func testStep2AuthorizeSub2api(client *req.Client, orgUUID, verifier, challenge string) (string, error) {
	fmt.Println("\n========== STEP 2B: Authorize with Sub2api Flow ==========")

	authURL := fmt.Sprintf("https://claude.ai/v1/oauth/%s/authorize", orgUUID)
	reqBody := map[string]interface{}{
		"response_type":         "code",
		"client_id":             sub2apiClientID,
		"organization_uuid":     orgUUID,
		"redirect_uri":          sub2apiRedirectURI,
		"scope":                 sub2apiScope,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}

	printJSON("Request Body (Sub2api)", reqBody)

	var result struct {
		RedirectURI string `json:"redirect_uri"`
		Error       struct {
			Message string `json:"message"`
			Details struct {
				ErrorCode string `json:"error_code"`
			} `json:"details"`
		} `json:"error"`
	}

	resp, err := client.R().
		SetHeader("Cookie", "sessionKey="+sessionKey).
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetHeader("Origin", "https://claude.ai").
		SetBody(reqBody).
		SetSuccessResult(&result).
		Post(authURL)

	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Response: %s\n", resp.String())

	if !resp.IsSuccessState() {
		if result.Error.Details.ErrorCode != "" {
			return "", fmt.Errorf("❌ Error: %s (code: %s)", result.Error.Message, result.Error.Details.ErrorCode)
		}
		return "", fmt.Errorf("failed with status %d", resp.StatusCode)
	}

	if result.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri in response")
	}

	parsedURL, err := url.Parse(result.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse redirect_uri: %w", err)
	}

	authCode := parsedURL.Query().Get("code")
	if authCode == "" {
		return "", fmt.Errorf("no authorization code in redirect_uri")
	}

	fmt.Printf("✅ Got authorization code: %s...\n", authCode[:20])
	return authCode, nil
}

func testStep3ExchangeTokenClove(client *req.Client, authCode, verifier string) error {
	fmt.Println("\n========== STEP 3A: Exchange Token with Clove Flow ==========")

	reqBody := map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          authCode,
		"client_id":     cloveClientID,
		"redirect_uri":  cloveRedirectURI,
		"code_verifier": verifier,
	}

	printJSON("Request Body (Clove)", reqBody)

	var tokenResp map[string]interface{}
	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetBody(reqBody).
		SetSuccessResult(&tokenResp).
		Post(cloveTokenURL)

	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	if !resp.IsSuccessState() {
		return fmt.Errorf("❌ Failed with status %d, body: %s", resp.StatusCode, resp.String())
	}

	printJSON("✅ Token Response (Clove)", tokenResp)
	return nil
}

func testStep3ExchangeTokenSub2api(client *req.Client, authCode, verifier string) error {
	fmt.Println("\n========== STEP 3B: Exchange Token with Sub2api Flow ==========")

	reqBody := map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          authCode,
		"client_id":     sub2apiClientID,
		"redirect_uri":  sub2apiRedirectURI,
		"code_verifier": verifier,
	}

	printJSON("Request Body (Sub2api)", reqBody)

	var tokenResp map[string]interface{}
	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetBody(reqBody).
		SetSuccessResult(&tokenResp).
		Post(sub2apiTokenURL)

	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	if !resp.IsSuccessState() {
		return fmt.Errorf("❌ Failed with status %d, body: %s", resp.StatusCode, resp.String())
	}

	printJSON("✅ Token Response (Sub2api)", tokenResp)
	return nil
}

func main() {
	client := req.C().
		SetTimeout(30 * time.Second).
		ImpersonateChrome()

	fmt.Println("========================================")
	fmt.Println("Testing SessionKey OAuth Conversion")
	fmt.Println("========================================")
	fmt.Printf("SessionKey: %s...\n", sessionKey[:30])

	// Step 1: Get organization
	org, err := testStep1GetOrgInfo(client)
	if err != nil {
		fmt.Printf("\n❌ STEP 1 FAILED: %v\n", err)
		os.Exit(1)
	}

	// Generate PKCE for Clove flow
	verifierClove, challengeClove, err := generatePKCE()
	if err != nil {
		fmt.Printf("\n❌ Failed to generate PKCE: %v\n", err)
		os.Exit(1)
	}

	// Step 2A: Test Clove flow authorization
	authCodeClove, errClove := testStep2AuthorizeClove(client, org.UUID, verifierClove, challengeClove)

	// Generate PKCE for Sub2api flow
	verifierSub2api, challengeSub2api, err := generatePKCE()
	if err != nil {
		fmt.Printf("\n❌ Failed to generate PKCE: %v\n", err)
		os.Exit(1)
	}

	// Step 2B: Test Sub2api flow authorization
	authCodeSub2api, errSub2api := testStep2AuthorizeSub2api(client, org.UUID, verifierSub2api, challengeSub2api)

	// Step 3: Exchange tokens
	if errClove == nil {
		if err := testStep3ExchangeTokenClove(client, authCodeClove, verifierClove); err != nil {
			fmt.Printf("\n❌ STEP 3A (Clove) FAILED: %v\n", err)
		}
	} else {
		fmt.Printf("\n⚠️ Skipping STEP 3A (Clove) - Step 2A failed: %v\n", errClove)
	}

	if errSub2api == nil {
		if err := testStep3ExchangeTokenSub2api(client, authCodeSub2api, verifierSub2api); err != nil {
			fmt.Printf("\n❌ STEP 3B (Sub2api) FAILED: %v\n", err)
		}
	} else {
		fmt.Printf("\n⚠️ Skipping STEP 3B (Sub2api) - Step 2B failed: %v\n", errSub2api)
	}

	// Summary
	fmt.Println("\n========================================")
	fmt.Println("SUMMARY")
	fmt.Println("========================================")
	fmt.Printf("Clove Flow (localhost redirect, minimal scope):\n")
	if errClove != nil {
		fmt.Printf("  ❌ FAILED at Step 2: %v\n", errClove)
	} else {
		fmt.Printf("  ✅ SUCCESS\n")
	}

	fmt.Printf("\nSub2api Flow (platform redirect, full scope):\n")
	if errSub2api != nil {
		fmt.Printf("  ❌ FAILED at Step 2: %v\n", errSub2api)
	} else {
		fmt.Printf("  ✅ SUCCESS\n")
	}

	fmt.Println("\n========================================")
	fmt.Println("KEY DIFFERENCES FOUND:")
	fmt.Println("========================================")
	fmt.Println("1. Redirect URI:")
	fmt.Printf("   Clove:   %s\n", cloveRedirectURI)
	fmt.Printf("   Sub2api: %s\n", sub2apiRedirectURI)
	fmt.Println("\n2. Scope:")
	fmt.Printf("   Clove:   %s\n", cloveScope)
	fmt.Printf("   Sub2api: %s\n", sub2apiScope)
	fmt.Println("\n3. Token URL:")
	fmt.Printf("   Clove:   %s\n", cloveTokenURL)
	fmt.Printf("   Sub2api: %s\n", sub2apiTokenURL)
}
