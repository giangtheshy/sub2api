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

	clientID     = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	redirectURI  = "http://localhost:54545/callback"
	scope        = "user:profile user:inference"
	authorizeURL = "https://claude.ai/cai/oauth/authorize"
	tokenURL     = "https://console.anthropic.com/v1/oauth/token"
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

func testStep2AuthorizeGET(client *req.Client, orgUUID, state, challenge string) (string, error) {
	fmt.Println("\n========== STEP 2: Authorize with GET (Browser Flow) ==========")

	// Build URL like browser does
	authURL := fmt.Sprintf("%s?code=true&client_id=%s&response_type=code&redirect_uri=%s&scope=%s&code_challenge=%s&code_challenge_method=S256&state=%s",
		authorizeURL,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scope),
		url.QueryEscape(challenge),
		url.QueryEscape(state),
	)

	fmt.Printf("Request URL: %s\n", authURL)

	resp, err := client.R().
		SetHeader("Cookie", "sessionKey="+sessionKey).
		SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36").
		SetHeader("Referer", "https://claude.ai/").
		Get(authURL)

	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Response headers: %v\n", resp.Header)

	// Check for redirect
	location := resp.Header.Get("Location")
	if location == "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Try lowercase
		location = resp.Header.Get("location")
	}

	if location != "" {
		fmt.Printf("Redirect to: %s\n", location)
		parsedURL, err := url.Parse(location)
		if err != nil {
			return "", fmt.Errorf("failed to parse redirect URL: %w", err)
		}

		authCode := parsedURL.Query().Get("code")
		if authCode == "" {
			return "", fmt.Errorf("no authorization code in redirect URL")
		}

		fmt.Printf("✅ Got authorization code: %s...\n", authCode[:20])
		return authCode, nil
	}

	// If no redirect, check body for error
	fmt.Printf("Response body: %s\n", resp.String())
	return "", fmt.Errorf("no redirect received, status %d", resp.StatusCode)
}

func testStep3ExchangeToken(client *req.Client, authCode, verifier string) error {
	fmt.Println("\n========== STEP 3: Exchange Token ==========")

	reqBody := map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          authCode,
		"client_id":     clientID,
		"redirect_uri":  redirectURI,
		"code_verifier": verifier,
	}

	printJSON("Request Body", reqBody)

	var tokenResp map[string]interface{}
	resp, err := client.R().
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetBody(reqBody).
		SetSuccessResult(&tokenResp).
		Post(tokenURL)

	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	if !resp.IsSuccessState() {
		return fmt.Errorf("❌ Failed with status %d, body: %s", resp.StatusCode, resp.String())
	}

	printJSON("✅ Token Response", tokenResp)
	return nil
}

func main() {
	client := req.C().
		SetTimeout(30 * time.Second).
		ImpersonateChrome().
		SetRedirectPolicy(req.NoRedirectPolicy()) // Don't follow redirects automatically

	fmt.Println("========================================")
	fmt.Println("Testing SessionKey OAuth Conversion")
	fmt.Println("Using Browser Flow (GET with query params)")
	fmt.Println("========================================")
	fmt.Printf("SessionKey: %s...\n", sessionKey[:30])

	// Step 1: Get organization
	org, err := testStep1GetOrgInfo(client)
	if err != nil {
		fmt.Printf("\n❌ STEP 1 FAILED: %v\n", err)
		os.Exit(1)
	}

	// Generate PKCE
	verifier, challenge, err := generatePKCE()
	if err != nil {
		fmt.Printf("\n❌ Failed to generate PKCE: %v\n", err)
		os.Exit(1)
	}

	state := fmt.Sprintf("state_%d", time.Now().Unix())

	// Step 2: Authorize using GET
	authCode, err := testStep2AuthorizeGET(client, org.UUID, state, challenge)
	if err != nil {
		fmt.Printf("\n❌ STEP 2 FAILED: %v\n", err)
		os.Exit(1)
	}

	// Step 3: Exchange token
	if err := testStep3ExchangeToken(client, authCode, verifier); err != nil {
		fmt.Printf("\n❌ STEP 3 FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n========================================")
	fmt.Println("✅ SUCCESS - SessionKey can be converted to OAuth token!")
	fmt.Println("========================================")
}
