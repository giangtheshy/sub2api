package oauth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ClaudeAIOAuthFile is the credential bundle Claude Code persists on disk under
// the "claudeAiOauth" key. Operators can paste this file to import an already
// issued OAuth account instead of running the interactive authorization flow.
//
// This is an import of a credential the caller already holds — it mints nothing
// and contacts no authorization endpoint. It mirrors the shape written by the
// official client so a genuine Claude Code login can be replayed verbatim.
type ClaudeAIOAuthFile struct {
	AccessToken      string   `json:"accessToken"`
	RefreshToken     string   `json:"refreshToken"`
	ExpiresAt        int64    `json:"expiresAt"` // epoch milliseconds
	SubscriptionType string   `json:"subscriptionType"`
	Scopes           []string `json:"scopes"`
}

// ParsedOAuthCredentials is the normalized result of importing a credential file.
type ParsedOAuthCredentials struct {
	AccessToken      string
	RefreshToken     string
	ExpiresAt        int64 // epoch seconds (normalized from the file's milliseconds)
	SubscriptionType string
	Scope            string
}

// ParseClaudeOAuthCredentials parses a pasted credential blob into normalized
// OAuth credentials. It accepts either the wrapped form
// {"claudeAiOauth": {...}} written by Claude Code, or a bare {...} object with
// the same fields.
//
// It fails fast when the mandatory tokens are absent so the operator sees a
// clear error instead of a half-populated account.
func ParseClaudeOAuthCredentials(raw string) (*ParsedOAuthCredentials, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty credential input")
	}

	// The file wraps the bundle under "claudeAiOauth"; a bare bundle is also
	// accepted. Decode into a wrapper first, then fall back to the bare object.
	var wrapper struct {
		ClaudeAIOAuth *ClaudeAIOAuthFile `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal([]byte(trimmed), &wrapper); err != nil {
		return nil, fmt.Errorf("invalid credential JSON: %w", err)
	}

	bundle := wrapper.ClaudeAIOAuth
	if bundle == nil {
		var bare ClaudeAIOAuthFile
		if err := json.Unmarshal([]byte(trimmed), &bare); err != nil {
			return nil, fmt.Errorf("invalid credential JSON: %w", err)
		}
		bundle = &bare
	}

	accessToken := strings.TrimSpace(bundle.AccessToken)
	refreshToken := strings.TrimSpace(bundle.RefreshToken)

	if accessToken == "" {
		return nil, fmt.Errorf("accessToken is missing or empty")
	}
	if refreshToken == "" {
		return nil, fmt.Errorf("refreshToken is missing or empty")
	}

	// The file stores expiresAt in epoch milliseconds; the rest of the service
	// works in epoch seconds. Normalize here so callers never see the unit skew.
	expiresAt := normalizeExpiryToSeconds(bundle.ExpiresAt)

	return &ParsedOAuthCredentials{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		ExpiresAt:        expiresAt,
		SubscriptionType: strings.TrimSpace(bundle.SubscriptionType),
		Scope:            strings.Join(bundle.Scopes, " "),
	}, nil
}

// normalizeExpiryToSeconds converts the file's millisecond epoch to seconds.
// A zero or negative value means "unknown"; callers treat that as expired and
// refresh immediately. Values that already look like seconds (10-digit range)
// are passed through so a hand-edited file still works.
func normalizeExpiryToSeconds(expiresAtMillis int64) int64 {
	if expiresAtMillis <= 0 {
		return 0
	}
	// Anything past ~year 2286 in seconds (> 1e10) is really milliseconds.
	const millisThreshold = 1e12
	if expiresAtMillis >= millisThreshold {
		return expiresAtMillis / 1000
	}
	return expiresAtMillis
}

// IsExpired reports whether the imported access token is already past its expiry.
func (p *ParsedOAuthCredentials) IsExpired(now time.Time) bool {
	if p.ExpiresAt <= 0 {
		return true
	}
	return now.Unix() >= p.ExpiresAt
}
