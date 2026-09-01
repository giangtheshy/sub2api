package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	return parseOneCredential([]byte(trimmed))
}

// ParseClaudeOAuthCredentialsMany parses a blob holding one or more credentials
// so an operator can import a whole batch of accounts in a single paste. It
// accepts, in addition to everything ParseClaudeOAuthCredentials takes:
//
//   - a JSON array of credentials (wrapped or bare)
//   - several objects one after another, whether newline-separated (JSONL) or
//     simply concatenated
//
// Duplicates are collapsed on the refresh token: the same account pasted twice
// must not become two competing accounts sharing one upstream identity.
//
// A malformed or incomplete entry fails the whole call and names its position.
// Skipping it silently would create fewer accounts than the operator pasted
// without saying which one went missing.
func ParseClaudeOAuthCredentialsMany(raw string) ([]*ParsedOAuthCredentials, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty credential input")
	}

	entries, err := splitCredentialEntries(trimmed)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no credential object found")
	}

	parsed := make([]*ParsedOAuthCredentials, 0, len(entries))
	seenRefreshTokens := make(map[string]struct{}, len(entries))
	for i, entry := range entries {
		credentials, err := parseOneCredential(entry)
		if err != nil {
			// Positions are 1-based and only reported when the blob held more than
			// one entry, so a single bad paste keeps the plain message.
			if len(entries) == 1 {
				return nil, err
			}
			return nil, fmt.Errorf("credential #%d: %w", i+1, err)
		}
		if _, duplicate := seenRefreshTokens[credentials.RefreshToken]; duplicate {
			continue
		}
		seenRefreshTokens[credentials.RefreshToken] = struct{}{}
		parsed = append(parsed, credentials)
	}

	return parsed, nil
}

// splitCredentialEntries breaks the blob into individual JSON values. A leading
// "[" is decoded as an array; otherwise the input is streamed so consecutive
// objects work with or without separators between them.
func splitCredentialEntries(trimmed string) ([]json.RawMessage, error) {
	if strings.HasPrefix(trimmed, "[") {
		var array []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &array); err != nil {
			return nil, fmt.Errorf("invalid credential JSON: %w", err)
		}
		return array, nil
	}

	decoder := json.NewDecoder(strings.NewReader(trimmed))
	entries := make([]json.RawMessage, 0, 4)
	for {
		var entry json.RawMessage
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("invalid credential JSON: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func parseOneCredential(entry []byte) (*ParsedOAuthCredentials, error) {
	// The file wraps the bundle under "claudeAiOauth"; a bare bundle is also
	// accepted. Decode into a wrapper first, then fall back to the bare object.
	var wrapper struct {
		ClaudeAIOAuth *ClaudeAIOAuthFile `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(entry, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid credential JSON: %w", err)
	}

	bundle := wrapper.ClaudeAIOAuth
	if bundle == nil {
		var bare ClaudeAIOAuthFile
		if err := json.Unmarshal(entry, &bare); err != nil {
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
