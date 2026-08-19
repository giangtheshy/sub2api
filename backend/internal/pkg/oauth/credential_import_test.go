package oauth

import (
	"testing"
	"time"
)

func TestParseClaudeOAuthCredentials(t *testing.T) {
	// Synthetic tokens — never a real credential. Shape matches Claude Code's file.
	const wrapped = `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-TESTaccess","refreshToken":"sk-ant-ort01-TESTrefresh","expiresAt":1787183506000,"subscriptionType":"max_20x"}}`

	tests := []struct {
		name    string
		raw     string
		wantErr bool
		check   func(t *testing.T, got *ParsedOAuthCredentials)
	}{
		{
			name: "wrapped claudeAiOauth file",
			raw:  wrapped,
			check: func(t *testing.T, got *ParsedOAuthCredentials) {
				if got.AccessToken != "sk-ant-oat01-TESTaccess" {
					t.Errorf("AccessToken = %q", got.AccessToken)
				}
				if got.RefreshToken != "sk-ant-ort01-TESTrefresh" {
					t.Errorf("RefreshToken = %q", got.RefreshToken)
				}
				if got.SubscriptionType != "max_20x" {
					t.Errorf("SubscriptionType = %q", got.SubscriptionType)
				}
				// 1787183506000 ms -> 1787183506 s
				if got.ExpiresAt != 1787183506 {
					t.Errorf("ExpiresAt = %d, want 1787183506", got.ExpiresAt)
				}
			},
		},
		{
			name: "bare bundle without wrapper",
			raw:  `{"accessToken":"a","refreshToken":"r","expiresAt":2000000000000}`,
			check: func(t *testing.T, got *ParsedOAuthCredentials) {
				if got.AccessToken != "a" || got.RefreshToken != "r" {
					t.Errorf("tokens = %q / %q", got.AccessToken, got.RefreshToken)
				}
				if got.ExpiresAt != 2000000000 {
					t.Errorf("ExpiresAt = %d", got.ExpiresAt)
				}
			},
		},
		{
			name: "scopes joined into scope string",
			raw:  `{"claudeAiOauth":{"accessToken":"a","refreshToken":"r","scopes":["user:profile","user:inference"]}}`,
			check: func(t *testing.T, got *ParsedOAuthCredentials) {
				if got.Scope != "user:profile user:inference" {
					t.Errorf("Scope = %q", got.Scope)
				}
			},
		},
		{
			name:    "missing access token",
			raw:     `{"claudeAiOauth":{"refreshToken":"r"}}`,
			wantErr: true,
		},
		{
			name:    "missing refresh token",
			raw:     `{"claudeAiOauth":{"accessToken":"a"}}`,
			wantErr: true,
		},
		{
			name:    "empty input",
			raw:     "   ",
			wantErr: true,
		},
		{
			name:    "garbage input",
			raw:     "not json at all",
			wantErr: true,
		},
		{
			name: "seconds-scale expiry passed through",
			raw:  `{"claudeAiOauth":{"accessToken":"a","refreshToken":"r","expiresAt":1900000000}}`,
			check: func(t *testing.T, got *ParsedOAuthCredentials) {
				if got.ExpiresAt != 1900000000 {
					t.Errorf("ExpiresAt = %d, want passthrough 1900000000", got.ExpiresAt)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseClaudeOAuthCredentials(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result=%+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("nil result without error")
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestParsedOAuthCredentials_IsExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name      string
		expiresAt int64
		want      bool
	}{
		{"future expiry", 1_700_000_500, false},
		{"past expiry", 1_699_999_500, true},
		{"exact now counts as expired", 1_700_000_000, true},
		{"zero expiry treated as expired", 0, true},
		{"negative expiry treated as expired", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ParsedOAuthCredentials{ExpiresAt: tt.expiresAt}
			if got := p.IsExpired(now); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}
