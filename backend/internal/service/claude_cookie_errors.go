package service

import (
	"fmt"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// Reason codes surfaced to the panel so the frontend can localise the message.
const (
	ReasonClaudeSessionStale     = "CLAUDE_SESSION_STALE"
	ReasonClaudeCookieInvalid    = "CLAUDE_COOKIE_INVALID"
	ReasonClaudeOrgUnavailable   = "CLAUDE_ORG_UNAVAILABLE"
	ReasonClaudeWebBlocked       = "CLAUDE_WEB_BLOCKED"
	ReasonClaudeWebOrgDisabled   = "CLAUDE_WEB_ORG_DISABLED"
	ReasonClaudeWebRateLimited   = "CLAUDE_WEB_RATE_LIMITED"
	ReasonClaudeWebToolsRejected = "CLAUDE_WEB_TOOLS_REJECTED"
	ReasonClaudeWebModelMissing  = "CLAUDE_WEB_MODEL_UNAVAILABLE"
)

// ErrClaudeSessionStale is returned when claude.ai accepts the cookie for normal
// API calls but refuses to mint an OAuth code because the sign-in is too old
// (403 permission_error / session_stale_relogin).
//
// This is a server-side freshness check on Anthropic's side: no additional
// cookie makes it pass. The operator has to sign in to claude.ai again and
// export the cookie right away.
var ErrClaudeSessionStale = infraerrors.BadRequest(
	ReasonClaudeSessionStale,
	"claude.ai session is too old to grant OAuth access. Sign in to claude.ai again, export the cookie immediately after, then retry.",
)

// ErrClaudeCookieInvalid is returned when claude.ai rejects the cookie itself.
var ErrClaudeCookieInvalid = infraerrors.BadRequest(
	ReasonClaudeCookieInvalid,
	"claude.ai rejected this cookie. Export a fresh cookie and retry.",
)

// ErrClaudeOrgUnavailable is returned when the selected organization cannot
// grant the requested authorization (for example an API-only organization).
var ErrClaudeOrgUnavailable = infraerrors.BadRequest(
	ReasonClaudeOrgUnavailable,
	"this claude.ai account has no chat-capable organization to authorize.",
)

// ErrClaudeWebCloudflareBlocked is returned when claude.ai answers with a
// redirect to a challenge page instead of the API response.
var ErrClaudeWebCloudflareBlocked = infraerrors.BadRequest(
	ReasonClaudeWebBlocked,
	"claude.ai returned a Cloudflare challenge. Try a different proxy for this account.",
)

// ErrClaudeWebOrgDisabled is returned when the organization has been disabled
// upstream (typically a banned account).
var ErrClaudeWebOrgDisabled = infraerrors.BadRequest(
	ReasonClaudeWebOrgDisabled,
	"this claude.ai organization has been disabled by Anthropic.",
)

// ErrClaudeWebModelUnavailable is returned when claude.ai refuses the requested
// model for this plan. claude.ai reports this as a 403, so it must be
// distinguished from an authentication failure.
var ErrClaudeWebModelUnavailable = infraerrors.BadRequest(
	ReasonClaudeWebModelMissing,
	"claude.ai does not offer the requested model on this account's plan.",
)

// ClaudeWebRateLimitedError carries the upstream reset time for a 429.
type ClaudeWebRateLimitedError struct {
	*infraerrors.ApplicationError
	ResetsAt *time.Time
}

// NewClaudeWebRateLimited builds a rate-limit error, including the reset time
// when claude.ai reported one.
func NewClaudeWebRateLimited(resetsAt *time.Time) error {
	message := "claude.ai rate limit reached for this account."
	if resetsAt != nil {
		message = fmt.Sprintf("claude.ai rate limit reached for this account, resets at %s.", resetsAt.Format(time.RFC3339))
	}
	return &ClaudeWebRateLimitedError{
		ApplicationError: infraerrors.TooManyRequests(ReasonClaudeWebRateLimited, message),
		ResetsAt:         resetsAt,
	}
}
