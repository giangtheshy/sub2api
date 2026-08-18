package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
	"github.com/imroc/req/v3"
)

// claudeWebClient drives the claude.ai web API with a browser cookie.
//
// These are the same endpoints the claude.ai frontend calls, which is why a
// cookie that works in a browser works here without an OAuth grant.
type claudeWebClient struct {
	baseURL       string
	clientFactory func(proxyURL string) (*req.Client, error)
}

// NewClaudeWebClient creates the claude.ai web API client.
func NewClaudeWebClient() service.ClaudeWebClient {
	return &claudeWebClient{
		baseURL:       "https://claude.ai",
		clientFactory: createReqClient,
	}
}

const (
	// claudeWebStreamTimeout is generous: a long completion can stream for minutes.
	claudeWebStreamTimeout = 10 * time.Minute

	headerContentType = "Content-Type"
	headerAccept      = "Accept"
	mimeJSON          = "application/json"
	mimeEventStream   = "text/event-stream"
)

func (c *claudeWebClient) request(ctx context.Context, proxyURL string) (*req.Request, error) {
	client, err := c.clientFactory(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("create HTTP client: %w", err)
	}
	client.SetTimeout(claudeWebStreamTimeout)
	return client.R().SetContext(ctx), nil
}

// withBrowserHeaders applies the header set the claude.ai frontend sends.
// referer is switched to the conversation URL when one exists, matching the
// browser's own navigation state.
func withBrowserHeaders(r *req.Request, cookieJar, convUUID string) *req.Request {
	referer := "https://claude.ai/new"
	if convUUID != "" {
		referer = "https://claude.ai/chat/" + convUUID
	}
	return r.
		SetHeader("Cookie", cookieJar).
		SetHeader(headerAccept, mimeJSON).
		SetHeader("Accept-Language", "en-US,en;q=0.9").
		SetHeader("Cache-Control", "no-cache").
		SetHeader("Origin", "https://claude.ai").
		SetHeader("Referer", referer)
}

func (c *claudeWebClient) ListOrganizations(ctx context.Context, cookieJar, proxyURL string) ([]service.ClaudeWebOrganization, error) {
	r, err := c.request(ctx, proxyURL)
	if err != nil {
		return nil, err
	}

	var raw []struct {
		UUID         string   `json:"uuid"`
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
	}

	resp, err := withBrowserHeaders(r, cookieJar, "").
		SetSuccessResult(&raw).
		Get(c.baseURL + "/api/organizations")
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if !resp.IsSuccessState() {
		return nil, classifyClaudeWebError(resp.StatusCode, resp.Bytes())
	}

	orgs := make([]service.ClaudeWebOrganization, 0, len(raw))
	for _, o := range raw {
		orgs = append(orgs, service.ClaudeWebOrganization{
			UUID:         o.UUID,
			Name:         o.Name,
			Capabilities: o.Capabilities,
		})
	}
	return orgs, nil
}

// AccountEmail reads the signed-in identity from /api/bootstrap, the same
// endpoint the claude.ai frontend uses on page load.
func (c *claudeWebClient) AccountEmail(ctx context.Context, cookieJar, proxyURL string) (string, error) {
	r, err := c.request(ctx, proxyURL)
	if err != nil {
		return "", err
	}

	var result struct {
		Account struct {
			EmailAddress string `json:"email_address"`
		} `json:"account"`
	}

	resp, err := withBrowserHeaders(r, cookieJar, "").
		SetSuccessResult(&result).
		Get(c.baseURL + "/api/bootstrap")
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	if !resp.IsSuccessState() {
		return "", classifyClaudeWebError(resp.StatusCode, resp.Bytes())
	}
	return result.Account.EmailAddress, nil
}

func (c *claudeWebClient) CreateConversation(ctx context.Context, cookieJar, orgUUID, proxyURL string) (*service.ClaudeWebConversation, error) {
	r, err := c.request(ctx, proxyURL)
	if err != nil {
		return nil, err
	}

	convUUID := uuid.NewString()
	var result struct {
		UUID     string `json:"uuid"`
		Settings struct {
			PaprikaMode *string `json:"paprika_mode"`
		} `json:"settings"`
	}

	resp, err := withBrowserHeaders(r, cookieJar, "").
		SetHeader(headerContentType, mimeJSON).
		SetBody(map[string]any{"uuid": convUUID, "name": ""}).
		SetSuccessResult(&result).
		Post(fmt.Sprintf("%s/api/organizations/%s/chat_conversations", c.baseURL, orgUUID))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if !resp.IsSuccessState() {
		return nil, classifyClaudeWebError(resp.StatusCode, resp.Bytes())
	}
	if result.UUID == "" {
		result.UUID = convUUID
	}

	conv := &service.ClaudeWebConversation{UUID: result.UUID}
	if result.Settings.PaprikaMode != nil {
		conv.PaprikaMode = *result.Settings.PaprikaMode
	}
	logger.LegacyPrintf("repository.claude_web", "[ClaudeWeb] Created conversation %s", conv.UUID)
	return conv, nil
}

func (c *claudeWebClient) SetPaprikaMode(ctx context.Context, cookieJar, orgUUID, convUUID, mode, proxyURL string) error {
	r, err := c.request(ctx, proxyURL)
	if err != nil {
		return err
	}

	// A nil paprika_mode is meaningful: it turns extended thinking back off.
	var modeValue any
	if mode != "" {
		modeValue = mode
	}

	resp, err := withBrowserHeaders(r, cookieJar, convUUID).
		SetHeader(headerContentType, mimeJSON).
		SetBody(map[string]any{"settings": map[string]any{"paprika_mode": modeValue}}).
		Put(fmt.Sprintf("%s/api/organizations/%s/chat_conversations/%s", c.baseURL, orgUUID, convUUID))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if !resp.IsSuccessState() {
		return classifyClaudeWebError(resp.StatusCode, resp.Bytes())
	}
	return nil
}

func (c *claudeWebClient) UploadFile(ctx context.Context, cookieJar, orgUUID, filename, contentType string, data []byte, proxyURL string) (string, error) {
	r, err := c.request(ctx, proxyURL)
	if err != nil {
		return "", err
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, filename))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	header.Set("Content-Type", contentType)
	part, err := writer.CreatePart(header)
	if err != nil {
		return "", fmt.Errorf("build multipart body: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return "", fmt.Errorf("write multipart body: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("close multipart body: %w", err)
	}

	var result struct {
		FileUUID string `json:"file_uuid"`
	}

	resp, err := withBrowserHeaders(r, cookieJar, "").
		SetHeader(headerContentType, writer.FormDataContentType()).
		SetBody(body.Bytes()).
		SetSuccessResult(&result).
		Post(fmt.Sprintf("%s/api/%s/upload", c.baseURL, orgUUID))
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	if !resp.IsSuccessState() {
		return "", classifyClaudeWebError(resp.StatusCode, resp.Bytes())
	}
	if result.FileUUID == "" {
		return "", fmt.Errorf("upload succeeded but returned no file_uuid")
	}
	return result.FileUUID, nil
}

func (c *claudeWebClient) SendMessage(ctx context.Context, cookieJar, orgUUID, convUUID string, payload map[string]any, proxyURL string) (*service.ClaudeWebStream, error) {
	r, err := c.request(ctx, proxyURL)
	if err != nil {
		return nil, err
	}

	resp, err := withBrowserHeaders(r, cookieJar, convUUID).
		SetHeader(headerAccept, mimeEventStream).
		SetHeader(headerContentType, mimeJSON).
		SetBody(payload).
		DisableAutoReadResponse().
		Post(fmt.Sprintf("%s/api/organizations/%s/chat_conversations/%s/completion", c.baseURL, orgUUID, convUUID))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if !resp.IsSuccessState() {
		// The body was not auto-read; pull it so the error carries upstream detail.
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if readErr != nil {
			raw = nil
		}
		return nil, classifyClaudeWebError(resp.StatusCode, raw)
	}

	return &service.ClaudeWebStream{
		Body:      resp.Body,
		RequestID: resp.Header.Get("x-request-id"),
	}, nil
}

func (c *claudeWebClient) SendToolResult(ctx context.Context, cookieJar, orgUUID, convUUID string, payload map[string]any, proxyURL string) error {
	r, err := c.request(ctx, proxyURL)
	if err != nil {
		return err
	}

	resp, err := withBrowserHeaders(r, cookieJar, convUUID).
		SetHeader(headerContentType, mimeJSON).
		SetBody(payload).
		Post(fmt.Sprintf("%s/api/organizations/%s/chat_conversations/%s/tool_result", c.baseURL, orgUUID, convUUID))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if !resp.IsSuccessState() {
		return classifyClaudeWebError(resp.StatusCode, resp.Bytes())
	}
	return nil
}

func (c *claudeWebClient) DeleteConversation(ctx context.Context, cookieJar, orgUUID, convUUID, proxyURL string) error {
	if convUUID == "" {
		return nil
	}
	r, err := c.request(ctx, proxyURL)
	if err != nil {
		return err
	}

	resp, err := withBrowserHeaders(r, cookieJar, convUUID).
		Delete(fmt.Sprintf("%s/api/organizations/%s/chat_conversations/%s", c.baseURL, orgUUID, convUUID))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if !resp.IsSuccessState() {
		return classifyClaudeWebError(resp.StatusCode, resp.Bytes())
	}
	return nil
}

// classifyClaudeWebError maps a claude.ai web API failure onto a typed error.
func classifyClaudeWebError(statusCode int, body []byte) error {
	var parsed struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
			Details struct {
				ErrorCode string `json:"error_code"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	message := parsed.Error.Message

	switch {
	case statusCode == http.StatusFound || statusCode == http.StatusMovedPermanently:
		// claude.ai redirects to a challenge page instead of answering.
		return service.ErrClaudeWebCloudflareBlocked

	// A 403 is not necessarily an auth problem: claude.ai also uses it to say
	// the requested model is not on this plan, so match on the error code first.
	case parsed.Error.Details.ErrorCode == "model_not_available":
		return service.ErrClaudeWebModelUnavailable
	case statusCode == http.StatusUnauthorized,
		statusCode == http.StatusForbidden && strings.Contains(message, "Invalid authorization"):
		return service.ErrClaudeCookieInvalid

	case statusCode == http.StatusBadRequest && strings.Contains(message, "organization has been disabled"):
		return service.ErrClaudeWebOrgDisabled
	case statusCode == http.StatusTooManyRequests:
		return service.NewClaudeWebRateLimited(parseClaudeWebResetsAt(message))
	}

	if message == "" {
		message = truncateForError(string(body))
	}
	return fmt.Errorf("claude.ai web API error: status %d, body: %s", statusCode, message)
}

// parseClaudeWebResetsAt extracts the rate-limit reset time. claude.ai nests a
// JSON document inside error.message for 429s.
func parseClaudeWebResetsAt(message string) *time.Time {
	var payload struct {
		ResetsAt int64 `json:"resetsAt"`
	}
	if err := json.Unmarshal([]byte(message), &payload); err != nil || payload.ResetsAt <= 0 {
		return nil
	}
	t := time.Unix(payload.ResetsAt, 0).UTC()
	return &t
}

func truncateForError(s string) string {
	const limit = 300
	s = strings.TrimSpace(s)
	if len(s) > limit {
		return s[:limit] + "..."
	}
	return s
}
