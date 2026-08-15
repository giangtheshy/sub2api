package service

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// testClaudeCookieAccountConnection probes a claude.ai cookie account.
//
// A cookie account has no bearer token, so the probe drives the same claude.ai
// web endpoints the gateway uses: resolve the organization, then run one short
// completion in a throwaway conversation.
func (s *AccountTestService) testClaudeCookieAccountConnection(
	c *gin.Context,
	ctx context.Context,
	account *Account,
	testModelID string,
) error {
	if s.claudeWebClient == nil {
		return s.sendErrorAndEnd(c, "claude.ai web client not configured")
	}

	cookieJar := account.CookieJar()
	if cookieJar == "" {
		return s.sendErrorAndEnd(c, "No cookie stored for this account")
	}

	proxyURL := ""
	if account.ProxyID != nil && account.Proxy != nil {
		proxyURL = account.Proxy.URL()
	}

	s.sendEvent(c, TestEvent{Type: "test_start", Model: testModelID})

	// Step 1: the cookie must still authenticate.
	orgs, err := s.claudeWebClient.ListOrganizations(ctx, cookieJar, proxyURL)
	if err != nil {
		return s.sendErrorAndEnd(c, fmt.Sprintf("claude.ai rejected the cookie: %s", err.Error()))
	}
	orgUUID := account.ClaudeOrgUUID()
	if orgUUID == "" {
		org, ok := SelectClaudeWebOrganization(orgs)
		if !ok {
			return s.sendErrorAndEnd(c, "No chat-capable claude.ai organization for this cookie")
		}
		orgUUID = org.UUID
	}

	// Step 2: one real completion, in a conversation that is removed afterwards.
	conv, err := s.claudeWebClient.CreateConversation(ctx, cookieJar, orgUUID, proxyURL)
	if err != nil {
		return s.sendErrorAndEnd(c, fmt.Sprintf("Failed to create a claude.ai conversation: %s", err.Error()))
	}
	defer func() {
		if err := s.claudeWebClient.DeleteConversation(ctx, cookieJar, orgUUID, conv.UUID, proxyURL); err != nil {
			logger.LegacyPrintf("service.account_test",
				"[ClaudeWeb] Failed to delete probe conversation %s: %v", conv.UUID, err)
		}
	}()

	prompt := &ClaudeWebPrompt{
		Latest:    "Reply with exactly: OK",
		MaxTokens: 256,
	}
	payload := prompt.CompletionPayload(testModelID, nil)

	stream, err := s.claudeWebClient.SendMessage(ctx, cookieJar, orgUUID, conv.UUID, payload, proxyURL)
	if err != nil {
		// The requested model may simply not be on this plan; retry with the
		// claude.ai default before calling the account unhealthy.
		fallback := prompt.CompletionPayload("", nil)
		delete(fallback, "model")
		stream, err = s.claudeWebClient.SendMessage(ctx, cookieJar, orgUUID, conv.UUID, fallback, proxyURL)
		if err != nil {
			return s.sendErrorAndEnd(c, fmt.Sprintf("claude.ai refused the completion: %s", err.Error()))
		}
	}
	defer func() { _ = stream.Body.Close() }()

	var text strings.Builder
	scanner := bufio.NewScanner(stream.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxClaudeWebSSELine)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		event := gjson.Parse(strings.TrimSpace(rest))
		if event.Get("delta.type").String() != "text_delta" {
			continue
		}
		chunk := event.Get("delta.text").String()
		if chunk == "" {
			continue
		}
		text.WriteString(chunk)
		s.sendEvent(c, TestEvent{Type: "content", Text: chunk})
	}
	if err := scanner.Err(); err != nil {
		return s.sendErrorAndEnd(c, fmt.Sprintf("Failed to read the claude.ai stream: %s", err.Error()))
	}

	if strings.TrimSpace(text.String()) == "" {
		return s.sendErrorAndEnd(c, "claude.ai returned no content for the probe")
	}

	s.sendEvent(c, TestEvent{Type: "test_complete", Success: true})
	return nil
}
