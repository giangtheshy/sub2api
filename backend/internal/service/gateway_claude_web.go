package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// forwardClaudeWebCookie serves a request from a claude.ai cookie account.
//
// Instead of calling api.anthropic.com with a bearer token, it drives the
// claude.ai web API the way the browser does. That path needs no OAuth grant, so
// it keeps working for sessions Anthropic considers too stale to authorize.
//
// claude.ai is asked for rendering_mode "messages", which makes it stream
// Anthropic-shaped SSE events; those are relayed to the client as-is.
func (s *GatewayService) forwardClaudeWebCookie(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	parsed *ParsedRequest,
	startTime time.Time,
) (*ForwardResult, error) {
	if s.claudeWebClient == nil {
		return nil, errors.New("claude web client not configured")
	}

	cookieJar := account.CookieJar()
	if cookieJar == "" {
		return nil, errors.New("cookie_jar not found in credentials")
	}
	orgUUID := account.ClaudeOrgUUID()
	if orgUUID == "" {
		return nil, errors.New("org_uuid not found in credentials")
	}

	proxyURL := ""
	if account.ProxyID != nil && account.Proxy != nil {
		proxyURL = account.Proxy.URL()
	}

	prompt, err := BuildClaudeWebPrompt(parsed.Body.Bytes())
	if err != nil {
		return nil, fmt.Errorf("build claude.ai web request: %w", err)
	}
	if prompt.SkippedURLImages > 0 {
		logger.LegacyPrintf("service.gateway",
			"[ClaudeWeb] Skipped %d remote image URL(s); only inline base64 images are uploaded (account: %s)",
			prompt.SkippedURLImages, account.Name)
	}

	requestModel := parsed.Model
	upstreamModel := account.GetMappedModel(requestModel)

	conv, err := s.claudeWebClient.CreateConversation(ctx, cookieJar, orgUUID, proxyURL)
	if err != nil {
		return nil, err
	}
	// Conversations are per request; clean up on a background context so a
	// cancelled client request still removes the conversation upstream.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if err := s.claudeWebClient.DeleteConversation(cleanupCtx, cookieJar, orgUUID, conv.UUID, proxyURL); err != nil {
			logger.LegacyPrintf("service.gateway", "[ClaudeWeb] Failed to delete conversation %s: %v", conv.UUID, err)
		}
	}()

	// Extended thinking is a conversation-level setting on claude.ai.
	wantPaprika := ""
	if prompt.ThinkingEnabled && account.SupportsExtendedThinking() {
		wantPaprika = PaprikaModeExtended
	}
	if wantPaprika != conv.PaprikaMode {
		if err := s.claudeWebClient.SetPaprikaMode(ctx, cookieJar, orgUUID, conv.UUID, wantPaprika, proxyURL); err != nil {
			// Thinking mode is a preference, not a precondition for answering.
			logger.LegacyPrintf("service.gateway", "[ClaudeWeb] Failed to set paprika_mode=%q: %v", wantPaprika, err)
		}
	}

	fileIDs, err := s.uploadClaudeWebImages(ctx, account, cookieJar, orgUUID, proxyURL, prompt)
	if err != nil {
		return nil, err
	}

	stream, usedModel, err := s.openClaudeWebStream(ctx, account, cookieJar, orgUUID, conv.UUID, proxyURL, prompt, upstreamModel, fileIDs)
	if err != nil {
		return nil, err
	}
	defer func() { _ = stream.Body.Close() }()

	if parsed.OnUpstreamAccepted != nil {
		parsed.OnUpstreamAccepted()
	}

	relayed, err := s.relayClaudeWebStream(c, stream.Body, parsed.Stream, startTime)
	if err != nil {
		return nil, err
	}

	// claude.ai's web API does not meter input tokens the way /v1/messages does,
	// so anything it does not report is estimated locally.
	usage := ClaudeUsage{
		InputTokens:  relayed.inputTokens,
		OutputTokens: relayed.outputTokens,
	}
	if usage.InputTokens == 0 {
		usage.InputTokens = estimateClaudeTokens(prompt.Transcript())
	}
	if usage.OutputTokens == 0 && relayed.text.Len() > 0 {
		usage.OutputTokens = estimateClaudeTokens(relayed.text.String())
	}

	result := &ForwardResult{
		RequestID:             stream.RequestID,
		Usage:                 usage,
		Model:                 requestModel,
		Stream:                parsed.Stream,
		Duration:              time.Since(startTime),
		FirstTokenMs:          relayed.firstTokenMs,
		ClientDisconnect:      relayed.clientDisconnect,
		UpstreamResponseModel: relayed.upstreamModel,
	}
	switch {
	case usedModel != "" && usedModel != requestModel:
		result.UpstreamModel = usedModel
	case usedModel == "" && relayed.upstreamModel != "" && relayed.upstreamModel != requestModel:
		// claude.ai chose the model itself, because the requested one is not on
		// this plan and openClaudeWebStream retried without the field. Leaving
		// UpstreamModel empty here made the substitution invisible: upstream_model
		// stayed NULL, so no report could attribute the request to what actually
		// served it, and billableModelWithFallback had no priced model to fall
		// back to when the requested name is unknown to the price table.
		result.UpstreamModel = relayed.upstreamModel
	}
	return result, nil
}

// uploadClaudeWebImages pushes inline images to claude.ai and returns their IDs.
func (s *GatewayService) uploadClaudeWebImages(
	ctx context.Context,
	account *Account,
	cookieJar, orgUUID, proxyURL string,
	prompt *ClaudeWebPrompt,
) ([]string, error) {
	if len(prompt.Images) == 0 {
		return nil, nil
	}

	fileIDs := make([]string, 0, len(prompt.Images))
	for i, img := range prompt.Images {
		fileID, err := s.claudeWebClient.UploadFile(ctx, cookieJar, orgUUID, img.Filename(i), img.MediaType, img.Data, proxyURL)
		if err != nil {
			return nil, fmt.Errorf("upload image %d to claude.ai: %w", i, err)
		}
		fileIDs = append(fileIDs, fileID)
	}
	logger.LegacyPrintf("service.gateway", "[ClaudeWeb] Uploaded %d image(s) (account: %s)", len(fileIDs), account.Name)
	return fileIDs, nil
}

// openClaudeWebStream starts the completion stream, retrying without an explicit
// model when claude.ai does not offer the requested one on this plan. Omitting
// the field makes claude.ai pick its own default, which is better than failing.
func (s *GatewayService) openClaudeWebStream(
	ctx context.Context,
	account *Account,
	cookieJar, orgUUID, convUUID, proxyURL string,
	prompt *ClaudeWebPrompt,
	model string,
	fileIDs []string,
) (*ClaudeWebStream, string, error) {
	payload := prompt.CompletionPayload(model, fileIDs)

	stream, err := s.claudeWebClient.SendMessage(ctx, cookieJar, orgUUID, convUUID, payload, proxyURL)
	if err == nil {
		return stream, model, nil
	}
	if !errors.Is(err, ErrClaudeWebModelUnavailable) || model == "" {
		return nil, "", err
	}

	logger.LegacyPrintf("service.gateway",
		"[ClaudeWeb] Model %q unavailable on this plan; retrying with the claude.ai default (account: %s)",
		model, account.Name)

	fallback := prompt.CompletionPayload("", fileIDs)
	delete(fallback, "model")

	stream, err = s.claudeWebClient.SendMessage(ctx, cookieJar, orgUUID, convUUID, fallback, proxyURL)
	if err != nil {
		return nil, "", err
	}
	return stream, "", nil
}

// claudeWebRelayResult captures what was observed while relaying the stream.
type claudeWebRelayResult struct {
	inputTokens      int
	outputTokens     int
	firstTokenMs     *int
	clientDisconnect bool
	upstreamModel    string
	text             strings.Builder
	blocks           map[int]*claudeWebBlock
	blockOrder       []int
	stopReason       string
	messageID        string
}

// claudeWebBlock accumulates one content block for the non-streaming response.
type claudeWebBlock struct {
	Type      string
	Text      strings.Builder
	Thinking  strings.Builder
	ToolID    string
	ToolName  string
	ToolInput strings.Builder
}

// anthropicSSEEvents is the set of event names a Messages API client expects.
// claude.ai also emits its own events (notably message_limit, which carries
// rate-limit windows); forwarding those verbatim would break strict clients, so
// they are consumed for telemetry and dropped from the relay.
var anthropicSSEEvents = map[string]struct{}{
	"message_start":       {},
	"message_delta":       {},
	"message_stop":        {},
	"content_block_start": {},
	"content_block_delta": {},
	"content_block_stop":  {},
	"ping":                {},
	"error":               {},
}

// maxClaudeWebSSELine bounds a single SSE line; tool inputs can be large.
const maxClaudeWebSSELine = 8 << 20

// relayClaudeWebStream reads the claude.ai SSE stream. Events are buffered one at
// a time so claude.ai-specific ones can be filtered before reaching the client.
// A streaming client receives the Anthropic events verbatim; otherwise they are
// folded into a single Messages response.
func (s *GatewayService) relayClaudeWebStream(
	c *gin.Context,
	body io.Reader,
	streamToClient bool,
	startTime time.Time,
) (*claudeWebRelayResult, error) {
	result := &claudeWebRelayResult{blocks: map[int]*claudeWebBlock{}}

	var flusher http.Flusher
	if streamToClient {
		if c == nil {
			return nil, errors.New("streaming requested without a response writer")
		}
		f, ok := c.Writer.(http.Flusher)
		if !ok {
			return nil, errors.New("streaming not supported")
		}
		flusher = f
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("X-Accel-Buffering", "no")
	}

	emit := func(eventName, data string) {
		if !streamToClient || result.clientDisconnect {
			return
		}
		if _, ok := anthropicSSEEvents[eventName]; !ok {
			return
		}
		if _, err := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", eventName, data); err != nil {
			// The client hung up. Keep draining upstream so the turn completes
			// and the recorded usage stays accurate.
			result.clientDisconnect = true
			return
		}
		flusher.Flush()
	}

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxClaudeWebSSELine)

	eventName := ""
	dataLines := make([]string, 0, 2)

	flushEvent := func() {
		if len(dataLines) == 0 {
			eventName = ""
			return
		}
		data := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]

		if name := result.observeEvent(data, startTime); eventName == "" {
			eventName = name
		}
		emit(eventName, data)
		eventName = ""
	}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")

		switch {
		case line == "":
			flushEvent()
		case strings.HasPrefix(line, ":"):
			// SSE comment / keep-alive.
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	flushEvent()

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read claude.ai stream: %w", err)
	}

	if !streamToClient && c != nil {
		c.JSON(http.StatusOK, result.messagesResponse())
	}
	return result, nil
}

// observeEvent folds one SSE payload into usage, timing and content state, and
// returns the event type it carried.
func (r *claudeWebRelayResult) observeEvent(payload string, startTime time.Time) string {
	if !strings.HasPrefix(payload, "{") {
		return ""
	}
	event := gjson.Parse(payload)
	eventType := event.Get("type").String()

	switch eventType {
	case "message_start":
		r.upstreamModel = event.Get("message.model").String()
		r.messageID = event.Get("message.id").String()
		// claude.ai usually omits usage here, but honour real numbers when present.
		if in := event.Get("message.usage.input_tokens"); in.Exists() {
			r.inputTokens = int(in.Int())
		}
		if out := event.Get("message.usage.output_tokens"); out.Exists() {
			r.outputTokens = int(out.Int())
		}

	case "content_block_start":
		index := int(event.Get("index").Int())
		block := &claudeWebBlock{
			Type:     event.Get("content_block.type").String(),
			ToolID:   event.Get("content_block.id").String(),
			ToolName: event.Get("content_block.name").String(),
		}
		if text := event.Get("content_block.text").String(); text != "" {
			block.Text.WriteString(text)
		}
		if _, seen := r.blocks[index]; !seen {
			r.blockOrder = append(r.blockOrder, index)
		}
		r.blocks[index] = block

	case "content_block_delta":
		r.markFirstToken(startTime)
		// claude.ai interleaves deltas across block indices, so route by index
		// rather than assuming the most recently opened block.
		r.applyDelta(int(event.Get("index").Int()), event.Get("delta"))

	case "message_delta":
		if stop := event.Get("delta.stop_reason").String(); stop != "" {
			r.stopReason = stop
		}
		if out := event.Get("usage.output_tokens"); out.Exists() {
			r.outputTokens = int(out.Int())
		}
	}

	return eventType
}

func (r *claudeWebRelayResult) applyDelta(index int, delta gjson.Result) {
	block, ok := r.blocks[index]
	if !ok {
		block = &claudeWebBlock{Type: "text"}
		r.blocks[index] = block
		r.blockOrder = append(r.blockOrder, index)
	}

	switch delta.Get("type").String() {
	case "text_delta":
		text := delta.Get("text").String()
		block.Text.WriteString(text)
		r.text.WriteString(text)
	case "thinking_delta":
		thinking := delta.Get("thinking").String()
		block.Thinking.WriteString(thinking)
		r.text.WriteString(thinking)
	case "thinking_summary_delta":
		// claude.ai streams a summary of its reasoning instead of raw thinking.
		summary := delta.Get("summary.summary").String()
		if summary != "" {
			block.Thinking.WriteString(summary)
			r.text.WriteString(summary)
		}
	case "input_json_delta":
		partial := delta.Get("partial_json").String()
		block.ToolInput.WriteString(partial)
		r.text.WriteString(partial)
	}
}

func (r *claudeWebRelayResult) markFirstToken(startTime time.Time) {
	if r.firstTokenMs != nil {
		return
	}
	ms := int(time.Since(startTime).Milliseconds())
	r.firstTokenMs = &ms
}

// messagesResponse folds the observed blocks into an Anthropic Messages response
// for a non-streaming client.
func (r *claudeWebRelayResult) messagesResponse() map[string]any {
	content := make([]map[string]any, 0, len(r.blockOrder))
	for _, index := range r.blockOrder {
		block := r.blocks[index]
		if block == nil {
			continue
		}
		switch block.Type {
		case "text":
			content = append(content, map[string]any{"type": "text", "text": block.Text.String()})
		case "thinking":
			if thinking := block.Thinking.String(); thinking != "" {
				content = append(content, map[string]any{"type": "thinking", "thinking": thinking})
			}
		case "tool_use":
			input := map[string]any{}
			if raw := block.ToolInput.String(); raw != "" {
				_ = json.Unmarshal([]byte(raw), &input)
			}
			content = append(content, map[string]any{
				"type":  "tool_use",
				"id":    block.ToolID,
				"name":  block.ToolName,
				"input": input,
			})
		}
	}

	stopReason := r.stopReason
	if stopReason == "" {
		stopReason = "end_turn"
	}
	messageID := r.messageID
	if messageID == "" {
		messageID = "msg_claude_web"
	}

	return map[string]any{
		"id":            messageID,
		"type":          "message",
		"role":          "assistant",
		"model":         r.upstreamModel,
		"content":       content,
		"stop_reason":   stopReason,
		"stop_sequence": nil,
		"usage": map[string]any{
			"input_tokens":  r.inputTokens,
			"output_tokens": r.outputTokens,
		},
	}
}
