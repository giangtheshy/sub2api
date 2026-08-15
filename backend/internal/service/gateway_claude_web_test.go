package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// relayFixture returns a real claude.ai completion stream captured from the live
// web API. It exercises the parts only live traffic reveals: deltas interleaved
// across block indices, claude.ai's thinking_summary_delta, and the non-standard
// message_limit event. See loadRelayFixture in the forward test for the reader.
func relayFixture(t *testing.T) string {
	t.Helper()
	return loadRelayFixture(t)
}

func newRelayContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	return c, rec
}

func TestRelayClaudeWebStreamAggregatesNonStreaming(t *testing.T) {
	svc := &GatewayService{}
	c, rec := newRelayContext()

	got, err := svc.relayClaudeWebStream(c, strings.NewReader(relayFixture(t)), false, time.Now())
	if err != nil {
		t.Fatalf("relayClaudeWebStream() error = %v", err)
	}

	if got.upstreamModel != "claude-opus-5" {
		t.Errorf("upstreamModel = %q", got.upstreamModel)
	}
	if got.stopReason != "end_turn" {
		t.Errorf("stopReason = %q", got.stopReason)
	}
	if got.firstTokenMs == nil {
		t.Error("firstTokenMs is nil; a delta arrived so it should be set")
	}
	if !strings.Contains(got.text.String(), "The uploaded file contains only this:") {
		t.Errorf("text = %q", got.text.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if body["role"] != "assistant" || body["type"] != "message" {
		t.Errorf("body = %#v", body)
	}
	content, ok := body["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("content = %#v", body["content"])
	}

	// Both a thinking block (index 0) and a text block (index 1) were streamed,
	// and their deltas arrived interleaved.
	types := make([]string, 0, len(content))
	for _, item := range content {
		block, _ := item.(map[string]any)
		types = append(types, block["type"].(string))
	}
	if len(types) != 2 || types[0] != "thinking" || types[1] != "text" {
		t.Errorf("block types = %v, want [thinking text]", types)
	}

	textBlock := content[1].(map[string]any)
	if !strings.Contains(textBlock["text"].(string), "PONG") {
		t.Errorf("text block = %q", textBlock["text"])
	}
}

func TestRelayClaudeWebStreamFiltersNonAnthropicEvents(t *testing.T) {
	svc := &GatewayService{}
	c, rec := newRelayContext()

	if _, err := svc.relayClaudeWebStream(c, strings.NewReader(relayFixture(t)), true, time.Now()); err != nil {
		t.Fatalf("relayClaudeWebStream() error = %v", err)
	}

	out := rec.Body.String()

	// message_limit is claude.ai-specific and would break a strict Messages
	// client, so it must not be relayed.
	if strings.Contains(out, "message_limit") {
		t.Errorf("relayed stream contains message_limit:\n%s", out)
	}
	for _, want := range []string{
		"event: message_start",
		"event: content_block_start",
		"event: content_block_delta",
		"event: content_block_stop",
		"event: message_delta",
		"event: message_stop",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("relayed stream missing %q", want)
		}
	}
	// Every relayed event must keep the "event:\ndata:\n\n" framing.
	if strings.Contains(out, "data: \n") {
		t.Error("relayed stream has an empty data line")
	}
}

func TestRelayClaudeWebStreamRoutesDeltasByIndex(t *testing.T) {
	// Interleaved deltas across two blocks: routing by "most recent block"
	// would append index 0's text onto index 1.
	stream := strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"AAA"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"BBB"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"CCC"}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	svc := &GatewayService{}
	c, rec := newRelayContext()

	if _, err := svc.relayClaudeWebStream(c, strings.NewReader(stream), false, time.Now()); err != nil {
		t.Fatalf("error = %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	content := body["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("content = %#v", content)
	}
	if got := content[0].(map[string]any)["text"]; got != "AAACCC" {
		t.Errorf("block 0 text = %q, want %q", got, "AAACCC")
	}
	if got := content[1].(map[string]any)["text"]; got != "BBB" {
		t.Errorf("block 1 text = %q, want %q", got, "BBB")
	}
}

func TestRelayClaudeWebStreamCollectsToolUse(t *testing.T) {
	stream := strings.Join([]string{
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"city\":"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"Hanoi\"}"}}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":42}}`,
		``,
	}, "\n")

	svc := &GatewayService{}
	c, rec := newRelayContext()

	got, err := svc.relayClaudeWebStream(c, strings.NewReader(stream), false, time.Now())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got.stopReason != "tool_use" {
		t.Errorf("stopReason = %q", got.stopReason)
	}
	if got.outputTokens != 42 {
		t.Errorf("outputTokens = %d, want the upstream number", got.outputTokens)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	block := body["content"].([]any)[0].(map[string]any)
	if block["type"] != "tool_use" || block["name"] != "get_weather" || block["id"] != "toolu_1" {
		t.Fatalf("block = %#v", block)
	}
	input, _ := block["input"].(map[string]any)
	if input["city"] != "Hanoi" {
		t.Errorf("input = %#v, want the reassembled JSON", input)
	}
}

func TestRelayClaudeWebStreamStreamsVerbatimToClient(t *testing.T) {
	stream := "event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}` + "\n\n"

	svc := &GatewayService{}
	c, rec := newRelayContext()

	got, err := svc.relayClaudeWebStream(c, strings.NewReader(stream), true, time.Now())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got.clientDisconnect {
		t.Error("clientDisconnect = true")
	}
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), `"text":"hi"`) {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestDetectClaudePlan(t *testing.T) {
	tests := []struct {
		caps []string
		want string
	}{
		{[]string{"chat", "claude_max"}, "max"},
		{[]string{"chat", "claude_pro"}, "pro"},
		{[]string{"chat", "raven"}, "team"},
		{[]string{"chat"}, "free"},
		{[]string{"api", "api_individual"}, ""},
		{nil, ""},
	}

	for _, tt := range tests {
		if got := DetectClaudePlan(tt.caps); got != tt.want {
			t.Errorf("DetectClaudePlan(%v) = %q, want %q", tt.caps, got, tt.want)
		}
	}
}

func TestSelectClaudeWebOrganization(t *testing.T) {
	// The API-only org is listed first on a real Max account; picking it yields
	// "Invalid authorization for organization" upstream.
	orgs := []ClaudeWebOrganization{
		{UUID: "api-org", Capabilities: []string{"api", "api_individual"}},
		{UUID: "max-org", Capabilities: []string{"chat", "claude_max"}},
	}

	got, ok := SelectClaudeWebOrganization(orgs)
	if !ok || got.UUID != "max-org" {
		t.Errorf("got %q, ok=%v, want max-org", got.UUID, ok)
	}

	if _, ok := SelectClaudeWebOrganization([]ClaudeWebOrganization{
		{UUID: "api-only", Capabilities: []string{"api"}},
	}); ok {
		t.Error("expected no selection when no org can chat")
	}
}

func TestSupportsExtendedThinking(t *testing.T) {
	tests := []struct {
		plan string
		want bool
	}{
		{"max", true},
		{"pro", true},
		{"team", true},
		{"free", false},
		{"", false},
	}

	for _, tt := range tests {
		account := &Account{Extra: map[string]any{ExtraKeyCookiePlan: tt.plan}}
		if got := account.SupportsExtendedThinking(); got != tt.want {
			t.Errorf("plan %q: SupportsExtendedThinking() = %v, want %v", tt.plan, got, tt.want)
		}
	}
}

func TestIsClaudeCookie(t *testing.T) {
	cookieAccount := &Account{Platform: PlatformAnthropic, Type: AccountTypeCookie}
	if !cookieAccount.IsClaudeCookie() {
		t.Error("IsClaudeCookie() = false for an anthropic cookie account")
	}
	oauthAccount := &Account{Platform: PlatformAnthropic, Type: AccountTypeOAuth}
	if oauthAccount.IsClaudeCookie() {
		t.Error("IsClaudeCookie() = true for an OAuth account")
	}
	otherPlatform := &Account{Platform: PlatformOpenAI, Type: AccountTypeCookie}
	if otherPlatform.IsClaudeCookie() {
		t.Error("IsClaudeCookie() = true for a non-anthropic platform")
	}
}
