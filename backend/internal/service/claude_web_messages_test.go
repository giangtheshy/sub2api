package service

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildClaudeWebPromptFlattensTranscript(t *testing.T) {
	body := []byte(`{
		"model": "claude-sonnet-4-5",
		"max_tokens": 1024,
		"system": "You are terse.",
		"messages": [
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
			{"role": "user", "content": [{"type": "text", "text": "again"}]}
		]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("BuildClaudeWebPrompt() error = %v", err)
	}

	// Transcript() is system + attached history + the live turn. The live turn
	// carries no role prefix because it travels in the prompt, not the history.
	want := "You are terse.\n\nHuman: hello\n\nAssistant: hi\n\nagain"
	if got.Transcript() != want {
		t.Errorf("Transcript() =\n%q\nwant\n%q", got.Transcript(), want)
	}
	if got.History != "Human: hello\n\nAssistant: hi" {
		t.Errorf("History = %q", got.History)
	}
	if got.Latest != "again" {
		t.Errorf("Latest = %q", got.Latest)
	}
	if got.MaxTokens != 1024 {
		t.Errorf("MaxTokens = %d", got.MaxTokens)
	}
	if got.Model != "claude-sonnet-4-5" {
		t.Errorf("Model = %q", got.Model)
	}
	if got.ThinkingEnabled {
		t.Error("ThinkingEnabled = true, want false")
	}
}

func TestBuildClaudeWebPromptMergesConsecutiveSameRoleMessages(t *testing.T) {
	// Two user turns in a row must not emit a second "Human:" prefix.
	body := []byte(`{
		"max_tokens": 16,
		"messages": [
			{"role": "user", "content": "one"},
			{"role": "user", "content": "two"}
		]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	// Both turns merge into the single live user turn, newline separated;
	// concatenating them would fuse "one" and "two" into one word.
	if got.Latest != "one\ntwo" {
		t.Errorf("Latest = %q, want %q", got.Latest, "one\ntwo")
	}
	if got.History != "" {
		t.Errorf("History = %q, want empty", got.History)
	}
	if strings.Contains(got.Latest, claudeWebHumanPrefix) {
		t.Errorf("Latest = %q, want no role prefix", got.Latest)
	}
}

func TestBuildClaudeWebPromptSystemBlocks(t *testing.T) {
	body := []byte(`{
		"max_tokens": 16,
		"system": [{"type":"text","text":"line one"},{"type":"text","text":"line two"}],
		"messages": [{"role":"user","content":"go"}]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !strings.HasPrefix(got.Transcript(), "line one\nline two") {
		t.Errorf("Text = %q, want both system blocks joined", got.Transcript())
	}
}

func TestBuildClaudeWebPromptToolUseAndResult(t *testing.T) {
	body := []byte(`{
		"max_tokens": 16,
		"messages": [
			{"role": "user", "content": "weather?"},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "t1", "name": "get_weather", "input": {"city": "Hanoi", "days": 3}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "31C"}]}
			]}
		]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}

	for _, want := range []string{
		`<invoke name="get_weather">`,
		`<parameter name="city">Hanoi</parameter>`,
		`<parameter name="days">3</parameter>`,
		`<function_results>31C</function_results>`,
	} {
		if !strings.Contains(got.Transcript(), want) {
			t.Errorf("Text missing %q\ngot:\n%s", want, got.Transcript())
		}
	}
}

func TestBuildClaudeWebPromptThinkingBlock(t *testing.T) {
	body := []byte(`{
		"max_tokens": 16,
		"thinking": {"type": "enabled", "budget_tokens": 2048},
		"messages": [
			{"role": "assistant", "content": [{"type":"thinking","thinking":"pondering"}]},
			{"role": "user", "content": "go on"}
		]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !got.ThinkingEnabled {
		t.Error("ThinkingEnabled = false, want true")
	}
	if !strings.Contains(got.Transcript(), "<thinking>\npondering\n</thinking>") {
		t.Errorf("Text = %q", got.Transcript())
	}
}

func TestBuildClaudeWebPromptCollectsBase64Image(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("fake-png-bytes"))
	body := []byte(`{
		"max_tokens": 16,
		"messages": [{"role":"user","content":[
			{"type":"text","text":"look"},
			{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"` + payload + `"}}
		]}]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(got.Images) != 1 {
		t.Fatalf("Images = %d, want 1", len(got.Images))
	}
	if string(got.Images[0].Data) != "fake-png-bytes" {
		t.Errorf("image data = %q", got.Images[0].Data)
	}
	if name := got.Images[0].Filename(0); name != "image_0.jpeg" {
		t.Errorf("Filename() = %q", name)
	}
}

func TestBuildClaudeWebPromptDecodesDataURLImage(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("inline"))
	body := []byte(`{
		"max_tokens": 16,
		"messages": [{"role":"user","content":[
			{"type":"image","source":{"type":"url","url":"data:image/png;base64,` + payload + `"}}
		]}]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(got.Images) != 1 || got.SkippedURLImages != 0 {
		t.Fatalf("Images = %d, Skipped = %d", len(got.Images), got.SkippedURLImages)
	}
}

func TestBuildClaudeWebPromptCountsSkippedRemoteImages(t *testing.T) {
	// Remote URLs are never fetched; the count makes the omission visible.
	body := []byte(`{
		"max_tokens": 16,
		"messages": [{"role":"user","content":[
			{"type":"text","text":"see this"},
			{"type":"image","source":{"type":"url","url":"https://example.com/a.png"}}
		]}]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(got.Images) != 0 {
		t.Errorf("Images = %d, want 0", len(got.Images))
	}
	if got.SkippedURLImages != 1 {
		t.Errorf("SkippedURLImages = %d, want 1", got.SkippedURLImages)
	}
}

func TestBuildClaudeWebPromptDefaultsMaxTokens(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got.MaxTokens != defaultClaudeWebMaxTokens {
		t.Errorf("MaxTokens = %d, want %d", got.MaxTokens, defaultClaudeWebMaxTokens)
	}
}

func TestBuildClaudeWebPromptErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"no messages", `{"max_tokens":16}`},
		{"messages not an array", `{"max_tokens":16,"messages":{}}`},
		{"empty content", `{"max_tokens":16,"messages":[{"role":"user","content":""}]}`},
		{"blank content only", `{"max_tokens":16,"messages":[{"role":"user","content":"   "}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := BuildClaudeWebPrompt([]byte(tt.body)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestBuildClaudeWebPromptCarriesTools(t *testing.T) {
	body := []byte(`{
		"max_tokens": 16,
		"tools": [{"name":"get_weather","description":"d","input_schema":{"type":"object"}}],
		"messages": [{"role":"user","content":"hi"}]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(got.Tools) != 1 {
		t.Fatalf("Tools = %d, want 1", len(got.Tools))
	}
}

func TestBuildClaudeWebPromptSplitsPromptFromHistory(t *testing.T) {
	// claude.ai rejects instructions found in attachments, so the live turn must
	// land in the prompt and only earlier turns may be attached.
	body := []byte(`{
		"max_tokens": 64,
		"system": "Be terse.",
		"messages": [
			{"role": "user", "content": "earlier question"},
			{"role": "assistant", "content": "earlier answer"},
			{"role": "user", "content": "Reply with exactly: PONG"}
		]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}

	if got.Latest != "Reply with exactly: PONG" {
		t.Errorf("Latest = %q", got.Latest)
	}
	if got.System != "Be terse." {
		t.Errorf("System = %q", got.System)
	}
	if got.History != "Human: earlier question\n\nAssistant: earlier answer" {
		t.Errorf("History = %q", got.History)
	}
	if want := "Be terse.\n\nReply with exactly: PONG"; got.PromptText() != want {
		t.Errorf("PromptText() = %q, want %q", got.PromptText(), want)
	}
}

func TestBuildClaudeWebPromptSingleTurnHasNoHistory(t *testing.T) {
	got, err := BuildClaudeWebPrompt([]byte(`{"max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got.History != "" {
		t.Errorf("History = %q, want empty", got.History)
	}
	if got.PromptText() != "hi" {
		t.Errorf("PromptText() = %q", got.PromptText())
	}

	payload := got.CompletionPayload("m", nil)
	attachments, _ := payload["attachments"].([]map[string]any)
	if len(attachments) != 0 {
		t.Errorf("attachments = %#v, want none for a single turn", attachments)
	}
}

func TestBuildClaudeWebPromptAssistantPrefillKeepsEverythingAsHistory(t *testing.T) {
	// An assistant-prefill request has no live user turn.
	body := []byte(`{
		"max_tokens": 16,
		"messages": [
			{"role": "user", "content": "count to three"},
			{"role": "assistant", "content": "one,"}
		]
	}`)

	got, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if got.Latest != "" {
		t.Errorf("Latest = %q, want empty", got.Latest)
	}
	if !strings.Contains(got.History, "Assistant: one,") {
		t.Errorf("History = %q", got.History)
	}
	if got.PromptText() == "" {
		t.Error("PromptText() is empty; claude.ai needs a non-empty prompt")
	}
}

func TestCompletionPayload(t *testing.T) {
	prompt := &ClaudeWebPrompt{
		System:    "Be terse.",
		History:   "Human: old\n\nAssistant: older",
		Latest:    "hi",
		MaxTokens: 512,
	}

	payload := prompt.CompletionPayload("claude-sonnet-4-5", []string{"file-1"})

	if payload["rendering_mode"] != claudeWebRenderingMode {
		t.Errorf("rendering_mode = %v", payload["rendering_mode"])
	}
	if payload["max_tokens_to_sample"] != 512 {
		t.Errorf("max_tokens_to_sample = %v", payload["max_tokens_to_sample"])
	}
	if payload["model"] != "claude-sonnet-4-5" {
		t.Errorf("model = %v", payload["model"])
	}
	if payload["prompt"] != "Be terse.\n\nhi" {
		t.Errorf("prompt = %v", payload["prompt"])
	}
	attachments, ok := payload["attachments"].([]map[string]any)
	if !ok || len(attachments) != 1 {
		t.Fatalf("attachments = %#v", payload["attachments"])
	}
	if attachments[0]["extracted_content"] != prompt.History {
		t.Errorf("extracted_content = %v", attachments[0]["extracted_content"])
	}
	if attachments[0]["file_size"] != len(prompt.History) {
		t.Errorf("file_size = %v", attachments[0]["file_size"])
	}
	if files, _ := payload["files"].([]string); len(files) != 1 {
		t.Errorf("files = %v", payload["files"])
	}
	// Empty slices must serialise as [] rather than null.
	empty := (&ClaudeWebPrompt{Latest: "x", MaxTokens: 1}).CompletionPayload("m", nil)
	if files, _ := empty["files"].([]string); files == nil {
		t.Error("files = nil, want an empty slice")
	}
	if tools, _ := empty["tools"].([]any); tools == nil {
		t.Error("tools = nil, want an empty slice")
	}
}
