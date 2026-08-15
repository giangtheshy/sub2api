package service

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

// The claude.ai completion endpoint takes a single prompt plus attachments
// rather than a message list, so an Anthropic Messages request is split the way
// the browser would send it: the final user turn becomes the prompt, and any
// earlier turns are attached as a transcript file.
//
// Putting everything in the attachment (with an empty prompt) does not work:
// claude.ai treats attachment text as an untrusted document and the model
// refuses to follow instructions found there. Verified against the live API.
//
// rendering_mode "messages" makes claude.ai stream Anthropic-shaped SSE events
// back, which keeps the response side thin.
const (
	claudeWebHumanPrefix     = "Human: "
	claudeWebAssistantPrefix = "Assistant: "
	claudeWebRenderingMode   = "messages"
	claudeWebAttachmentName  = "conversation.txt"
	claudeWebAttachmentType  = "txt"

	// defaultClaudeWebMaxTokens mirrors the Messages API requirement that
	// max_tokens is present; claude.ai rejects a zero budget.
	defaultClaudeWebMaxTokens = 4096
)

// ClaudeWebImage is an inline image destined for the claude.ai upload endpoint.
type ClaudeWebImage struct {
	MediaType string
	Data      []byte
}

// Filename returns a stable upload filename derived from the media type.
func (img ClaudeWebImage) Filename(index int) string {
	ext := "png"
	if _, sub, ok := strings.Cut(img.MediaType, "/"); ok && sub != "" {
		ext = sub
	}
	return fmt.Sprintf("image_%d.%s", index, ext)
}

// ClaudeWebPrompt is an Anthropic Messages request flattened for claude.ai.
type ClaudeWebPrompt struct {
	// System is the system prompt, sent as part of the prompt text.
	System string
	// History is the transcript of every turn before the final user turn; it is
	// attached as a file. Empty for a single-turn request.
	History string
	// Latest is the final user turn, which becomes the claude.ai prompt.
	Latest          string
	Images          []ClaudeWebImage
	Tools           []any
	Model           string
	MaxTokens       int
	ThinkingEnabled bool
	// SkippedURLImages counts image blocks referencing a remote URL, which are
	// not fetched. Callers log this so a silently missing image is visible.
	SkippedURLImages int
}

// BuildClaudeWebPrompt flattens an Anthropic Messages request body.
func BuildClaudeWebPrompt(body []byte) (*ClaudeWebPrompt, error) {
	root := gjson.ParseBytes(body)

	out := &ClaudeWebPrompt{
		Model:     root.Get("model").String(),
		MaxTokens: int(root.Get("max_tokens").Int()),
	}
	if out.MaxTokens <= 0 {
		out.MaxTokens = defaultClaudeWebMaxTokens
	}

	switch thinking := root.Get("thinking.type").String(); thinking {
	case "enabled", "adaptive":
		out.ThinkingEnabled = true
	}

	if tools := root.Get("tools"); tools.IsArray() {
		for _, tool := range tools.Array() {
			out.Tools = append(out.Tools, tool.Value())
		}
	}

	messages := root.Get("messages")
	if !messages.IsArray() {
		return nil, fmt.Errorf("request has no messages array")
	}

	// Turns are accumulated as segments so that consecutive messages from the
	// same role merge under one role prefix while still being newline separated.
	var segments []string
	currentRole := ""
	// hasBody tracks whether any message actually contributed content; role
	// prefixes alone are not a request worth forwarding.
	hasBody := false

	messages.ForEach(func(_, msg gjson.Result) bool {
		role := msg.Get("role").String()
		if role != "assistant" {
			role = "user"
		}

		var rendered strings.Builder
		content := msg.Get("content")
		if content.Type == gjson.String {
			rendered.WriteString(content.String())
			rendered.WriteString("\n")
		} else if content.IsArray() {
			content.ForEach(func(_, block gjson.Result) bool {
				out.writeBlock(&rendered, block)
				return true
			})
		}
		text := strings.TrimRight(rendered.String(), "\n")
		if strings.TrimSpace(text) != "" {
			hasBody = true
		}

		if role != currentRole {
			prefix := claudeWebHumanPrefix
			if role == "assistant" {
				prefix = claudeWebAssistantPrefix
			}
			segments = append(segments, prefix+text)
			currentRole = role
			return true
		}

		// Same role as the previous message: extend that turn.
		if text != "" && len(segments) > 0 {
			last := len(segments) - 1
			if strings.HasSuffix(segments[last], ": ") {
				segments[last] += text
			} else {
				segments[last] += "\n" + text
			}
		}
		return true
	})

	out.System = flattenSystemPrompt(root.Get("system"))

	// The final turn is the live request and must travel in the prompt; earlier
	// turns are context and travel as an attachment.
	if n := len(segments); n > 0 && currentRole == "user" {
		out.Latest = strings.TrimPrefix(segments[n-1], claudeWebHumanPrefix)
		out.History = strings.Join(segments[:n-1], "\n\n")
	} else {
		out.History = strings.Join(segments, "\n\n")
	}

	if !hasBody && len(out.Images) == 0 {
		return nil, fmt.Errorf("request has no usable message content")
	}
	return out, nil
}

// writeBlock renders one content block into the transcript.
func (p *ClaudeWebPrompt) writeBlock(b *strings.Builder, block gjson.Result) {
	switch block.Get("type").String() {
	case "text":
		b.WriteString(block.Get("text").String())
		b.WriteString("\n")

	case "thinking":
		b.WriteString("<thinking>\n")
		b.WriteString(block.Get("thinking").String())
		b.WriteString("\n</thinking>\n")

	case "tool_use", "server_tool_use":
		p.writeToolUse(b, block)

	case "tool_result":
		p.writeToolResult(b, block)

	case "image":
		p.collectImage(block.Get("source"))
	}
}

// writeToolUse replays an assistant tool call as the tag form claude.ai's model
// was trained on, since the web endpoint takes a flat transcript.
func (p *ClaudeWebPrompt) writeToolUse(b *strings.Builder, block gjson.Result) {
	b.WriteString("<function_calls>\n<invoke name=\"")
	b.WriteString(block.Get("name").String())
	b.WriteString("\">\n")
	block.Get("input").ForEach(func(key, value gjson.Result) bool {
		b.WriteString("<parameter name=\"")
		b.WriteString(key.String())
		b.WriteString("\">")
		if value.Type == gjson.String {
			b.WriteString(value.String())
		} else {
			b.WriteString(value.Raw)
		}
		b.WriteString("</parameter>\n")
		return true
	})
	b.WriteString("</invoke>\n</function_calls>\n")
}

func (p *ClaudeWebPrompt) writeToolResult(b *strings.Builder, block gjson.Result) {
	content := block.Get("content")
	var text strings.Builder

	switch {
	case content.Type == gjson.String:
		text.WriteString(content.String())
	case content.IsArray():
		content.ForEach(func(_, inner gjson.Result) bool {
			switch inner.Get("type").String() {
			case "text":
				text.WriteString(inner.Get("text").String())
				text.WriteString("\n")
			case "image":
				if p.collectImage(inner.Get("source")) {
					text.WriteString("(image attached)\n")
				}
			}
			return true
		})
	}

	b.WriteString("<function_results>")
	b.WriteString(strings.TrimSuffix(text.String(), "\n"))
	b.WriteString("</function_results>\n")
}

// collectImage queues an inline image for upload. It reports whether an image
// was queued; remote URLs are counted and skipped rather than fetched, so the
// gateway never makes an outbound request on behalf of a client payload.
func (p *ClaudeWebPrompt) collectImage(source gjson.Result) bool {
	if !source.Exists() {
		return false
	}

	switch source.Get("type").String() {
	case "base64":
		data, err := base64.StdEncoding.DecodeString(source.Get("data").String())
		if err != nil || len(data) == 0 {
			return false
		}
		p.Images = append(p.Images, ClaudeWebImage{
			MediaType: source.Get("media_type").String(),
			Data:      data,
		})
		return true

	case "url":
		url := source.Get("url").String()
		if inline, ok := decodeDataURLImage(url); ok {
			p.Images = append(p.Images, inline)
			return true
		}
		p.SkippedURLImages++
		return false
	}
	return false
}

// decodeDataURLImage parses "data:image/png;base64,...." into raw bytes.
func decodeDataURLImage(url string) (ClaudeWebImage, bool) {
	if !strings.HasPrefix(url, "data:") {
		return ClaudeWebImage{}, false
	}
	meta, payload, ok := strings.Cut(strings.TrimPrefix(url, "data:"), ",")
	if !ok {
		return ClaudeWebImage{}, false
	}
	mediaType, encoding, _ := strings.Cut(meta, ";")
	if !strings.EqualFold(strings.TrimSpace(encoding), "base64") {
		return ClaudeWebImage{}, false
	}
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil || len(data) == 0 {
		return ClaudeWebImage{}, false
	}
	return ClaudeWebImage{MediaType: strings.TrimSpace(mediaType), Data: data}, true
}

// flattenSystemPrompt accepts both the string and the content-block form.
func flattenSystemPrompt(system gjson.Result) string {
	if !system.Exists() {
		return ""
	}
	if system.Type == gjson.String {
		return system.String()
	}
	if !system.IsArray() {
		return ""
	}
	parts := make([]string, 0, 2)
	system.ForEach(func(_, item gjson.Result) bool {
		if text := item.Get("text").String(); text != "" {
			parts = append(parts, text)
		}
		return true
	})
	return strings.Join(parts, "\n")
}

// PromptText is what goes into the claude.ai prompt field: the system prompt
// followed by the live user turn. Instructions must live here rather than in the
// attachment, because claude.ai treats attachments as untrusted documents.
func (p *ClaudeWebPrompt) PromptText() string {
	switch {
	case p.System != "" && p.Latest != "":
		return p.System + "\n\n" + p.Latest
	case p.Latest != "":
		return p.Latest
	case p.System != "":
		return p.System
	default:
		// An assistant-prefill request has no live user turn; ask claude.ai to
		// continue from the attached transcript.
		return "Continue the conversation in the attached transcript."
	}
}

// Transcript is the full conversation as text, used for token estimation.
func (p *ClaudeWebPrompt) Transcript() string {
	parts := make([]string, 0, 3)
	for _, part := range []string{p.System, p.History, p.Latest} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "\n\n")
}

// CompletionPayload builds the claude.ai completion request body.
// fileIDs are upload UUIDs returned by ClaudeWebClient.UploadFile.
func (p *ClaudeWebPrompt) CompletionPayload(model string, fileIDs []string) map[string]any {
	if fileIDs == nil {
		fileIDs = []string{}
	}
	tools := p.Tools
	if tools == nil {
		tools = []any{}
	}

	// Only earlier turns are attached; a single-turn request sends no attachment.
	attachments := []map[string]any{}
	if p.History != "" {
		attachments = append(attachments, map[string]any{
			"extracted_content": p.History,
			"file_name":         claudeWebAttachmentName,
			"file_type":         claudeWebAttachmentType,
			"file_size":         len(p.History),
		})
	}

	return map[string]any{
		"max_tokens_to_sample": p.MaxTokens,
		"attachments":          attachments,
		"files":                fileIDs,
		"model":                model,
		"rendering_mode":       claudeWebRenderingMode,
		"prompt":               p.PromptText(),
		"timezone":             "UTC",
		"tools":                tools,
	}
}
