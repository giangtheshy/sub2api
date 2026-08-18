package service

import (
	"strings"
	"testing"
)

// A tool schema of the size Claude Code actually sends. The transcript is what
// the input-token estimate is computed from, and CompletionPayload does send
// `tools` upstream, so omitting them under-counts every tool-using request.
const toolSchemaJSON = `[{"name":"Bash","description":"Run a shell command","input_schema":{"type":"object","properties":{"command":{"type":"string","description":"The command to run"},"timeout":{"type":"number"}},"required":["command"]}}]`

func promptWithTools(t *testing.T) *ClaudeWebPrompt {
	t.Helper()
	body := []byte(`{"model":"claude-sonnet-4-5","max_tokens":100,` +
		`"tools":` + toolSchemaJSON + `,` +
		`"messages":[{"role":"user","content":"list the files"}]}`)
	prompt, err := BuildClaudeWebPrompt(body)
	if err != nil {
		t.Fatalf("BuildClaudeWebPrompt: %v", err)
	}
	if len(prompt.Tools) == 0 {
		t.Fatal("fixture did not produce any tools")
	}
	return prompt
}

// The transcript drives billing. Tools are sent upstream but were excluded from
// it, so every tool-using turn was billed short by the size of the schema —
// 10-15K tokens per request for a Claude Code client.
func TestTranscriptIncludesToolSchemas(t *testing.T) {
	prompt := promptWithTools(t)

	transcript := prompt.Transcript()

	if !strings.Contains(transcript, "input_schema") || !strings.Contains(transcript, "Bash") {
		t.Errorf("Transcript() omits the tool schemas that CompletionPayload sends upstream:\n%s", transcript)
	}
	if !strings.Contains(transcript, "list the files") {
		t.Error("Transcript() lost the user turn")
	}
}

// The estimate must grow when tools are present; if it does not, the tools are
// still being billed as free.
func TestToolSchemasRaiseTheInputEstimate(t *testing.T) {
	withTools := promptWithTools(t)

	bare, err := BuildClaudeWebPrompt([]byte(`{"model":"claude-sonnet-4-5","max_tokens":100,"messages":[{"role":"user","content":"list the files"}]}`))
	if err != nil {
		t.Fatalf("BuildClaudeWebPrompt: %v", err)
	}

	withCount := estimateClaudeTokens(withTools.Transcript())
	bareCount := estimateClaudeTokens(bare.Transcript())

	if withCount <= bareCount {
		t.Errorf("estimate with tools = %d, without = %d; the schema is billed as free", withCount, bareCount)
	}
}

// The character heuristic it replaces assumes ~4 chars per token, which is well
// off for JSON and code — the dominant content in Claude Code traffic. A real
// tokenizer must disagree with it on such input, otherwise nothing changed.
func TestClaudeTokenEstimateUsesARealTokenizer(t *testing.T) {
	if got := estimateClaudeTokens(""); got != 0 {
		t.Errorf("estimateClaudeTokens(\"\") = %d, want 0", got)
	}

	dense := strings.Repeat(`{"key":"value","n":12345},`, 40)
	tokenized := estimateClaudeTokens(dense)
	heuristic := estimateTokensForText(dense)

	if tokenized <= 0 {
		t.Fatalf("estimateClaudeTokens returned %d for non-empty input", tokenized)
	}
	if tokenized == heuristic {
		t.Errorf("tokenizer agrees exactly with the chars/4 heuristic (%d); it is probably not being used", tokenized)
	}

	// Sanity: a real tokenizer stays within a sane band of the text length.
	if tokenized > len(dense) {
		t.Errorf("estimate %d exceeds the character count %d", tokenized, len(dense))
	}
}
