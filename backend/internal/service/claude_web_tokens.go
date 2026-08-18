package service

import (
	"strings"
	"sync"

	"github.com/tiktoken-go/tokenizer"
)

// claude.ai's web API never reports input tokens, so the cookie path has to
// estimate them — and that estimate is what the user is actually charged.
//
// The previous estimator assumed ~4 characters per token, which is roughly true
// for English prose and badly wrong for the content that dominates Claude Code
// traffic: JSON, source code, tool schemas and base64. Anthropic does not
// publish its tokenizer, so exactness is unavailable either way; cl100k_base is
// a BPE vocabulary of the same family and tracks that content far more closely
// than a character count does.
var claudeTokenCodec = sync.OnceValues(func() (tokenizer.Codec, error) {
	return tokenizer.Get(tokenizer.Cl100kBase)
})

// estimateClaudeTokens counts the tokens in text as closely as we can without
// Anthropic's own tokenizer. It falls back to the character heuristic if the
// codec is unavailable, so a tokenizer failure degrades the estimate rather
// than failing the request.
func estimateClaudeTokens(text string) int {
	if strings.TrimSpace(text) == "" {
		return 0
	}

	codec, err := claudeTokenCodec()
	if err != nil || codec == nil {
		return estimateTokensForText(text)
	}

	ids, _, err := codec.Encode(text)
	if err != nil {
		return estimateTokensForText(text)
	}
	return len(ids)
}
