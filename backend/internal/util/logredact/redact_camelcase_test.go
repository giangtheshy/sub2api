package logredact

import (
	"strings"
	"testing"
)

// The Claude CLI credentials export speaks camelCase, because the file it
// produces is read by another program whose spelling we do not get to choose.
// normalizeKey only lowercases, so "accessToken" becomes "accesstoken" and
// misses the snake_case entries entirely — a live OAuth token would travel
// into logs in full. The redactor has to recognize both spellings of the same
// secret.
func TestRedactsCamelCaseTokenKeysInJSON(t *testing.T) {
	raw := []byte(`{"claudeAiOauth":{"accessToken":"sk-ant-oat01-secret",` +
		`"refreshToken":"sk-ant-ort01-secret","expiresAt":1755500000000}}`)

	out := RedactJSON(raw)

	if strings.Contains(out, "sk-ant-oat01-secret") {
		t.Errorf("accessToken survived redaction: %s", out)
	}
	if strings.Contains(out, "sk-ant-ort01-secret") {
		t.Errorf("refreshToken survived redaction: %s", out)
	}
	if !strings.Contains(out, "1755500000000") {
		t.Errorf("expiresAt was redacted; only secrets should be: %s", out)
	}
}

func TestRedactsCamelCaseTokenKeysInText(t *testing.T) {
	out := RedactText(`upstream said accessToken=sk-ant-oat01-secret and idToken=jwt-secret`)

	if strings.Contains(out, "sk-ant-oat01-secret") || strings.Contains(out, "jwt-secret") {
		t.Errorf("camelCase token values survived text redaction: %s", out)
	}
}

// Guard against over-redaction: the fix must key on the token fields, not on
// any word containing "token". Counters and flags carry no secret and become
// useless if masked.
func TestDoesNotRedactTokenAdjacentCounters(t *testing.T) {
	raw := []byte(`{"inputTokens":1234,"outputTokens":56,"tokenCount":78,"hasAccessToken":true}`)

	out := RedactJSON(raw)

	for _, want := range []string{"1234", "56", "78", "true"} {
		if !strings.Contains(out, want) {
			t.Errorf("value %s was redacted; it carries no secret: %s", want, out)
		}
	}
}
