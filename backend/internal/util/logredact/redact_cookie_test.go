package logredact

import (
	"strings"
	"testing"
)

// A fabricated session value; never put a real claude.ai cookie in a test.
const fakeSessionValue = "sk-ant-sid02-testvalue"

// Idempotency records persist the account-create response body, and this package
// is the only thing standing between that body and the database. It keeps its
// own key list, independent of service.SensitiveCredentialKeys, so the cookie
// keys have to be added here too.
func TestRedactsCookieCredentialsInJSON(t *testing.T) {
	raw := []byte(`{"credentials":{"cookie_jar":"sessionKey=` + fakeSessionValue +
		`","session_key":"` + fakeSessionValue + `","cookie":"opaque"}}`)

	out := RedactJSON(raw)

	if strings.Contains(out, fakeSessionValue) {
		t.Errorf("RedactJSON leaked the session value: %s", out)
	}
	for _, key := range []string{"cookie_jar", "session_key", "cookie"} {
		if !strings.Contains(out, `"`+key+`":"***"`) {
			t.Errorf("key %q was not masked: %s", key, out)
		}
	}
}

func TestRedactsCookieCredentialsInText(t *testing.T) {
	for _, input := range []string{
		"cookie_jar=sessionKey=" + fakeSessionValue + "&next=1",
		`cookie_jar: sessionKey=` + fakeSessionValue,
		`session_key = ` + fakeSessionValue,
	} {
		if out := RedactText(input); strings.Contains(out, fakeSessionValue) {
			t.Errorf("RedactText(%q) leaked the session value: %s", input, out)
		}
	}
}

// Guard against over-redaction: a key that merely starts with "cookie" carries
// no secret, and masking counters would make logs useless for debugging.
func TestDoesNotRedactCookieAdjacentCounters(t *testing.T) {
	out := RedactJSON([]byte(`{"cookie_count":27,"cookies_parsed":27}`))

	for _, want := range []string{`"cookie_count":27`, `"cookies_parsed":27`} {
		if !strings.Contains(out, want) {
			t.Errorf("over-redacted a non-secret field, expected %s in: %s", want, out)
		}
	}
}
