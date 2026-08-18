package service

import "testing"

// A fabricated jar. Never put a real claude.ai session in a test.
const fakeCookieJar = "sessionKey=sk-ant-sid02-testvalue; lastActiveOrg=test-org"

// cookie_jar is the credential the gateway replays to claude.ai, so it is
// exactly as sensitive as the session_key sitting beside it in the same map.
// SensitiveCredentialKeys drives response redaction, audit-log masking and
// update-merge preservation, so a key missing from it fails in all three.
func TestCookieJarIsSensitive(t *testing.T) {
	for _, key := range []string{"cookie_jar", "org_uuid", "session_key"} {
		if !IsSensitiveCredentialKey(key) {
			t.Errorf("IsSensitiveCredentialKey(%q) = false; the value would reach clients and audit logs", key)
		}
	}
}

// The admin UI edits accounts with a whole-object PUT built from the redacted
// GET response, so sensitive keys arrive absent rather than unchanged. Any key
// the merge does not preserve is destroyed on the first unrelated edit, leaving
// an account the scheduler still selects but that cannot authenticate.
func TestPartialUpdatePreservesCookieCredentials(t *testing.T) {
	existing := map[string]any{
		"cookie_jar":  fakeCookieJar,
		"session_key": "sk-ant-sid02-testvalue",
		"org_uuid":    "max-org",
	}
	incoming := map[string]any{"model_mapping": map[string]any{"a": "b"}}

	merged := MergePreservingSensitiveCreds(existing, incoming)

	for key, want := range map[string]string{
		"cookie_jar":  fakeCookieJar,
		"org_uuid":    "max-org",
		"session_key": "sk-ant-sid02-testvalue",
	} {
		got, ok := merged[key].(string)
		if !ok || got != want {
			t.Errorf("merged[%q] = %v, want %q; a partial update destroyed the account", key, merged[key], want)
		}
	}
	if merged["model_mapping"] == nil {
		t.Error("non-sensitive key was lost by the merge")
	}
}

// Preservation must not block a deliberate rotation, which is how an operator
// replaces an expired cookie.
func TestExplicitCookieRotationOverwrites(t *testing.T) {
	existing := map[string]any{"cookie_jar": "sessionKey=old"}
	incoming := map[string]any{"cookie_jar": "sessionKey=new"}

	if got := MergePreservingSensitiveCreds(existing, incoming)["cookie_jar"]; got != "sessionKey=new" {
		t.Errorf("cookie_jar = %v, want the incoming value; rotation would be impossible", got)
	}
}
