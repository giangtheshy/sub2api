package admin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// The cookie-validate response is consumed by the create form, which needs the
// credential exactly once. Echoing it again in the info block multiplies the
// places a live claude.ai session comes to rest: browser devtools history, any
// reverse-proxy response log, and any client-side error reporter.
func TestCookieValidateResponseCarriesCredentialOnce(t *testing.T) {
	const fakeSession = "sk-ant-sid02-testvalue"

	info := &service.ClaudeCookieAccountInfo{
		CookieJar:    "sessionKey=" + fakeSession,
		SessionKey:   fakeSession,
		OrgUUID:      "max-org",
		OrgName:      "Personal",
		Plan:         "max",
		Capabilities: []string{"chat", "claude_max"},
		CookieCount:  27,
	}

	// The info block is descriptive metadata for the panel to display. It has no
	// reason to restate the credential that `credentials` already carries.
	encodedInfo, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal info: %v", err)
	}
	if strings.Contains(string(encodedInfo), fakeSession) {
		t.Errorf("the info block restates the credential: %s", encodedInfo)
	}

	// The metadata the panel renders must survive the change.
	for _, want := range []string{"max-org", "Personal", "max", "claude_max"} {
		if !strings.Contains(string(encodedInfo), want) {
			t.Errorf("info lost the %q metadata the create form displays: %s", want, encodedInfo)
		}
	}

	// credentials is what the create request posts, so it must still carry both
	// keys — this is the one place the value legitimately appears.
	encodedCreds, err := json.Marshal(info.Credentials())
	if err != nil {
		t.Fatalf("marshal credentials: %v", err)
	}
	for _, want := range []string{"cookie_jar", "session_key", "org_uuid"} {
		if !strings.Contains(string(encodedCreds), want) {
			t.Errorf("credentials lost %q; the account could not be created: %s", want, encodedCreds)
		}
	}
}
