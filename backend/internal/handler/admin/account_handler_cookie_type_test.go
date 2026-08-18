package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// bindCreateAccount runs a payload through the same binding+validation step the
// Create handler performs, so the binding tags are exercised exactly as in
// production.
func bindCreateAccount(t *testing.T, body string) error {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")

	var req CreateAccountRequest
	return c.ShouldBindJSON(&req)
}

func bindUpdateAccount(t *testing.T, body string) error {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/admin/accounts/1", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")

	var req UpdateAccountRequest
	return c.ShouldBindJSON(&req)
}

// The cookie import panel posts type "cookie". Binding tags are the first gate a
// payload hits, so an account type missing from the oneof list is rejected with
// an opaque validator error before any handler logic runs — the account can
// never be created no matter what the rest of the stack supports.
func TestCreateAccountRequestAcceptsEverySupportedType(t *testing.T) {
	for _, accountType := range []string{
		"oauth", "setup-token", "apikey", "upstream", "bedrock", "service_account", "cookie",
	} {
		t.Run(accountType, func(t *testing.T) {
			body := `{"name":"acc","platform":"anthropic","type":"` + accountType +
				`","credentials":{"cookie_jar":"sessionKey=x"}}`
			if err := bindCreateAccount(t, body); err != nil {
				t.Fatalf("type %q was rejected by request validation: %v", accountType, err)
			}
		})
	}
}

func TestUpdateAccountRequestAcceptsCookieType(t *testing.T) {
	if err := bindUpdateAccount(t, `{"type":"cookie"}`); err != nil {
		t.Fatalf("update with type cookie was rejected: %v", err)
	}
}

// Guard against the opposite failure: widening the oneof list must not turn it
// into a no-op that accepts anything.
func TestCreateAccountRequestRejectsUnknownType(t *testing.T) {
	err := bindCreateAccount(t, `{"name":"acc","platform":"anthropic","type":"not-a-type","credentials":{"a":"b"}}`)
	if err == nil {
		t.Fatal("an unknown account type was accepted; the oneof validation is no longer enforced")
	}
	if !strings.Contains(err.Error(), "oneof") {
		t.Errorf("expected a oneof validation error, got: %v", err)
	}
}
