package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/internal/testutil"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// [FORK-BAN-SCOPE] handler 层回归：转售商一把 Key 背后多个 X-User-Id，屏蔽只能落在
// 会话或 X-User-Id 上；终端用户永久封禁的响应必须与会话屏蔽可区分。

// Anthropic 原生链路：Claude Code 会话参与屏蔽标识——同会话被挡、新会话放行、
// 同 Key 其他终端用户放行、无标识请求放行。
func TestForkBanScope_NativeClaudeCodeSessionBlock(t *testing.T) {
	harness := newNativeCyberAllowlistHarness(t)
	apiKey := nativeCyberTestAPIKey(21, 1752)
	const s1 = "11111111-1111-4111-8111-111111111111"
	const s2 = "22222222-2222-4222-8222-222222222222"
	body := `{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`

	flagged := newNativeGatewayTestCtxWithHeaders(body, map[string]string{"X-User-Id": "u1", "X-Claude-Code-Session-Id": s1})
	meta := service.CyberSessionBlockMeta(apiKey, flagged, []byte(body))
	require.Equal(t, service.StickyIdentityKindXUserIDSession, meta.Kind)
	require.NoError(t, harness.blockStore.SetCyberSessionBlocked(context.Background(), "", []string{meta.Key}, time.Minute))

	legacyMetadataBody := `{"model":"claude-sonnet-4-6","metadata":{"user_id":"user_` + strings.Repeat("ab", 32) + `_account__session_` + s1 + `"},"messages":[]}`
	cases := []struct {
		name    string
		headers map[string]string
		body    string
		blocked bool
	}{
		{"same session header", map[string]string{"X-User-Id": "u1", "X-Claude-Code-Session-Id": s1}, body, true},
		{"same session via metadata.user_id", map[string]string{"X-User-Id": "u1"}, legacyMetadataBody, true},
		{"new session escapes", map[string]string{"X-User-Id": "u1", "X-Claude-Code-Session-Id": s2}, body, false},
		{"other end user same key", map[string]string{"X-User-Id": "u2", "X-Claude-Code-Session-Id": s1}, body, false},
		{"other end user no session", map[string]string{"X-User-Id": "u2"}, body, false},
		{"header-less request", nil, body, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newNativeGatewayTestCtxWithHeaders(tc.body, tc.headers)
			_, rejected := harness.handler.rejectIfCyberSessionBlockedNative(c, apiKey, []byte(tc.body), "claude-sonnet-4-6")
			require.Equal(t, tc.blocked, rejected)
			if tc.blocked {
				require.Equal(t, http.StatusForbidden, c.Writer.Status())
			}
		})
	}
}

// OpenAI/Codex 链路：真实写入计划（buildCyberSessionBlockWritePlan）与真实读取
// （findBlockedCyberSessionKey）往返——同 IP+UA、同 Key 的其他终端用户不受影响。
func TestForkBanScope_OpenAIWritePlanRoundTripIsolatesEndUsers(t *testing.T) {
	gatewayCache := testutil.NewRedisGatewayCache(t)
	settingRepo := &contentModerationHandlerSettingRepo{values: map[string]string{
		service.SettingKeyRiskControlEnabled:          "true",
		service.SettingKeyCyberSessionBlockEnabled:    "true",
		service.SettingKeyCyberSessionBlockTTLSeconds: "60",
	}}
	cfg := &config.Config{}
	gatewaySvc := service.NewOpenAIGatewayService(
		nil, nil, nil, nil, nil, nil, gatewayCache, cfg, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		service.NewSettingService(settingRepo, cfg), nil,
	)
	apiKey := &service.APIKey{ID: 31, UserID: 3100, User: &service.User{ID: 3100}}
	body := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"}]}`)
	newCtx := func(headers map[string]string) *gin.Context {
		c := newTestGinContext()
		c.Request = httptest.NewRequest(http.MethodPost, "/openai/v1/responses", strings.NewReader(string(body)))
		c.Request.RemoteAddr = "203.0.113.50:4000"
		c.Request.Header.Set("User-Agent", "reseller-proxy/1.0")
		for k, v := range headers {
			c.Request.Header.Set(k, v)
		}
		return c
	}

	for _, tc := range []struct {
		name    string
		flagged map[string]string
		other   map[string]string
	}{
		{"x_user_id only", map[string]string{"X-User-Id": "cust-a"}, map[string]string{"X-User-Id": "cust-b"}},
		{"constant reseller session", map[string]string{"X-User-Id": "cust-c", "session_id": "constant"}, map[string]string{"X-User-Id": "cust-d", "session_id": "constant"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flagged := newCtx(tc.flagged)
			plan := buildCyberSessionBlockWritePlan(apiKey, flagged, body)
			gatewaySvc.MarkCyberSessionBlockedWithMeta(context.Background(), plan.scopeKey, plan.keys, plan.meta)

			require.NotEmpty(t, findBlockedCyberSessionKey(context.Background(), gatewaySvc, apiKey, newCtx(tc.flagged), body))
			require.Empty(t, findBlockedCyberSessionKey(context.Background(), gatewaySvc, apiKey, newCtx(tc.other), body),
				"identical prompt from another end user on the same key/IP/UA must pass")
		})
	}
}

type forkEndUserBanStore struct {
	mu     sync.Mutex
	banned map[string]bool
}

func (s *forkEndUserBanStore) BanEndUser(_ context.Context, identity string, _ service.EndUserBanMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.banned == nil {
		s.banned = map[string]bool{}
	}
	s.banned[identity] = true
	return nil
}
func (s *forkEndUserBanStore) IsEndUserBanned(_ context.Context, identity string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.banned[identity], nil
}
func (s *forkEndUserBanStore) UnbanEndUser(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (s *forkEndUserBanStore) ListBannedEndUsers(_ context.Context) ([]service.EndUserBanMeta, error) {
	return nil, nil
}
func (s *forkEndUserBanStore) ClearBannedEndUsers(_ context.Context) (int64, error) {
	return 0, nil
}

// #7：终端用户永久封禁有独立文案与 code，所有格式都可与会话屏蔽区分；HTTP 403 +
// permission_error 保持不变。
func TestForkBanScope_EndUserBanHasDistinctMessageAndCode(t *testing.T) {
	require.NotEqual(t, cyberSessionBlockedClientMsg, endUserBannedClientMsg)
	require.NotEqual(t, cyberSessionBlockedErrorCode, endUserBannedErrorCode)
	require.Contains(t, endUserBannedClientMsg, "banned")
	require.NotContains(t, endUserBannedClientMsg, "please start a new session")

	settingRepo := &contentModerationHandlerSettingRepo{values: map[string]string{
		service.SettingKeyRiskControlEnabled:      "true",
		service.SettingKeyContentModerationConfig: `{"end_user_ban_enabled":true}`,
	}}
	banStore := &forkEndUserBanStore{}
	cmSvc := service.NewContentModerationService(settingRepo, &contentModerationHandlerTestRepo{}, nil, nil, nil, nil, nil, nil, banStore)
	apiKey := &service.APIKey{ID: 51, UserID: 5100, User: &service.User{ID: 5100}}
	headers := map[string]string{"X-User-Id": "banned-user"}
	_, identity := service.EndUserBanIdentity(apiKeyUserID(apiKey), newNativeGatewayTestCtxWithHeaders(`{}`, headers))
	require.NotEmpty(t, identity)
	require.NoError(t, banStore.BanEndUser(context.Background(), identity, service.EndUserBanMeta{}))

	assertBanBody := func(t *testing.T, raw []byte) {
		t.Helper()
		require.True(t, json.Valid(raw))
		require.Equal(t, "permission_error", gjson.GetBytes(raw, "error.type").String())
		require.Equal(t, endUserBannedErrorCode, gjson.GetBytes(raw, "error.code").String())
		require.Equal(t, endUserBannedClientMsg, gjson.GetBytes(raw, "error.message").String())
	}

	t.Run("native anthropic", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
		c.Request.Header.Set("X-User-Id", "banned-user")
		h := &GatewayHandler{contentModerationService: cmSvc}
		_, rejected := h.rejectIfEndUserBannedNative(c, apiKey, "claude-sonnet-4-6")
		require.True(t, rejected)
		require.Equal(t, http.StatusForbidden, rec.Code)
		assertBanBody(t, rec.Body.Bytes())
	})

	for _, format := range []cyberSessionBlockFormat{cyberBlockFormatResponses, cyberBlockFormatChat, cyberBlockFormatAnthropic} {
		t.Run("openai handler format", func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/openai/v1/responses", strings.NewReader(`{}`))
			c.Request.Header.Set("X-User-Id", "banned-user")
			h := &OpenAIGatewayHandler{contentModerationService: cmSvc}
			_, rejected := h.rejectIfEndUserBanned(c, apiKey, "gpt-5", format)
			require.True(t, rejected)
			require.Equal(t, http.StatusForbidden, rec.Code)
			assertBanBody(t, rec.Body.Bytes())
		})
	}

	t.Run("other end user on same key passes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
		c.Request.Header.Set("X-User-Id", "innocent-user")
		h := &GatewayHandler{contentModerationService: cmSvc}
		_, rejected := h.rejectIfEndUserBannedNative(c, apiKey, "claude-sonnet-4-6")
		require.False(t, rejected)
	})
}
