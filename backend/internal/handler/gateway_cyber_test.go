package handler

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/internal/testutil"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func newNativeGatewayTestCtx(body string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/messages", strings.NewReader(body))
	return c
}

// 无标记 → 不记录、不置守卫位。
func TestRecordAnthropicRefusalIfMarked_NoMark(t *testing.T) {
	c := newNativeGatewayTestCtx(`{}`)
	h := &GatewayHandler{}

	require.NotPanics(t, func() {
		h.recordAnthropicRefusalIfMarked(c, nil, nil, "claude-sonnet-4-6", service.CyberBlockMeta{}, "")
	})
	require.False(t, c.GetBool(anthropicRefusalRecordedKey),
		"guard must stay false when there is no hard-signal mark")
}

// 有标记 → 置守卫位；重复调用幂等；nil 依赖不 panic（failover 重试会多次经过）。
func TestRecordAnthropicRefusalIfMarked_WithMarkIsIdempotent(t *testing.T) {
	c := newNativeGatewayTestCtx(`{}`)
	service.MarkAnthropicRefusal(c, service.AnthropicRefusalMark{
		Signal:         service.AnthropicRefusalSignalRefusal,
		UpstreamStatus: 200,
	})
	h := &GatewayHandler{} // nil services

	blockMeta := service.CyberBlockMeta{Key: "deadbeef", Kind: service.StickyIdentityKindXUserID, Masked: "deadbe"}
	require.NotPanics(t, func() {
		h.recordAnthropicRefusalIfMarked(c, nil, nil, "claude-sonnet-4-6", blockMeta, "")
	})
	require.True(t, c.GetBool(anthropicRefusalRecordedKey))

	require.NotPanics(t, func() {
		h.recordAnthropicRefusalIfMarked(c, nil, nil, "claude-sonnet-4-6", blockMeta, "")
	})
	require.True(t, c.GetBool(anthropicRefusalRecordedKey))
}

// 风控日志入参：category 随信号变化，provider 固定 anthropic，
// 且必须复用 cyber_policy 这个 action 以便沿用既有封号计数与开关语义。
func TestBuildAnthropicRefusalRecordInput(t *testing.T) {
	apiKey := &service.APIKey{
		ID:   11,
		Name: "key-a",
		User: &service.User{ID: 22, Email: "u@example.com"},
	}

	in := buildAnthropicRefusalRecordInput(
		&service.AnthropicRefusalMark{
			Signal:         service.AnthropicRefusalSignalRefusal,
			Message:        "",
			UpstreamStatus: 200,
			AccountID:      5,
			AccountName:    "acc5",
		},
		apiKey, "req-1", "/v1/messages", "claude-sonnet-4-6", "",
	)
	require.Equal(t, "anthropic_refusal", in.Category)
	require.Equal(t, "anthropic", in.Provider)
	require.Equal(t, int64(22), in.UserID)
	require.Equal(t, "u@example.com", in.UserEmail)
	require.Equal(t, int64(11), in.APIKeyID)
	require.Equal(t, 200, in.UpstreamStatus)
	require.Contains(t, in.UpstreamBody, "acc5", "operators need to know which upstream account was judged")

	in2 := buildAnthropicRefusalRecordInput(
		&service.AnthropicRefusalMark{
			Signal:         service.AnthropicRefusalSignalPermissionError,
			Message:        "org blocked",
			UpstreamStatus: 403,
		},
		apiKey, "req-2", "/v1/messages", "claude-sonnet-4-6", "",
	)
	require.Equal(t, "anthropic_permission_error", in2.Category)
	require.Equal(t, "org blocked", in2.UpstreamMessage)
	require.Equal(t, 403, in2.UpstreamStatus)
}

// 拦截层 fail-open：依赖缺失一律放行，绝不阻断主链路。
func TestRejectIfCyberSessionBlockedNative_FailOpen(t *testing.T) {
	c := newNativeGatewayTestCtx(`{}`)

	h := &GatewayHandler{}
	meta, rejected := h.rejectIfCyberSessionBlockedNative(c, nil, []byte(`{}`), "claude-sonnet-4-6")
	require.False(t, rejected, "nil apiKey → pass")
	require.Empty(t, meta.Key)

	h2 := &GatewayHandler{openAIGatewayService: nil}
	apiKey := &service.APIKey{ID: 1}
	meta2, rejected2 := h2.rejectIfCyberSessionBlockedNative(c, apiKey, []byte(`{}`), "claude-sonnet-4-6")
	require.False(t, rejected2, "nil block-store owner → pass")
	require.Empty(t, meta2.Key)
	require.False(t, c.Writer.Written(), "fail-open must not write any response")
}

const nativeCyberAllowlistedUserID = int64(1751)

type nativeCyberAllowlistHarness struct {
	handler        *GatewayHandler
	moderationRepo *contentModerationHandlerTestRepo
	blockStore     service.CyberSessionBlockStore
}

// newNativeCyberAllowlistHarness 组装会话屏蔽已开启、且把 nativeCyberAllowlistedUserID
// 列入风控白名单的 Anthropic 原生链路 handler。
func newNativeCyberAllowlistHarness(t *testing.T) *nativeCyberAllowlistHarness {
	t.Helper()
	gatewayCache := testutil.NewRedisGatewayCache(t)
	blockStore, ok := gatewayCache.(service.CyberSessionBlockStore)
	require.True(t, ok)
	settingRepo := &contentModerationHandlerSettingRepo{values: map[string]string{
		service.SettingKeyRiskControlEnabled:          "true",
		service.SettingKeyCyberSessionBlockEnabled:    "true",
		service.SettingKeyCyberSessionBlockTTLSeconds: "60",
		service.SettingKeyCyberPolicyUserAllowlist:    "1751",
	}}
	moderationRepo := &contentModerationHandlerTestRepo{}
	cfg := &config.Config{}
	gatewaySvc := service.NewOpenAIGatewayService(
		nil, nil, nil, nil, nil, nil, gatewayCache, cfg, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		service.NewSettingService(settingRepo, cfg), nil,
	)
	return &nativeCyberAllowlistHarness{
		handler: &GatewayHandler{
			openAIGatewayService:     gatewaySvc,
			contentModerationService: service.NewContentModerationService(settingRepo, moderationRepo, nil, nil, nil, nil, nil, nil, nil),
		},
		moderationRepo: moderationRepo,
		blockStore:     blockStore,
	}
}

func nativeCyberTestAPIKey(id, userID int64) *service.APIKey {
	return &service.APIKey{ID: id, UserID: userID, Name: "native-key", User: &service.User{ID: userID, Email: "u@example.com"}}
}

// 风控白名单用户跳过既有屏蔽（与 OpenAI HTTP/WS 准入一致）；非白名单用户照常被拒。
func TestRejectIfCyberSessionBlockedNative_AllowlistedUserSkipsExistingBlock(t *testing.T) {
	harness := newNativeCyberAllowlistHarness(t)
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[]}`)
	trusted := nativeCyberTestAPIKey(11, nativeCyberAllowlistedUserID)
	regular := nativeCyberTestAPIKey(12, 1752)
	for _, apiKey := range []*service.APIKey{trusted, regular} {
		meta := service.CyberSessionBlockMeta(apiKey, newNativeGatewayTestCtx(string(body)), body)
		require.NotEmpty(t, meta.Key)
		require.NoError(t, harness.blockStore.SetCyberSessionBlocked(context.Background(), "", []string{meta.Key}, time.Minute))
	}

	regularCtx := newNativeGatewayTestCtx(string(body))
	_, rejected := harness.handler.rejectIfCyberSessionBlockedNative(regularCtx, regular, body, "claude-sonnet-4-6")
	require.True(t, rejected, "non-allowlisted users must still be rejected by an existing block")

	trustedCtx := newNativeGatewayTestCtx(string(body))
	_, rejected = harness.handler.rejectIfCyberSessionBlockedNative(trustedCtx, trusted, body, "claude-sonnet-4-6")
	require.False(t, rejected, "allowlisted users must skip existing blocks")
	require.False(t, trustedCtx.Writer.Written())
}

// 风控白名单用户命中 Anthropic 硬拒答：只留 cyber_log_only 证据，不计封号、不写屏蔽表。
func TestRecordAnthropicRefusalIfMarked_AllowlistedUserIsLogOnly(t *testing.T) {
	harness := newNativeCyberAllowlistHarness(t)
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[]}`)
	apiKey := nativeCyberTestAPIKey(11, nativeCyberAllowlistedUserID)
	c := newNativeGatewayTestCtx(string(body))
	service.MarkAnthropicRefusal(c, service.AnthropicRefusalMark{
		Signal:         service.AnthropicRefusalSignalRefusal,
		UpstreamStatus: 200,
	})
	blockMeta := service.CyberSessionBlockMeta(apiKey, c, body)
	require.NotEmpty(t, blockMeta.Key)

	harness.handler.recordAnthropicRefusalIfMarked(c, apiKey, nil, "claude-sonnet-4-6", blockMeta, "")

	require.Eventually(t, func() bool {
		logs := harness.moderationRepo.logSnapshot()
		return len(logs) == 1 && logs[0].Mode == service.ContentModerationModeCyberLogOnly
	}, 3*time.Second, 10*time.Millisecond)
	logs := harness.moderationRepo.logSnapshot()
	require.False(t, logs[0].AutoBanned)
	require.False(t, logs[0].EmailSent)
	require.Never(t, func() bool {
		matched, err := harness.blockStore.FindCyberSessionBlocked(context.Background(), []string{blockMeta.Key})
		return err == nil && len(matched) > 0
	}, 300*time.Millisecond, 10*time.Millisecond, "allowlisted refusals must not write session blocks")
}
