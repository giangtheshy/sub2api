package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// [FORK-BAN-SCOPE] 内容审核/安全审计输入必须携带终端用户标识，且与封禁检查侧
// （rejectIfEndUserBanned*，userID 取 apiKey.User.ID）派生出同一个哈希。
func newBanScopeTestContext(headers map[string]string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/chat/completions", nil)
	for k, v := range headers {
		c.Request.Header.Set(k, v)
	}
	return c
}

func TestBuildModerationInputs_CarryEndUserIdentity(t *testing.T) {
	apiKey := &service.APIKey{ID: 5, UserID: 77, User: &service.User{ID: 77}}
	tests := []struct {
		name      string
		headers   map[string]string
		subject   middleware2.AuthSubject
		wantEmpty bool
	}{
		{name: "with X-User-Id", headers: map[string]string{"X-User-Id": "customer-a"}, subject: middleware2.AuthSubject{UserID: 77}},
		{name: "subject id differs, hash still follows apiKey.User.ID", headers: map[string]string{"X-User-Id": "customer-a"}, subject: middleware2.AuthSubject{UserID: 999}},
		{name: "without X-User-Id", headers: nil, subject: middleware2.AuthSubject{UserID: 77}, wantEmpty: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newBanScopeTestContext(tt.headers)
			_, want := service.EndUserBanIdentity(apiKeyUserID(apiKey), c)

			input := buildContentModerationInput(c, apiKey, tt.subject, service.ContentModerationProtocolOpenAIChat, "gpt-5", nil)
			request := buildSecurityAuditRequest(c, apiKey, tt.subject, service.ContentModerationProtocolOpenAIChat, "gpt-5", nil, "http")

			if tt.wantEmpty {
				require.Empty(t, input.EndUserIdentity)
				require.Empty(t, request.EndUserIdentity)
				return
			}
			require.NotEmpty(t, want)
			require.Equal(t, want, input.EndUserIdentity)
			require.Equal(t, want, request.EndUserIdentity)
			require.Equal(t, want, request.Clone().EndUserIdentity)
		})
	}
}

// keyword_block 走异步落库队列：落库的违规行必须带上终端用户标识，终端用户层才会生效。
func TestRunContentModeration_KeywordBlockLogCarriesEndUserIdentity(t *testing.T) {
	cfg := &service.ContentModerationConfig{
		Enabled:             true,
		Mode:                service.ContentModerationModePreBlock,
		SampleRate:          100,
		AllGroups:           true,
		BlockMessage:        "blocked",
		BlockedKeywords:     []string{"forbiddenword"},
		KeywordBlockingMode: service.ContentModerationKeywordModeKeywordOnly,
	}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)
	repo := &contentModerationHandlerTestRepo{}
	settingRepo := &contentModerationHandlerSettingRepo{values: map[string]string{
		service.SettingKeyRiskControlEnabled:      "true",
		service.SettingKeyContentModerationConfig: string(rawCfg),
	}}
	svc := service.NewContentModerationService(settingRepo, repo, nil, nil, nil, nil, nil, nil, nil)

	apiKey := &service.APIKey{ID: 5, UserID: 77, User: &service.User{ID: 77}}
	c := newBanScopeTestContext(map[string]string{"X-User-Id": "customer-a"})
	_, want := service.EndUserBanIdentity(77, c)
	body := []byte(`{"model":"gpt-5","messages":[{"role":"user","content":"please say forbiddenword"}]}`)

	decision := runContentModeration(c, nil, svc, apiKey, middleware2.AuthSubject{UserID: 77}, service.ContentModerationProtocolOpenAIChat, "gpt-5", body)
	require.NotNil(t, decision)
	require.True(t, decision.Blocked)
	require.Equal(t, service.ContentModerationActionKeywordBlock, decision.Action)

	require.Eventually(t, func() bool { return len(repo.logSnapshot()) == 1 }, time.Second, 10*time.Millisecond)
	logs := repo.logSnapshot()
	require.Equal(t, want, logs[0].EndUserIdentity)
	require.False(t, logs[0].AutoBanned)
}
