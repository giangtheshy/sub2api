//go:build unit

package handler

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// openAIImagesPolicyHTTPUpstream answers every image call with one SSE event.
type openAIImagesPolicyHTTPUpstream struct {
	service.HTTPUpstream
	event string
	mu    sync.Mutex
	calls int
}

func (u *openAIImagesPolicyHTTPUpstream) Do(_ *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	u.mu.Lock()
	u.calls++
	u.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(bytes.NewBufferString("data: " + u.event + "\n\n")),
	}, nil
}

func (u *openAIImagesPolicyHTTPUpstream) callCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

type openAIImagesPolicyHarness struct {
	handler  *OpenAIGatewayHandler
	upstream *openAIImagesPolicyHTTPUpstream
	cmRepo   *contentModerationHandlerTestRepo
	banStore *forkEndUserBanStore
	apiKey   *service.APIKey
}

func newOpenAIImagesPolicyHarness(t *testing.T, upstreamEvent string) *openAIImagesPolicyHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	groupID := int64(3140)
	accountRepo := openAIImagesFailoverAccountRepo{accounts: []service.Account{{
		ID:          1,
		Name:        "image-account-1",
		Platform:    service.PlatformOpenAI,
		Type:        service.AccountTypeOAuth,
		Status:      service.StatusActive,
		Schedulable: true,
		Credentials: map[string]any{"access_token": "token-1"},
	}}}
	upstream := &openAIImagesPolicyHTTPUpstream{event: upstreamEvent}
	cfg := &config.Config{RunMode: config.RunModeSimple}
	gatewayService := service.NewOpenAIGatewayService(
		accountRepo, nil, nil, nil, nil, nil, nil, cfg, nil, nil, nil,
		nil, nil, upstream, nil, nil, nil, nil, nil, nil, nil, nil,
	)
	billingService := service.NewBillingCacheService(nil, nil, nil, nil, nil, nil, cfg, nil)
	t.Cleanup(billingService.Stop)
	handler := NewOpenAIGatewayHandler(
		gatewayService,
		service.NewConcurrencyService(nil),
		billingService,
		service.NewAPIKeyService(nil, nil, nil, nil, nil, nil, cfg),
		nil, nil, nil, nil,
		cfg,
	)

	settingRepo := &contentModerationHandlerSettingRepo{values: map[string]string{
		service.SettingKeyRiskControlEnabled:      "true",
		service.SettingKeyContentModerationConfig: `{"end_user_ban_enabled":true}`,
	}}
	cmRepo := &contentModerationHandlerTestRepo{}
	banStore := &forkEndUserBanStore{}
	handler.contentModerationService = service.NewContentModerationService(settingRepo, cmRepo, nil, nil, nil, nil, nil, nil, banStore)

	return &openAIImagesPolicyHarness{
		handler:  handler,
		upstream: upstream,
		cmRepo:   cmRepo,
		banStore: banStore,
		apiKey: &service.APIKey{
			ID:      98,
			UserID:  101,
			GroupID: &groupID,
			Group:   &service.Group{ID: groupID, AllowImageGeneration: true},
			User:    &service.User{ID: 101},
		},
	}
}

func (h *openAIImagesPolicyHarness) serve(endUserID string) (*gin.Context, *httptest.ResponseRecorder) {
	body := []byte(`{"model":"gpt-image-1","prompt":"draw something","size":"1024x1024"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Id", endUserID)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req
	c.Set(string(middleware2.ContextKeyAPIKey), h.apiKey)
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: 101})
	h.handler.Images(c)
	return c, rec
}

// A content-policy block on the Images API must go through the same
// risk-control pipeline as text endpoints: flagged cyber_policy log carrying the
// end-user identity, which is what drives violation counting and bans.
func TestOpenAIGatewayHandlerImages_PolicyBlockIsRecordedLikeTextEndpoints(t *testing.T) {
	h := newOpenAIImagesPolicyHarness(t,
		`{"type":"error","error":{"type":"image_generation_user_error","code":"moderation_blocked","message":"Your request was rejected by the safety system."}}`)

	c, rec := h.serve("img-user-1")

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Equal(t, 1, h.upstream.callCount(), "a content verdict must not fail over to another account")
	require.NotNil(t, service.GetOpsCyberPolicy(c))

	_, identity := service.EndUserBanIdentity(apiKeyUserID(h.apiKey), c)
	require.NotEmpty(t, identity)
	require.Eventually(t, func() bool { return len(h.cmRepo.logSnapshot()) == 1 }, 2*time.Second, 10*time.Millisecond)
	log := h.cmRepo.logSnapshot()[0]
	require.Equal(t, service.ContentModerationActionCyberPolicy, log.Action)
	require.True(t, log.Flagged)
	require.Equal(t, service.OpenAIImagesPolicyCategory, log.HighestCategory)
	require.Equal(t, identity, log.EndUserIdentity)
}

func TestOpenAIGatewayHandlerImages_NonPolicyErrorIsNotRecorded(t *testing.T) {
	h := newOpenAIImagesPolicyHarness(t,
		`{"type":"error","error":{"type":"invalid_request_error","code":"invalid_value","param":"size","message":"Invalid size"}}`)

	c, rec := h.serve("img-user-2")

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Nil(t, service.GetOpsCyberPolicy(c))
	require.Never(t, func() bool { return len(h.cmRepo.logSnapshot()) > 0 }, 200*time.Millisecond, 10*time.Millisecond)
}

// A banned end user must be stopped before any upstream image call, exactly as
// on the text endpoints.
func TestOpenAIGatewayHandlerImages_RejectsBannedEndUserBeforeUpstream(t *testing.T) {
	h := newOpenAIImagesPolicyHarness(t, `{"type":"error","error":{"type":"server_error","code":"server_error","message":"unused"}}`)
	probe, _ := gin.CreateTestContext(httptest.NewRecorder())
	probe.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)
	probe.Request.Header.Set("X-User-Id", "banned-img-user")
	_, identity := service.EndUserBanIdentity(apiKeyUserID(h.apiKey), probe)
	require.NoError(t, h.banStore.BanEndUser(context.Background(), identity, service.EndUserBanMeta{}))

	_, rec := h.serve("banned-img-user")

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, endUserBannedErrorCode, gjson.GetBytes(rec.Body.Bytes(), "error.code").String())
	require.Zero(t, h.upstream.callCount())
}
