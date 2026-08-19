package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func newRefusalTestGatewayService() *GatewayService {
	return &GatewayService{
		cfg:              &config.Config{},
		rateLimitService: &RateLimitService{},
	}
}

// refusalErrorPathAccountRepo 吸收 403 处理路径对账号仓储的写入，
// 让 handleErrorResponse 能在单测中跑完而不触碰真实 DB。
type refusalErrorPathAccountRepo struct {
	AccountRepository
	setErrorCalls int
}

func (r *refusalErrorPathAccountRepo) SetError(_ context.Context, _ int64, _ string) error {
	r.setErrorCalls++
	return nil
}

func newRefusalErrorPathGatewayService() *GatewayService {
	cfg := &config.Config{}
	return &GatewayService{
		cfg: cfg,
		rateLimitService: &RateLimitService{
			accountRepo: &refusalErrorPathAccountRepo{},
			cfg:         cfg,
		},
	}
}

func TestHandleNonStreamingResponse_MarksAnthropicRefusal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	body := []byte(`{"id":"msg_1","type":"message","stop_reason":"refusal","usage":{"input_tokens":12,"output_tokens":1}}`)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	usage, err := newRefusalTestGatewayService().handleNonStreamingResponse(
		context.Background(), resp, c, &Account{ID: 42, Name: "acc42"}, "claude-sonnet-4-6", "claude-sonnet-4-6")

	require.NoError(t, err)
	require.NotNil(t, usage)
	mark := GetAnthropicRefusalMark(c)
	require.NotNil(t, mark, "non-stream stop_reason=refusal must set a mark")
	require.Equal(t, AnthropicRefusalSignalRefusal, mark.Signal)
	require.Equal(t, int64(42), mark.AccountID)
	require.JSONEq(t, string(body), rec.Body.String(), "response must stay transparent")
}

func TestHandleNonStreamingResponse_DoesNotMarkSoftRefusal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	// 软拒答：正常结束 + 拒绝文案。绝不能计入违规。
	body := []byte(`{"id":"msg_1","type":"message","stop_reason":"end_turn","content":[{"type":"text","text":"I can't help with that."}],"usage":{"input_tokens":5,"output_tokens":8}}`)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	_, err := newRefusalTestGatewayService().handleNonStreamingResponse(
		context.Background(), resp, c, &Account{ID: 1}, "claude-sonnet-4-6", "claude-sonnet-4-6")

	require.NoError(t, err)
	require.Nil(t, GetAnthropicRefusalMark(c), "soft refusal must never be flagged")
}

func TestHandleErrorResponse_MarksAnthropicPermissionError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	body := []byte(`{"type":"error","error":{"type":"permission_error","message":"Your organization has been blocked"}}`)
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	_, _ = newRefusalErrorPathGatewayService().handleErrorResponse(
		context.Background(), resp, c, &Account{ID: 9, Name: "acc9"}, "claude-sonnet-4-6")

	mark := GetAnthropicRefusalMark(c)
	require.NotNil(t, mark, "403 permission_error must set a mark")
	require.Equal(t, AnthropicRefusalSignalPermissionError, mark.Signal)
	require.Equal(t, http.StatusForbidden, mark.UpstreamStatus)
	require.Equal(t, "Your organization has been blocked", mark.Message)
}

func TestHandleErrorResponse_DoesNotMarkRateLimit403(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	body := []byte(`{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`)
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	_, _ = newRefusalErrorPathGatewayService().handleErrorResponse(
		context.Background(), resp, c, &Account{ID: 9}, "claude-sonnet-4-6")

	require.Nil(t, GetAnthropicRefusalMark(c), "rate_limit_error must not be flagged as a policy block")
}
