package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// API Key 直通链路有自己的 SSE / 非流式处理函数，不走通用 relay。
// 硬拒答检测必须同样覆盖它，否则直通账号完全不受保护。
func TestHandleNonStreamingResponsePassthrough_MarksAnthropicRefusal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	body := []byte(`{"id":"msg_1","type":"message","stop_reason":"refusal","usage":{"input_tokens":4,"output_tokens":1}}`)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	_, err := newRefusalTestGatewayService().handleNonStreamingResponseAnthropicAPIKeyPassthrough(
		context.Background(), resp, c, &Account{ID: 3, Name: "passthrough"})

	require.NoError(t, err)
	mark := GetAnthropicRefusalMark(c)
	require.NotNil(t, mark, "passthrough non-stream refusal must be detected too")
	require.Equal(t, AnthropicRefusalSignalRefusal, mark.Signal)
	require.Equal(t, int64(3), mark.AccountID)
}

func TestHandleNonStreamingResponsePassthrough_IgnoresSoftRefusal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	body := []byte(`{"type":"message","stop_reason":"end_turn","content":[{"type":"text","text":"I can't help with that."}]}`)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	_, err := newRefusalTestGatewayService().handleNonStreamingResponseAnthropicAPIKeyPassthrough(
		context.Background(), resp, c, &Account{ID: 3})

	require.NoError(t, err)
	require.Nil(t, GetAnthropicRefusalMark(c))
}

func TestHandleStreamingResponsePassthrough_MarksAnthropicRefusal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	pr, pw := io.Pipe()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: pr}

	go func() {
		defer func() { _ = pw.Close() }()
		_, _ = pw.Write([]byte("data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3}}}\n\n"))
		_, _ = pw.Write([]byte("data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"refusal\"},\"usage\":{\"output_tokens\":1}}\n\n"))
		_, _ = pw.Write([]byte("data: [DONE]\n\n"))
	}()

	svc := newStreamingResponseTestGatewayService()
	_, err := svc.handleStreamingResponseAnthropicAPIKeyPassthrough(
		context.Background(), resp, c, &Account{ID: 8, Name: "pt8"}, time.Now(), "claude-sonnet-4-6")
	_ = pr.Close()
	require.NoError(t, err)

	mark := GetAnthropicRefusalMark(c)
	require.NotNil(t, mark, "passthrough stream refusal must be detected too")
	require.Equal(t, AnthropicRefusalSignalRefusal, mark.Signal)
	require.Equal(t, int64(8), mark.AccountID)
	require.Contains(t, rec.Body.String(), `"stop_reason":"refusal"`, "bytes stay transparent")
}

func TestHandleStreamingResponsePassthrough_IgnoresEndTurn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	pr, pw := io.Pipe()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: pr}

	go func() {
		defer func() { _ = pw.Close() }()
		_, _ = pw.Write([]byte("data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n"))
		_, _ = pw.Write([]byte("data: [DONE]\n\n"))
	}()

	svc := newStreamingResponseTestGatewayService()
	_, err := svc.handleStreamingResponseAnthropicAPIKeyPassthrough(
		context.Background(), resp, c, &Account{ID: 8}, time.Now(), "claude-sonnet-4-6")
	_ = pr.Close()
	require.NoError(t, err)
	require.Nil(t, GetAnthropicRefusalMark(c))
}
