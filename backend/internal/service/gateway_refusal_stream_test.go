package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// SSE 中继遇到 message_delta.stop_reason=="refusal" 时必须打上硬拒答标记，
// 且不得改动透传给客户端的字节。
func TestGatewayService_StreamingMarksAnthropicRefusal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newStreamingResponseTestGatewayService()

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	pr, pw := io.Pipe()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: pr}

	go func() {
		defer func() { _ = pw.Close() }()
		_, _ = pw.Write([]byte("data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3}}}\n\n"))
		_, _ = pw.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"refusal\"},\"usage\":{\"output_tokens\":1}}\n\n"))
		_, _ = pw.Write([]byte("data: [DONE]\n\n"))
	}()

	_, err := svc.handleStreamingResponse(context.Background(), resp, c, &Account{ID: 7, Name: "acc7"}, time.Now(), "model", "model", false)
	_ = pr.Close()
	require.NoError(t, err)

	mark := GetAnthropicRefusalMark(c)
	require.NotNil(t, mark, "refusal stop_reason in stream must set a mark")
	require.Equal(t, AnthropicRefusalSignalRefusal, mark.Signal)
	require.Equal(t, http.StatusOK, mark.UpstreamStatus)
	require.Equal(t, int64(7), mark.AccountID)
	require.Contains(t, rec.Body.String(), `"stop_reason":"refusal"`, "upstream bytes must stay transparent")
}

// 正常结束（end_turn）绝不能被判为违规——这是防止误封真实用户的关键约束。
func TestGatewayService_StreamingDoesNotMarkOnEndTurn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newStreamingResponseTestGatewayService()

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)

	pr, pw := io.Pipe()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: pr}

	go func() {
		defer func() { _ = pw.Close() }()
		_, _ = pw.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":9}}\n\n"))
		_, _ = pw.Write([]byte("data: [DONE]\n\n"))
	}()

	_, err := svc.handleStreamingResponse(context.Background(), resp, c, &Account{ID: 1}, time.Now(), "model", "model", false)
	_ = pr.Close()
	require.NoError(t, err)
	require.Nil(t, GetAnthropicRefusalMark(c), "end_turn must never be treated as a violation")
}
