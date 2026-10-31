package service

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestIsOpenAIImagesPolicyRejection(t *testing.T) {
	cases := []struct {
		name string
		err  *OpenAIImagesUpstreamError
		want bool
	}{
		{"moderation_blocked", &OpenAIImagesUpstreamError{StatusCode: http.StatusBadRequest, ErrorType: "image_generation_user_error", Code: "moderation_blocked"}, true},
		{"content_policy_violation", &OpenAIImagesUpstreamError{StatusCode: http.StatusBadRequest, ErrorType: "invalid_request_error", Code: "content_policy_violation"}, true},
		{"cyber_policy", &OpenAIImagesUpstreamError{StatusCode: http.StatusBadRequest, Code: "cyber_policy"}, true},
		{"safety_violation", &OpenAIImagesUpstreamError{StatusCode: http.StatusBadRequest, Code: "image_safety_violation"}, true},
		{"incomplete_content_filter", openAIImagesIncompleteUpstreamError(gjson.Parse(`{"id":"resp_1","incomplete_details":{"reason":"content_filter"}}`)), true},
		{"incomplete_max_output_tokens", openAIImagesIncompleteUpstreamError(gjson.Parse(`{"id":"resp_1","incomplete_details":{"reason":"max_output_tokens"}}`)), false},
		// The model declining in prose is a soft refusal, like Anthropic end_turn
		// refusals: never evidence enough to count against the end user.
		{"model_text_refusal", openAIImagesTextFallbackErrorForText("Blocked by our content policy."), false},
		{"rate_limit", &OpenAIImagesUpstreamError{StatusCode: http.StatusTooManyRequests, ErrorType: "rate_limit_error", Code: "rate_limit_exceeded"}, false},
		{"server_error", &OpenAIImagesUpstreamError{StatusCode: http.StatusBadGateway, ErrorType: "server_error", Code: "server_error"}, false},
		{"invalid_size", &OpenAIImagesUpstreamError{StatusCode: http.StatusBadRequest, ErrorType: "invalid_request_error", Code: "invalid_value", Param: "size"}, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, IsOpenAIImagesPolicyRejection(tc.err))
		})
	}
}

func TestMarkOpenAIImagesPolicyRejectionSetsCyberMark(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	upstreamErr := &OpenAIImagesUpstreamError{
		StatusCode: http.StatusBadRequest,
		ErrorType:  "image_generation_user_error",
		Code:       "moderation_blocked",
		Message:    "Your request was rejected by the safety system.",
	}

	require.True(t, MarkOpenAIImagesPolicyRejection(c, upstreamErr))

	mark := GetOpsCyberPolicy(c)
	require.NotNil(t, mark)
	require.Equal(t, OpenAIImagesPolicyCategory, mark.Category)
	require.Equal(t, http.StatusBadRequest, mark.UpstreamStatus)
	require.Equal(t, upstreamErr.Message, mark.Message)
	require.Contains(t, mark.Body, "moderation_blocked")
}

func TestMarkOpenAIImagesPolicyRejectionIgnoresOtherErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	require.False(t, MarkOpenAIImagesPolicyRejection(c, &OpenAIImagesUpstreamError{StatusCode: http.StatusBadGateway, Code: "server_error"}))
	require.Nil(t, GetOpsCyberPolicy(c))
}
