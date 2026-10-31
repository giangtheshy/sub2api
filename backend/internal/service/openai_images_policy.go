package service

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// OpenAIImagesPolicyCategory 是图片接口内容政策拒绝在风控中心的 highest_category，
// 用于和文本接口的 cyber_policy 区分来源；Action 仍是 cyber_policy，封号计数口径一致。
const OpenAIImagesPolicyCategory = "openai_image_policy"

// IsOpenAIImagesPolicyRejection reports whether an Images error is the upstream
// refusing the request content (moderation / content policy), as opposed to a
// capability, quota or server failure.
//
// [FORK-BAN-SCOPE] 只认机器可读的上游裁决。模型用文字婉拒（ModelTextPolicyRefusal）
// 与 Anthropic 的软拒答同属一类，不计入违规，避免误封正常用户。
func IsOpenAIImagesPolicyRejection(err *OpenAIImagesUpstreamError) bool {
	if err == nil || err.ModelTextPolicyRefusal || err.StatusCode >= http.StatusInternalServerError {
		return false
	}
	code := strings.ToLower(strings.TrimSpace(err.Code))
	switch {
	case code == "moderation_blocked",
		code == "cyber_policy",
		strings.Contains(code, "content_policy"),
		strings.Contains(code, "policy_violation"),
		strings.Contains(code, "safety_violation"):
		return true
	case code == "response_incomplete":
		// openAIImagesIncompleteUpstreamError 只在 content_filter / moderation 时归为用户错误。
		return err.ErrorType == "image_generation_user_error"
	}
	return false
}

// MarkOpenAIImagesPolicyRejection sets the cyber_policy mark for an Images
// request refused on content grounds, so the handler's recordCyberPolicyIfMarked
// applies the same risk-control pipeline as the text endpoints (violation
// counting, end-user ban, session block, notice email). Reports whether a mark
// was set.
func MarkOpenAIImagesPolicyRejection(c *gin.Context, err *OpenAIImagesUpstreamError) bool {
	if !IsOpenAIImagesPolicyRejection(err) {
		return false
	}
	MarkOpsCyberPolicy(c, CyberPolicyMark{
		Category:       OpenAIImagesPolicyCategory,
		Message:        err.Message,
		Body:           string(openAIImagesUpstreamErrorResponseBody(err)),
		UpstreamStatus: err.StatusCode,
	})
	return true
}
