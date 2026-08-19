package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// anthropicRefusalRecordedKey 防止同一请求重复记录（failover 会多次经过收尾路径）。
const anthropicRefusalRecordedKey = "ops_anthropic_refusal_recorded"

// anthropicRefusalCategory 把硬信号映射为风控中心的 highest_category。
func anthropicRefusalCategory(signal string) string {
	switch signal {
	case service.AnthropicRefusalSignalPermissionError:
		return "anthropic_permission_error"
	default:
		return "anthropic_refusal"
	}
}

// buildAnthropicRefusalRecordInput 把上游硬阻断证据整理成风控日志入参。
// 纯函数，便于单测；不触碰 gin.Context 之外的任何状态。
func buildAnthropicRefusalRecordInput(
	mark *service.AnthropicRefusalMark,
	apiKey *service.APIKey,
	requestID string,
	endpoint string,
	model string,
) service.CyberPolicyRecordInput {
	in := service.CyberPolicyRecordInput{
		Category:        anthropicRefusalCategory(mark.Signal),
		Provider:        "anthropic",
		RequestID:       requestID,
		Endpoint:        endpoint,
		Model:           model,
		UpstreamMessage: mark.Message,
		UpstreamStatus:  mark.UpstreamStatus,
	}
	// 账号信息进 body 而非 message：运维要能一眼看出是哪个上游号被判罚，
	// 但不该污染发给用户的提示文案。
	if mark.AccountID > 0 {
		in.UpstreamBody = fmt.Sprintf("signal=%s account=%d(%s)", mark.Signal, mark.AccountID, mark.AccountName)
	} else {
		in.UpstreamBody = "signal=" + mark.Signal
	}
	if apiKey != nil {
		in.APIKeyID = apiKey.ID
		in.APIKeyName = apiKey.Name
		in.GroupID = apiKey.GroupID
		if apiKey.Group != nil {
			in.GroupName = apiKey.Group.Name
		}
		if apiKey.User != nil {
			in.UserID = apiKey.User.ID
			in.UserEmail = apiKey.User.Email
		}
	}
	return in
}

// recordAnthropicRefusalIfMarked 在 Forward 返回后检查硬拒答标记，异步写风控日志
// （计入违规计数、触发既有自动封禁与邮件），并在会话屏蔽开关开启时把该标识写入屏蔽表。
//
// 只有硬信号才会到这里：stop_reason=="refusal" 与 403 permission_error。
// 软拒答（200 + end_turn + 拒绝文案）在检测层就被排除，避免误封正常用户。
// 全程 fail-open：任何缺失依赖都只是少记一条日志，绝不影响已经发给客户端的响应。
func (h *GatewayHandler) recordAnthropicRefusalIfMarked(
	c *gin.Context,
	apiKey *service.APIKey,
	account *service.Account,
	model string,
	blockMeta service.CyberBlockMeta,
) {
	if h == nil || c == nil {
		return
	}
	mark := service.GetAnthropicRefusalMark(c)
	if mark == nil {
		return
	}
	if c.GetBool(anthropicRefusalRecordedKey) {
		return
	}
	c.Set(anthropicRefusalRecordedKey, true)

	if account != nil && mark.AccountID == 0 {
		mark.AccountID = account.ID
		mark.AccountName = account.Name
	}

	requestPath := ""
	if c.Request != nil && c.Request.URL != nil {
		requestPath = c.Request.URL.Path
	}
	recordInput := buildAnthropicRefusalRecordInput(
		mark, apiKey, c.Writer.Header().Get("X-Request-Id"), GetInboundEndpoint(c), model,
	)
	recordInput.Endpoint = defaultString(recordInput.Endpoint, requestPath)

	cmSvc := h.contentModerationService
	blockOwner := h.openAIGatewayService
	signal := mark.Signal
	blockMeta.Signal = signal

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if cmSvc != nil {
			cmSvc.RecordCyberPolicyEvent(ctx, recordInput)
		}
		// 会话屏蔽是"下一次请求前"的本地防线：同一违规主体在 TTL 内直接被拒，
		// 不再消耗上游账号的风控额度。开关关闭时 MarkCyberSessionBlocked 自身会跳过。
		if blockOwner != nil && blockMeta.Key != "" {
			blockOwner.MarkCyberSessionBlockedWithMeta(ctx, blockMeta.Key, blockMeta)
		}
		logger.L().With(zap.String("component", "handler.gateway.anthropic_refusal")).
			Info("gateway.anthropic_hard_refusal_recorded",
				zap.String("signal", signal),
				zap.String("model", model),
			)
	}()
}

// nativeCyberBlockedClientMsg 与 OpenAI 路径同文案（双语单串：网关无 i18n 协商通道）。
const nativeCyberBlockedClientMsg = cyberSessionBlockedClientMsg

// rejectIfCyberSessionBlockedNative 在选号之前检查屏蔽表。
// 返回 blockKey 供收尾阶段复用（避免二次派生），rejected=true 表示响应已写出。
// fail-open：开关关闭、依赖缺失或查询出错都放行。
func (h *GatewayHandler) rejectIfCyberSessionBlockedNative(
	c *gin.Context,
	apiKey *service.APIKey,
	body []byte,
	model string,
) (service.CyberBlockMeta, bool) {
	var empty service.CyberBlockMeta
	if h == nil || c == nil || apiKey == nil || h.openAIGatewayService == nil {
		return empty, false
	}
	ctx := context.Background()
	if c.Request != nil {
		ctx = c.Request.Context()
	}
	// 开关默认关：先做 ~ns 级缓存开关检查，再付出 key 派生（gjson+sha256）成本。
	if enabled, _ := h.openAIGatewayService.CyberSessionBlockRuntime(ctx); !enabled {
		return empty, false
	}
	kind, masked, key := service.StickyIdentity(apiKey.ID, apiKeyUserID(apiKey), c, body)
	if key == "" {
		return empty, false
	}
	meta := service.CyberBlockMeta{Key: key, Kind: kind, Masked: masked}
	if !h.openAIGatewayService.IsCyberSessionBlocked(ctx, key) {
		return meta, false
	}
	service.MarkOpsClientBusinessLimited(c, service.OpsClientBusinessLimitedReasonLocalPolicyDenied)
	c.JSON(http.StatusForbidden, gin.H{"type": "error", "error": gin.H{
		"type":    "permission_error",
		"message": nativeCyberBlockedClientMsg,
	}})
	logger.L().With(zap.String("component", "handler.gateway.anthropic_refusal")).
		Info("gateway.native_request_rejected_by_cyber_block",
			zap.Int64("api_key_id", apiKey.ID),
			zap.String("identity_kind", kind),
			zap.String("identity", masked),
			zap.String("model", model),
		)
	return meta, true
}

// defaultString 返回第一个非空值。
func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
