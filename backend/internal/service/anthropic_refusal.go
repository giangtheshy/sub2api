package service

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// Anthropic 原生链路的"硬信号"种类。软拒答（HTTP 200 + stop_reason=end_turn +
// 拒绝文案）刻意不在此列——用户决策 (a)：只有机器可读的硬信号才参与风控/封号，
// 避免把正常用户的敏感提问误判为违规。
const (
	// AnthropicRefusalSignalRefusal 对应 stop_reason=="refusal"（流式与非流式）。
	AnthropicRefusalSignalRefusal = "refusal"
	// AnthropicRefusalSignalPermissionError 对应 HTTP 403 + error.type=="permission_error"。
	AnthropicRefusalSignalPermissionError = "permission_error"
)

// anthropicRefusalKey 在 gin context 中携带 Anthropic 硬拒答标记。
// 由 gateway 服务层在中继响应时设置，handler 在 Forward 返回后读取，
// 用于写风控日志、计入违规计数并（开关开启时）写入会话屏蔽表。
const anthropicRefusalKey = "ops_anthropic_refusal"

// AnthropicRefusalMark 记录一次 Anthropic 硬阻断的上游证据。
type AnthropicRefusalMark struct {
	// Signal ∈ {AnthropicRefusalSignalRefusal, AnthropicRefusalSignalPermissionError}
	Signal string
	// Message 上游可读信息（permission_error 的 error.message；refusal 通常为空）
	Message string
	// UpstreamStatus 上游 HTTP 状态（refusal 流式/非流式=200，permission_error=403）
	UpstreamStatus int
	// AccountID/AccountName 命中时所用的上游账号，便于运维定位是哪个号被判罚
	AccountID   int64
	AccountName string
}

// MarkAnthropicRefusal 记录硬拒答标记；首个写入生效，后续忽略（同一请求只记一次，
// 即便 failover 重试多次也不会重复计数）。空 Signal 视为无效，不落标记。
func MarkAnthropicRefusal(c *gin.Context, mark AnthropicRefusalMark) {
	if c == nil {
		return
	}
	mark.Signal = strings.TrimSpace(mark.Signal)
	if mark.Signal == "" {
		return
	}
	if GetAnthropicRefusalMark(c) != nil {
		return
	}
	mark.Message = strings.TrimSpace(mark.Message)
	c.Set(anthropicRefusalKey, &mark)
}

// GetAnthropicRefusalMark 返回硬拒答标记，未命中（或已被 Clear）返回 nil。
func GetAnthropicRefusalMark(c *gin.Context) *AnthropicRefusalMark {
	if c == nil {
		return nil
	}
	if v, ok := c.Get(anthropicRefusalKey); ok {
		if m, ok := v.(*AnthropicRefusalMark); ok && m != nil {
			return m
		}
	}
	return nil
}

// ClearAnthropicRefusalMark 清除标记（typed-nil 覆盖，与 ClearOpsCyberPolicy 同构）。
func ClearAnthropicRefusalMark(c *gin.Context) {
	if c == nil {
		return
	}
	c.Set(anthropicRefusalKey, (*AnthropicRefusalMark)(nil))
}

// DetectAnthropicRefusalJSON 检测非流式响应中的硬拒答：顶层 stop_reason=="refusal"。
// 这是 Anthropic 唯一机器可读的"本次内容被安全策略拒绝"信号。
// 刻意不匹配 end_turn + 拒绝文案的软拒答（决策 a）。
func DetectAnthropicRefusalJSON(payload []byte) (bool, string) {
	if len(payload) == 0 || !gjson.ValidBytes(payload) {
		return false, ""
	}
	if strings.EqualFold(strings.TrimSpace(gjson.GetBytes(payload, "stop_reason").String()), AnthropicRefusalSignalRefusal) {
		return true, strings.TrimSpace(gjson.GetBytes(payload, "stop_sequence").String())
	}
	return false, ""
}

// DetectAnthropicRefusalSSEDelta 检测流式 message_delta 事件中的
// delta.stop_reason=="refusal"。调用方需保证 event 已是解析后的 message_delta。
func DetectAnthropicRefusalSSEDelta(event map[string]any) bool {
	if event == nil {
		return false
	}
	delta, ok := event["delta"].(map[string]any)
	if !ok {
		return false
	}
	sr, _ := delta["stop_reason"].(string)
	return strings.EqualFold(strings.TrimSpace(sr), AnthropicRefusalSignalRefusal)
}

// DetectAnthropicRefusalSSEData 检测未反序列化的 SSE data 行中的硬拒答。
// 用于 API Key 直通链路——它有自己的 SSE 处理循环，不经过通用 relay 的
// map[string]any 解析路径。stop_reason 只在 message_delta 上有意义。
func DetectAnthropicRefusalSSEData(data string) bool {
	data = strings.TrimSpace(data)
	if data == "" || data == "[DONE]" || !gjson.Valid(data) {
		return false
	}
	parsed := gjson.Parse(data)
	if parsed.Get("type").String() != "message_delta" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(parsed.Get("delta.stop_reason").String()), AnthropicRefusalSignalRefusal)
}

// DetectAnthropicPermissionError 检测 HTTP 403 + error.type=="permission_error"
// （组织/账号层的策略封禁）。403 的限流、过载等其它错误类型不计入。
func DetectAnthropicPermissionError(status int, payload []byte) (bool, string) {
	if status != 403 || len(payload) == 0 || !gjson.ValidBytes(payload) {
		return false, ""
	}
	et := gjson.GetBytes(payload, "error.type").String()
	if !strings.EqualFold(strings.TrimSpace(et), AnthropicRefusalSignalPermissionError) {
		return false, ""
	}
	return true, strings.TrimSpace(gjson.GetBytes(payload, "error.message").String())
}

// markAnthropicRefusalForAccount 补全账号信息后打标记。account 为 nil 时仍记录，
// 便于兜底排查（handler 侧只依赖 Signal）。
func markAnthropicRefusalForAccount(c *gin.Context, account *Account, mark AnthropicRefusalMark) {
	if c == nil {
		return
	}
	if account != nil {
		mark.AccountID = account.ID
		mark.AccountName = account.Name
	}
	MarkAnthropicRefusal(c, mark)
}
