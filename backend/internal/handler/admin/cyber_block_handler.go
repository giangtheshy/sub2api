package admin

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// cyberBlockItem 是屏蔽项的对外表示。
//
// 标识分三层，供管理员由粗到细定位：userEmail/apiKeyName 是平台侧主体；
// maskedUserId/maskedSessionId 是部分遮蔽的终端标识（可与客户申诉时提供的
// ID 比对首尾）；masked/key 是不可逆哈希。完整的原始终端标识从不离开网关。
type cyberBlockItem struct {
	Key             string `json:"key"`
	Kind            string `json:"kind"`
	Masked          string `json:"masked"`
	Signal          string `json:"signal"`
	UserID          int64  `json:"userId,omitempty"`
	UserEmail       string `json:"userEmail,omitempty"`
	APIKeyID        int64  `json:"apiKeyId,omitempty"`
	APIKeyName      string `json:"apiKeyName,omitempty"`
	MaskedUserID    string `json:"maskedUserId,omitempty"`
	MaskedSessionID string `json:"maskedSessionId,omitempty"`
	BlockedAt       string `json:"blockedAt"`
	ExpiresAt       string `json:"expiresAt"`
}

const cyberBlockTimeLayout = "2006-01-02T15:04:05Z07:00"

func toCyberBlockItems(metas []service.CyberBlockMeta) []cyberBlockItem {
	items := make([]cyberBlockItem, 0, len(metas))
	for _, m := range metas {
		item := cyberBlockItem{
			Key:             m.Key,
			Kind:            m.Kind,
			Masked:          m.Masked,
			Signal:          m.Signal,
			UserID:          m.UserID,
			UserEmail:       m.UserEmail,
			APIKeyID:        m.APIKeyID,
			APIKeyName:      m.APIKeyName,
			MaskedUserID:    m.MaskedUserID,
			MaskedSessionID: m.MaskedSessionID,
		}
		if !m.BlockedAt.IsZero() {
			item.BlockedAt = m.BlockedAt.UTC().Format(cyberBlockTimeLayout)
		}
		if !m.ExpiresAt.IsZero() {
			item.ExpiresAt = m.ExpiresAt.UTC().Format(cyberBlockTimeLayout)
		}
		items = append(items, item)
	}
	return items
}

// ListBlocks 返回当前生效的会话屏蔽项（GET /admin/risk-control/blocks）。
// 支持 ?search= 按邮箱 / API Key 名称 / 遮蔽标识过滤。
// 只读视图：网关未接入或存储不可用时返回空列表，不让风控页整页失败。
func (h *ContentModerationHandler) ListBlocks(c *gin.Context) {
	if h == nil || h.gatewayService == nil {
		response.Success(c, []cyberBlockItem{})
		return
	}
	search := strings.TrimSpace(c.Query("search"))
	metas, err := h.gatewayService.ListActiveBlocksFiltered(c.Request.Context(), search)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, toCyberBlockItems(metas))
}

// Unblock 手动解除一个屏蔽项（DELETE /admin/risk-control/blocks/:key）。
// 写操作：失败必须明确回报，管理员才知道按钮有没有生效。
func (h *ContentModerationHandler) Unblock(c *gin.Context) {
	key := strings.TrimSpace(c.Param("key"))
	if key == "" {
		response.BadRequest(c, "Invalid block key")
		return
	}
	if h == nil || h.gatewayService == nil {
		response.BadRequest(c, "Session block store is unavailable")
		return
	}
	if err := h.gatewayService.UnblockIdentity(c.Request.Context(), key); err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"key": key, "unblocked": true})
}
