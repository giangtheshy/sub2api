package admin

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// cyberBlockItem 是屏蔽项的对外表示。
// 只暴露脱敏标识（哈希前缀）——原始 X-User-Id / session id 从不离开网关内存。
type cyberBlockItem struct {
	Key       string `json:"key"`
	Kind      string `json:"kind"`
	Masked    string `json:"masked"`
	Signal    string `json:"signal"`
	BlockedAt string `json:"blockedAt"`
	ExpiresAt string `json:"expiresAt"`
}

const cyberBlockTimeLayout = "2006-01-02T15:04:05Z07:00"

func toCyberBlockItems(metas []service.CyberBlockMeta) []cyberBlockItem {
	items := make([]cyberBlockItem, 0, len(metas))
	for _, m := range metas {
		item := cyberBlockItem{
			Key:    m.Key,
			Kind:   m.Kind,
			Masked: m.Masked,
			Signal: m.Signal,
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
// 只读视图：网关未接入或存储不可用时返回空列表，不让风控页整页失败。
func (h *ContentModerationHandler) ListBlocks(c *gin.Context) {
	if h == nil || h.gatewayService == nil {
		response.Success(c, []cyberBlockItem{})
		return
	}
	metas, err := h.gatewayService.ListActiveBlocks(c.Request.Context())
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
