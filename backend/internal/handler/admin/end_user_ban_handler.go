package admin

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// endUserBanItem 是终端用户封禁项的对外表示。
//
// 与 cyberBlockItem 的区别：没有 expiresAt（永久封禁，不会自动解除），
// 多了 violationCount（管理员判断是否误封的主要依据）。
// 同样只暴露脱敏标识——原始 X-User-Id 从不离开网关内存。
type endUserBanItem struct {
	Identity       string `json:"identity"`
	Masked         string `json:"masked"`
	ViolationCount int    `json:"violationCount"`
	Reason         string `json:"reason"`
	BannedAt       string `json:"bannedAt"`
}

func toEndUserBanItems(metas []service.EndUserBanMeta) []endUserBanItem {
	items := make([]endUserBanItem, 0, len(metas))
	for _, m := range metas {
		item := endUserBanItem{
			Identity:       m.Identity,
			Masked:         m.Masked,
			ViolationCount: m.ViolationCount,
			Reason:         m.Reason,
		}
		if !m.BannedAt.IsZero() {
			item.BannedAt = m.BannedAt.UTC().Format(cyberBlockTimeLayout)
		}
		items = append(items, item)
	}
	return items
}

// ListEndUserBans 返回当前被永久封禁的终端用户
// （GET /admin/risk-control/end-user-bans）。
// 只读视图：存储不可用时返回空列表，不让风控页整页失败。
func (h *ContentModerationHandler) ListEndUserBans(c *gin.Context) {
	if h == nil || h.service == nil {
		response.Success(c, []endUserBanItem{})
		return
	}
	metas, err := h.service.ListBannedEndUsers(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, toEndUserBanItems(metas))
}

// UnbanEndUser 手动解封一个终端用户
// （DELETE /admin/risk-control/end-user-bans/:identity）。
// 写操作：失败必须明确回报，管理员才知道按钮有没有生效。
func (h *ContentModerationHandler) UnbanEndUser(c *gin.Context) {
	identity := strings.TrimSpace(c.Param("identity"))
	if identity == "" {
		response.BadRequest(c, "Invalid end user identity")
		return
	}
	if h == nil || h.service == nil {
		response.BadRequest(c, "End user ban store is unavailable")
		return
	}
	result, err := h.service.UnbanEndUser(c.Request.Context(), identity)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

// ClearEndUserBans 清空终端用户封禁表
// （DELETE /admin/risk-control/end-user-bans/all）。
func (h *ContentModerationHandler) ClearEndUserBans(c *gin.Context) {
	if h == nil || h.service == nil {
		response.BadRequest(c, "End user ban store is unavailable")
		return
	}
	result, err := h.service.ClearBannedEndUsers(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
