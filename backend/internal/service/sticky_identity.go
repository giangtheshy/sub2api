package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

// 屏蔽标识的命中层级，用于管理端展示与排障。
// 标识由"所有可用信号的组合"派生，因此存在组合层级。
const (
	// StickyIdentityKindXUserIDSession：同时拿到终端用户与会话标识——颗粒度最细。
	StickyIdentityKindXUserIDSession = "x_user_id+session"
	// StickyIdentityKindXUserID：只有客户端声明的终端用户（X-User-Id）。
	StickyIdentityKindXUserID = "x_user_id"
	// StickyIdentityKindSession：只有显式会话标识（session_id/conversation_id/prompt_cache_key）。
	StickyIdentityKindSession = "session"
	// StickyIdentityKindAPIKeyUser：无任何请求级标识，只能落到 (apiKey, user)。
	// 永远可用，保证"不带标识"的请求也有稳定 key，堵住返回空串即放行的漏洞；
	// 代价是屏蔽范围等于整把 Key——没有信息可用来分辨是谁。
	StickyIdentityKindAPIKeyUser = "apikey_user"
)

// stickyIdentityUserHeaders 是终端用户标识头，按优先级排列。
// 与 Anthropic/OpenAI 生态常见约定一致（X-User-Id 为主）。
var stickyIdentityUserHeaders = []string{"X-User-Id", "X-User-ID", "x-user-id"}

// StickyIdentity 派生请求的"违规主体"标识。
//
// 关键设计：把所有可用信号 **组合** 进同一把 key，而不是挑一层用。
// 转售场景是硬约束——一把 API Key 背后可能有成百上千个终端客户，
// 若按 (apiKey,user) 一刀切，某个客户违规就会连坐整个转售商。
// 组合后，屏蔽只落在"这把 Key 的这个客户的这次会话"上。
//
// 代价是刻意接受的：换会话即可摆脱屏蔽。屏蔽只是给账号池减压的即时防线，
// 真正的惩罚走风控日志的违规计数与自动封禁（按用户累计，换会话逃不掉）。
//
// 返回值：
//   - kind：参与派生的信号组合，用于管理端展示；
//   - masked：可安全展示的短摘要（哈希前缀），绝不含原始标识；
//   - key：屏蔽表主键，sha256(kind|apiKeyID|userID|signals…)，永不为空。
func StickyIdentity(apiKeyID, userID int64, c *gin.Context, body []byte) (kind string, masked string, key string) {
	xUserID := ""
	if c != nil {
		for _, header := range stickyIdentityUserHeaders {
			if v := strings.TrimSpace(c.GetHeader(header)); v != "" {
				xUserID = v
				break
			}
		}
	}
	sessionID := explicitOpenAISessionID(c, body)

	var signals strings.Builder
	switch {
	case xUserID != "" && sessionID != "":
		kind = StickyIdentityKindXUserIDSession
		fmt.Fprintf(&signals, "x:%s|s:%s", xUserID, sessionID)
	case xUserID != "":
		kind = StickyIdentityKindXUserID
		fmt.Fprintf(&signals, "x:%s", xUserID)
	case sessionID != "":
		kind = StickyIdentityKindSession
		fmt.Fprintf(&signals, "s:%s", sessionID)
	default:
		// 无请求级信号：只能按 (apiKey,user) 兜底。内容不参与派生，
		// 避免同一主体换个提问就换一把 key。
		kind = StickyIdentityKindAPIKeyUser
	}

	// apiKeyID/userID 始终混入：跨 Key、跨用户隔离，
	// 不同租户即使用同一个 session_id 也不会互相牵连。
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|k%d|u%d|%s", kind, apiKeyID, userID, signals.String())))
	key = hex.EncodeToString(sum[:])
	return kind, key[:12], key
}
