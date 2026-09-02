package service

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
)

// CyberSessionBlockStore 是 cyber 会话屏蔽表的存取接口。
// repository 层 gatewayCache 附带实现（类型断言探测接入，不改 GatewayCache
// 共享接口）；测试 stub 不实现时屏蔽能力自动降级关闭。
type CyberSessionBlockStore interface {
	SetCyberSessionBlocked(ctx context.Context, key string, ttl time.Duration) error
	IsCyberSessionBlocked(ctx context.Context, key string) (bool, error)
	// SetCyberSessionBlockedMeta 写入屏蔽记录并附带可展示的元信息，
	// 使管理端能列出"当前谁被挡着、因为什么、什么时候解除"。
	SetCyberSessionBlockedMeta(ctx context.Context, key string, meta CyberBlockMeta, ttl time.Duration) error
	// ListCyberSessionBlocks 返回当前仍生效的屏蔽记录（过期的自动不列出）。
	ListCyberSessionBlocks(ctx context.Context) ([]CyberBlockMeta, error)
	// DeleteCyberSessionBlock 人工解封，幂等。
	DeleteCyberSessionBlock(ctx context.Context, key string) error
}

// CyberBlockMeta 是一条屏蔽记录的可展示元信息。
//
// 标识分两层：Masked 是 key 哈希的短前缀（不可逆，唯一标识这条记录）；
// MaskedUserID/MaskedSessionID 是原始信号的部分遮蔽串（如 usr_*******c21），
// 让管理员在客户申诉时能比对首尾确认主体。完整的原始 X-User-Id / session id
// 仍然绝不落库。
//
// UserID/APIKeyID 是屏蔽范围所属的平台侧主体；UserEmail/APIKeyName 在写入时
// 一并快照。刻意存冗余而不是列表时反查：屏蔽表是 Redis 缓存，管理端列表不该
// 为了两个展示字段而对每条记录打 DB；且快照保留了"当时是谁"，即使之后用户或
// Key 被删除，管理员仍能看懂这条记录。
type CyberBlockMeta struct {
	Key             string    `json:"key"`
	Kind            string    `json:"kind"`
	Masked          string    `json:"masked"`
	Signal          string    `json:"signal"`
	UserID          int64     `json:"userId,omitempty"`
	UserEmail       string    `json:"userEmail,omitempty"`
	APIKeyID        int64     `json:"apiKeyId,omitempty"`
	APIKeyName      string    `json:"apiKeyName,omitempty"`
	MaskedUserID    string    `json:"maskedUserId,omitempty"`
	MaskedSessionID string    `json:"maskedSessionId,omitempty"`
	BlockedAt       time.Time `json:"blockedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

// CyberSessionBlockKey 派生屏蔽 key，委托 StickyIdentity 组合派生：
// (apiKey, user) 始终参与，再叠加请求级信号 X-User-Id 与显式会话
// （header session_id/conversation_id 或 body prompt_cache_key）。
//
// 两点与最初实现不同：
//  1. 不再对"无显式会话标识"的请求返回空串——空串等于放行，
//     违规方只要不带 session 头就能绕开屏蔽表；
//  2. 不再"挑一层用"，而是组合所有可用信号，把屏蔽范围收到最窄。
//     转售场景下这是硬要求：一个终端客户违规不能连坐整把 Key。
//
// 开关默认关闭，行为变化只在启用会话屏蔽时生效。
func CyberSessionBlockKey(apiKeyID, userID int64, c *gin.Context, body []byte) string {
	_, _, key := StickyIdentity(apiKeyID, userID, c, body)
	return key
}

// CyberSessionBlockMeta 派生屏蔽 key 并一并组装管理端展示所需的元信息。
//
// 与 CyberSessionBlockKey 派生同一把 key，区别只是多带回主体归属（用户、Key）
// 与部分遮蔽的原始标识。OpenAI/Codex 路径用它替代裸 key，
// 使这些路径产生的屏蔽项在管理端与 Anthropic 原生路径展示一致。
//
// apiKey 可为 nil（调用方尚未认证完成时），此时只留下请求级信号。
func CyberSessionBlockMeta(apiKey *APIKey, c *gin.Context, body []byte) CyberBlockMeta {
	var apiKeyID, userID int64
	var apiKeyName, userEmail string
	if apiKey != nil {
		apiKeyID = apiKey.ID
		apiKeyName = apiKey.Name
		userID = apiKey.UserID
		if apiKey.User != nil {
			if userID == 0 {
				userID = apiKey.User.ID
			}
			userEmail = apiKey.User.Email
		}
	}
	info := StickyIdentityDetailed(apiKeyID, userID, c, body)
	return CyberBlockMeta{
		Key:             info.Key,
		Kind:            info.Kind,
		Masked:          info.Masked,
		UserID:          userID,
		UserEmail:       userEmail,
		APIKeyID:        apiKeyID,
		APIKeyName:      apiKeyName,
		MaskedUserID:    info.MaskedUserID,
		MaskedSessionID: info.MaskedSessionID,
	}
}

// cyberSessionBlockStore 探测 cache 是否具备屏蔽存储能力。
// 注意：若未来以装饰器包装 GatewayCache（如日志/指标装饰器），该装饰器必须同时实现
// CyberSessionBlockStore，否则会话屏蔽能力将静默降级关闭
// （编译断言 var _ service.CyberSessionBlockStore = (*gatewayCache)(nil) 只覆盖
// *gatewayCache 本体，无法覆盖其外层包装）。
func (s *OpenAIGatewayService) cyberSessionBlockStore() CyberSessionBlockStore {
	if s == nil || s.cache == nil {
		return nil
	}
	store, ok := s.cache.(CyberSessionBlockStore)
	if !ok {
		return nil
	}
	return store
}

// CyberSessionBlockRuntime 返回 (开关, TTL)。开关默认关。
// 委托给 SettingService.GetCyberSessionBlockRuntime，进程内缓存避免热路径 DB 往返。
func (s *OpenAIGatewayService) CyberSessionBlockRuntime(ctx context.Context) (bool, time.Duration) {
	if s == nil || s.settingService == nil {
		return false, time.Hour
	}
	return s.settingService.GetCyberSessionBlockRuntime(ctx)
}

// MarkCyberSessionBlocked 把会话写入屏蔽表（写入点：cyber 命中后）。
// 开关关闭、key 为空或存储不可用时静默跳过。
//
// 统一走带 meta 的写入，使 OpenAI/Codex 路径产生的屏蔽项同样能在管理端列出、
// 手动解除——否则运维只能干等 TTL 到期。信号固定为 cyber_policy。
func (s *OpenAIGatewayService) MarkCyberSessionBlocked(ctx context.Context, key string) {
	s.MarkCyberSessionBlockedWithMeta(ctx, key, CyberBlockMeta{Signal: "cyber_policy"})
}

// MarkCyberSessionBlockedWithMeta 写入屏蔽项并附带管理端展示所需的元信息
// （命中层级、脱敏标识、信号类型、自动解除时间）。
// 开关关闭、key 为空或存储不可用时静默跳过（屏蔽是增强防护，不阻断主链路）。
func (s *OpenAIGatewayService) MarkCyberSessionBlockedWithMeta(ctx context.Context, key string, meta CyberBlockMeta) {
	if key == "" {
		return
	}
	enabled, ttl := s.CyberSessionBlockRuntime(ctx)
	if !enabled {
		return
	}
	store := s.cyberSessionBlockStore()
	if store == nil {
		return
	}
	now := time.Now()
	meta.Key = key
	if meta.Kind == "" {
		meta.Kind = "unknown"
	}
	if meta.Masked == "" {
		// key 本身已是 sha256 十六进制串，取前缀即可作为不可逆的展示标识。
		meta.Masked = key
		if len(meta.Masked) > 12 {
			meta.Masked = meta.Masked[:12]
		}
	}
	if meta.BlockedAt.IsZero() {
		meta.BlockedAt = now
	}
	meta.ExpiresAt = now.Add(ttl)
	if err := store.SetCyberSessionBlockedMeta(ctx, key, meta, ttl); err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session block meta write failed: err=%v", err)
	}
}

// IsCyberSessionBlocked 查询会话是否被屏蔽（拦截点）。开关关闭、key 为空、
// 存储不可用或查询出错时返回 false（fail-open：屏蔽是增强防护，不阻断主链路）。
func (s *OpenAIGatewayService) IsCyberSessionBlocked(ctx context.Context, key string) bool {
	if key == "" {
		return false
	}
	enabled, _ := s.CyberSessionBlockRuntime(ctx)
	if !enabled {
		return false
	}
	store := s.cyberSessionBlockStore()
	if store == nil {
		return false
	}
	blocked, err := store.IsCyberSessionBlocked(ctx, key)
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session block read failed: err=%v", err)
		return false
	}
	return blocked
}
