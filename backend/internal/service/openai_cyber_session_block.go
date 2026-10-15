package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
)

// CyberSessionBlockStore 是 cyber 会话屏蔽表的存取接口。
// repository 层 gatewayCache 附带实现（类型断言探测接入，不改 GatewayCache
// 共享接口）；测试 stub 不实现时屏蔽能力自动降级关闭。
type CyberSessionBlockStore interface {
	SetCyberSessionBlocked(ctx context.Context, scopeKey string, keys []string, ttl time.Duration) error
	IsCyberSessionScopeActive(ctx context.Context, scopeKey string) (bool, error)
	FindCyberSessionBlocked(ctx context.Context, keys []string) (string, error)
	// SetCyberSessionBlockedMeta 写入屏蔽记录并附带可展示的元信息，
	// 使管理端能列出"当前谁被挡着、因为什么、什么时候解除"。
	// keys 是本条记录写入的全部屏蔽 key（上游多 key 模型），meta 只挂在
	// keys[0] 这把规范 key 上，解封时按 meta.Keys 一并清理。
	SetCyberSessionBlockedMeta(ctx context.Context, scopeKey string, keys []string, meta CyberBlockMeta, ttl time.Duration) error
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
	// Keys 是本条记录实际写入的全部屏蔽 key。上游把一次命中展开成多把 key
	// （显式会话 key + transcript 前缀 key + 本地 sticky key），管理端解封
	// 必须按这份清单全部删掉，只删规范 key 会留下仍在拦截的孤儿条目。
	Keys []string `json:"keys,omitempty"`
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
//
// [FORK-BAN-SCOPE] apikey_user 层（无 X-User-Id、无会话）返回空串：该层 key 等于
// 整把 Key，转售商的所有终端用户共用，绝不能写入或查询。
func CyberSessionBlockKey(apiKeyID, userID int64, c *gin.Context, body []byte) string {
	kind, _, key := StickyIdentity(apiKeyID, userID, c, body)
	if !IsPerEndUserStickyKind(kind) {
		return ""
	}
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
	// [FORK-BAN-SCOPE] apikey_user 层不产出 Key（=整把 Key 连坐）；此时只剩
	// transcript key 可写，Kind 标成 transcript 让管理端看清屏蔽范围。
	if !IsPerEndUserStickyKind(info.Kind) {
		info.Key = ""
		info.Masked = ""
		info.Kind = StickyIdentityKindTranscript
	}
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

const cyberSessionTranscriptLookupOverflowBlockKey = "transcript_lookup_limit_exceeded"

// CyberSessionExplicitBlockKey returns an inexpensive exact key when the
// client supplies a stable session signal.
//
// [FORK-BAN-SCOPE] 有 X-User-Id 时必须混入：转售商可能给所有终端用户用同一个
// session_id/prompt_cache_key，不混入就会一人违规封掉整把 Key。无 X-User-Id 时
// 保持上游原始派生（hash(apiKey, session)）。
func CyberSessionExplicitBlockKey(apiKeyID int64, c *gin.Context, body []byte) string {
	sessionID := explicitOpenAISessionID(c, body)
	if sessionID == "" {
		return ""
	}
	if endUserID := CyberBlockEndUserID(c); endUserID != "" {
		sessionID = "x_user_id=" + endUserID + "|session=" + sessionID
	}
	return hashCyberSessionBlockKey(apiKeyID, sessionID)
}

// CyberSessionTranscriptBlockKeys returns the exact full-request key followed
// by an optional rewrite-tolerant context key. The latter is emitted only after
// model-generated history has been observed.
//
// [FORK-BAN-SCOPE] endUserID（X-User-Id，见 CyberBlockEndUserID）参与派生；写入侧与
// CyberSessionTranscriptLookupKeys 读取侧必须传同一个值。
func CyberSessionTranscriptBlockKeys(apiKeyID int64, endUserID string, body []byte) []string {
	derived := deriveOpenAICyberTranscriptBlockKeys(apiKeyID, endUserID, body)
	if len(derived.lookupKeys) == 0 {
		return nil
	}
	keys := []string{derived.lookupKeys[len(derived.lookupKeys)-1]}
	if derived.preLatestUserKey != "" && derived.preLatestUserKey != keys[0] {
		keys = append(keys, derived.preLatestUserKey)
	}
	return keys
}

func CyberSessionTranscriptLookupKeys(apiKeyID int64, endUserID string, body []byte) []string {
	return deriveOpenAICyberTranscriptBlockKeys(apiKeyID, endUserID, body).lookupKeys
}

// CyberSessionScopeKey is a coarse, non-blocking fingerprint used only to
// avoid transcript parsing and MGET for sources that never produced a hit.
//
// [FORK-BAN-SCOPE] endUserID（X-User-Id）参与派生：转售商的所有终端用户共享同一
// IP+UA，不混入的话一个用户命中就会激活所有人的 scope。会话刻意不混入——transcript
// key 本就是为了抵抗"换 session id 重放同一段历史"。写读两侧必须传同一个值。
func CyberSessionScopeKey(apiKeyID int64, clientIP, userAgent, endUserID string) string {
	if apiKeyID <= 0 {
		return ""
	}
	raw := "cyber-scope:v1|api_key=" + strconv.FormatInt(apiKeyID, 10) +
		"|ip=" + strings.TrimSpace(clientIP) +
		"|ua=" + NormalizeSessionUserAgent(userAgent)
	if endUserID = strings.TrimSpace(endUserID); endUserID != "" {
		raw += "|x_user_id=" + endUserID
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func hashCyberSessionBlockKey(apiKeyID int64, raw string) string {
	if raw == "" {
		return ""
	}
	isolated := isolateOpenAISessionID(apiKeyID, raw)
	sum := sha256.Sum256([]byte(isolated))
	return hex.EncodeToString(sum[:])
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
// 开关关闭、keys 为空或存储不可用时静默跳过。
//
// 统一走带 meta 的写入，使 OpenAI/Codex 路径产生的屏蔽项同样能在管理端列出、
// 手动解除——否则运维只能干等 TTL 到期。信号固定为 cyber_policy。
func (s *OpenAIGatewayService) MarkCyberSessionBlocked(ctx context.Context, scopeKey string, keys []string) {
	s.MarkCyberSessionBlockedWithMeta(ctx, scopeKey, keys, CyberBlockMeta{Signal: "cyber_policy"})
}

// MarkCyberSessionBlockedWithMeta 写入屏蔽项并附带管理端展示所需的元信息
// （命中层级、脱敏标识、信号类型、自动解除时间）。
//
// 一次命中会展开成多把 key（显式会话 key、transcript 前缀 key、本地 sticky
// key），全部写入拦截表；meta 只挂在 keys[0] 这把规范 key 上，并记下完整
// key 清单供解封时一并清理。
// 开关关闭、keys 为空或存储不可用时静默跳过（屏蔽是增强防护，不阻断主链路）。
func (s *OpenAIGatewayService) MarkCyberSessionBlockedWithMeta(ctx context.Context, scopeKey string, keys []string, meta CyberBlockMeta) {
	if s == nil {
		return
	}
	keys = dropAPIKeyWideCyberBlockKey(keys, &meta)
	keys = dedupeCyberSessionKeys(keys)
	if len(keys) == 0 {
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
	key := keys[0]
	meta.Key = key
	meta.Keys = keys
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
	if err := store.SetCyberSessionBlockedMeta(ctx, scopeKey, keys, meta, ttl); err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session block meta write failed: err=%v", err)
	}
}

// dropAPIKeyWideCyberBlockKey 是写入侧的最后一道闸。
//
// [FORK-BAN-SCOPE] 调用方若递进来 apikey_user 层的 key（例如合并上游后又直接用
// StickyIdentity 的 key），这里把它剔除：该 key 覆盖整把 Key 的所有终端用户。
func dropAPIKeyWideCyberBlockKey(keys []string, meta *CyberBlockMeta) []string {
	if meta == nil || meta.Kind != StickyIdentityKindAPIKeyUser {
		return keys
	}
	wide := meta.Key
	meta.Kind = StickyIdentityKindTranscript
	meta.Key = ""
	meta.Masked = ""
	if wide == "" {
		return keys
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != wide {
			out = append(out, k)
		}
	}
	return out
}

// dedupeCyberSessionKeys 去空去重并保持顺序，keys[0] 因此稳定地是调用方给出的
// 第一把 key——meta 挂在它身上，去重不能打乱这个次序。
func dedupeCyberSessionKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// IsCyberSessionBlocked 单 key 查询（Anthropic 原生链路用：那条路径的 key 由
// StickyIdentity 组合派生，不走上游的 explicit/transcript 两段式查找）。
// 开关关闭、key 为空、存储不可用或查询出错时返回 false（fail-open）。
func (s *OpenAIGatewayService) IsCyberSessionBlocked(ctx context.Context, key string) bool {
	if s == nil || key == "" {
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
	hit, err := store.FindCyberSessionBlocked(ctx, []string{key})
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session block read failed: err=%v", err)
		return false
	}
	return hit != ""
}

// FindCyberSessionBlockedForRequest applies explicit-first lookup followed by
// scope-gated transcript matching. All failures remain fail-open.
func (s *OpenAIGatewayService) FindCyberSessionBlockedForRequest(ctx context.Context, apiKeyID, userID int64, c *gin.Context, body []byte, clientIP, userAgent string) string {
	enabled, _ := s.CyberSessionBlockRuntime(ctx)
	if !enabled {
		return ""
	}
	store := s.cyberSessionBlockStore()
	if store == nil {
		return ""
	}
	// [FORK-BAN-SCOPE] CyberSessionBlockKey 对 apikey_user 层返回空串，不查整把 Key 的 key。
	// 廉价的精确查找先行：本地 sticky key（(apiKey,user) 叠加 X-User-Id 与显式
	// 会话 ID）与上游的显式会话 key。前者是写入侧的规范 key，必须在这里查，
	// 否则 Anthropic 原生链路写下的屏蔽项在 OpenAI/Codex 链路上查不到。
	exact := dedupeCyberSessionKeys([]string{
		CyberSessionBlockKey(apiKeyID, userID, c, body),
		CyberSessionExplicitBlockKey(apiKeyID, c, body),
	})
	if len(exact) > 0 {
		key, err := store.FindCyberSessionBlocked(ctx, exact)
		if err != nil {
			logger.LegacyPrintf("service.openai_gateway", "cyber explicit session read failed: err=%v", err)
			return ""
		}
		if key != "" {
			return key
		}
	}
	// [FORK-BAN-SCOPE] scope/transcript 与写入侧（handler buildCyberSessionBlockWritePlan）
	// 用同一个 X-User-Id 派生，否则同 Key 不同终端用户互相命中。
	endUserID := CyberBlockEndUserID(c)
	scopeKey := CyberSessionScopeKey(apiKeyID, clientIP, userAgent, endUserID)
	active, err := store.IsCyberSessionScopeActive(ctx, scopeKey)
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session scope read failed: err=%v", err)
		return ""
	}
	if !active {
		return ""
	}
	transcript := deriveOpenAICyberTranscriptBlockKeys(apiKeyID, endUserID, body)
	if transcript.lookupKeysTruncated && endUserID != "" {
		// Once the coarse scope is active, silently dropping old candidates would
		// let a blocked client evade prefix matching by appending dummy items.
		// [FORK-BAN-SCOPE] 只有 scope 带 X-User-Id（=单个终端用户）时才 fail-closed；
		// 无 X-User-Id 的 scope 覆盖转售商全部终端用户，此时 fail-open，只查保留的
		// 最近 256 个前缀 key——否则所有长对话都会被 403。
		return cyberSessionTranscriptLookupOverflowBlockKey
	}
	keys := transcript.lookupKeys
	if len(keys) == 0 {
		return ""
	}
	key, err := store.FindCyberSessionBlocked(ctx, keys)
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "cyber session block batch read failed: err=%v", err)
		return ""
	}
	return key
}
