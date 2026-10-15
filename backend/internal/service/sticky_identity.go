package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
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
	// StickyIdentityKindTranscript：没有任何请求级标识，屏蔽只落在 transcript
	// 前缀 key 上（管理端展示用；见 IsPerEndUserStickyKind）。
	StickyIdentityKindTranscript = "transcript"
)

// IsPerEndUserStickyKind 报告该层级的 key 是否能区分"同一把 Key 下的不同终端用户"。
//
// [FORK-BAN-SCOPE] cyber 会话屏蔽绝不能写/读 apikey_user 层的 key：转售商把所有
// 终端用户经同一把 Key 转发，该层 key = hash(apiKey,user) 会一次封掉整把 Key。
// 没有 X-User-Id / 会话时，只允许 transcript key 生效。
func IsPerEndUserStickyKind(kind string) bool {
	switch kind {
	case StickyIdentityKindXUserIDSession, StickyIdentityKindXUserID, StickyIdentityKindSession:
		return true
	default:
		return false
	}
}

// CyberBlockEndUserID 返回客户端声明的终端用户标识（X-User-Id，已 trim），拿不到为空串。
//
// [FORK-BAN-SCOPE] 屏蔽表的写入侧与读取侧必须都经由这里取 X-User-Id 混入
// 显式会话 key / transcript key / scope key，否则同 Key 下的终端用户会互相连坐。
func CyberBlockEndUserID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	for _, header := range stickyIdentityUserHeaders {
		if v := strings.TrimSpace(c.GetHeader(header)); v != "" {
			return v
		}
	}
	return ""
}

// cyberBlockSessionID 解析 cyber 会话屏蔽使用的会话信号。
//
// [FORK-BAN-SCOPE] 先沿用 explicitOpenAISessionID（OpenAI/Codex 显式会话，保持
// 既有 key 不变），再补 Claude Code 会话：X-Claude-Code-Session-Id 头 >
// body metadata.user_id 内的 session。没有这一层时原生 /v1/messages 只能落到
// X-User-Id，用户开新会话也逃不出屏蔽。不得改 explicitOpenAISessionID 本身——
// 它同时决定调度粘性。
func cyberBlockSessionID(c *gin.Context, body []byte) string {
	if c == nil {
		return ""
	}
	if sessionID := explicitOpenAISessionID(c, body); sessionID != "" {
		return sessionID
	}
	if sessionID := ClaudeCodeSessionIDFromHeader(c); sessionID != "" {
		return "cc:" + sessionID
	}
	if len(body) > 0 {
		raw := gjson.GetBytes(body, "metadata.user_id").String()
		if parsed := ParseMetadataUserID(raw); parsed != nil {
			if sessionID := strings.TrimSpace(parsed.SessionID); sessionID != "" {
				// 与 header 同一命名空间：同一会话无论从 header 还是 metadata 取到都同 key。
				return "cc:" + sessionID
			}
		}
	}
	return ""
}

// stickyIdentityUserHeaders 是终端用户标识头，按优先级排列。
// 与 Anthropic/OpenAI 生态常见约定一致（X-User-Id 为主）。
var stickyIdentityUserHeaders = []string{"X-User-Id", "X-User-ID", "x-user-id"}

// maskedIdentityStars 是遮蔽段的固定星号数。
// 固定而非按原长度取——否则展示串长度会泄露原值长度。
const maskedIdentityStars = "*******"

// MaskIdentityValue 把原始标识（X-User-Id / session id）转成可展示的部分遮蔽串。
//
// 目的是"能对账、不能读全"：管理员收到客户申诉时可以比对首尾片段确认是不是同一个人，
// 但屏幕上和 Redis 里都不出现完整的终端用户标识。
//
// 分档保证任何长度都至少遮蔽 4 个字符，短值直接全遮蔽：
//
//	≤4    → 全星号
//	5-8   → 首 1 + 尾 1
//	9-11  → 首 2 + 尾 2
//	≥12   → 首 4 + 尾 4
//
// 按 rune 切分，避免把多字节字符截断成乱码。
func MaskIdentityValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	runes := []rune(v)
	n := len(runes)
	var head, tail int
	switch {
	case n <= 4:
		return strings.Repeat("*", n)
	case n <= 8:
		head, tail = 1, 1
	case n <= 11:
		head, tail = 2, 2
	default:
		head, tail = 4, 4
	}
	return string(runes[:head]) + maskedIdentityStars + string(runes[n-tail:])
}

// StickyIdentityInfo 是一次标识派生的完整结果。
//
// Key/Masked 是不可逆哈希（屏蔽表主键与短摘要）；MaskedUserID/MaskedSessionID
// 是原始信号的部分遮蔽展示串，仅用于管理端排障。原始值本身不在此结构中，
// 也不会离开派生现场。
type StickyIdentityInfo struct {
	Kind            string
	Masked          string
	Key             string
	MaskedUserID    string
	MaskedSessionID string
}

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
	info := StickyIdentityDetailed(apiKeyID, userID, c, body)
	return info.Kind, info.Masked, info.Key
}

// StickyIdentityDetailed 与 StickyIdentity 派生同一把 key，额外返回参与派生的
// 原始信号的部分遮蔽串，供管理端展示"到底是谁被挡了"。
//
// 哈希输入与 StickyIdentity 完全一致——遮蔽串只是附加的展示信息，
// 绝不参与 key 计算，否则历史屏蔽项会全部失配。
func StickyIdentityDetailed(apiKeyID, userID int64, c *gin.Context, body []byte) StickyIdentityInfo {
	xUserID := CyberBlockEndUserID(c)
	// [FORK-BAN-SCOPE] 会话信号含 Claude Code 会话（见 cyberBlockSessionID），
	// 读写两侧都经由本函数派生，保证同一请求得到同一把 key。
	sessionID := cyberBlockSessionID(c, body)

	var kind string
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
	key := hex.EncodeToString(sum[:])
	return StickyIdentityInfo{
		Kind:            kind,
		Masked:          key[:12],
		Key:             key,
		MaskedUserID:    MaskIdentityValue(xUserID),
		MaskedSessionID: MaskIdentityValue(sessionID),
	}
}

// endUserBanIdentityPrefix 让终端用户封禁 key 与 StickyIdentity 的会话屏蔽 key
// 永不碰撞——两者用途不同（永久封禁 vs TTL 冷却），绝不能互相命中。
const endUserBanIdentityPrefix = "end_user"

// EndUserBanIdentity 派生"终端用户"的永久封禁标识。
//
// 与 StickyIdentity 有两处**刻意**不同，都是为了让封禁真正跑不掉：
//
//  1. 不混入 session：一个 session 只是一次会话，换个对话就换 key。
//     会话屏蔽可以接受这种逃逸（它只是冷却），永久封禁不行。
//  2. 不混入 apiKeyID：只用 userID。转售商轮换或新增 Key 是常规操作，
//     若把 Key 混进来，违规方换一把 Key 就解封了。
//
// 只认客户端声明的 X-User-Id。拿不到就返回空串，调用方必须跳过本层而不是
// 退化到 (apiKey,user) 兜底——那等于封掉整把 Key 上的所有终端客户，
// 正是本功能要避免的连坐。
//
// 刻意不采用 metadata.user_id（Claude Code 的 device_id）作为封禁标识：
// 请求经代理转发时，代理的 cloak 层可能把它改写成"每个上游 Key 一个固定值"
// （所有终端用户撞成同一个 → 集体封禁），也可能每次请求随机生成
// （永远累计不到阈值）。两种都会让封禁失准。
//
// 返回值：
//   - masked：可安全展示的短摘要（哈希前缀），绝不含原始标识；
//   - key：封禁表主键，sha256("end_user|u<userID>|x:<X-User-Id>")。
func EndUserBanIdentity(userID int64, c *gin.Context) (masked string, key string) {
	// [FORK-BAN-SCOPE] 与 cyber 屏蔽共用同一个 X-User-Id 解析，避免两处读头逻辑漂移。
	xUserID := CyberBlockEndUserID(c)
	if xUserID == "" {
		return "", ""
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|u%d|x:%s", endUserBanIdentityPrefix, userID, xUserID)))
	key = hex.EncodeToString(sum[:])
	return key[:12], key
}
