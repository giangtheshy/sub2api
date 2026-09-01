package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

// contentModerationBannedEndUsersKey 是终端用户永久封禁表。
//
// 用 HASH 而非 SET（flagged_hashes 用的是 SET）：管理端需要展示"因为什么被封、
// 封了多久、累计几次违规"，这些元信息随 field 一起存，读取时一次 HGetAll 拿全。
//
// **不设 TTL**——这是与会话屏蔽表最本质的区别。会话屏蔽是临时冷却，到点自动放行；
// 本表是处罚，只能管理员手动解除。因此也不需要 cyber_session_block 那样的索引集合
// 来惰性剔除过期成员：这里的成员不会自己消失。
const contentModerationBannedEndUsersKey = "content_moderation:banned_end_users"

type contentModerationEndUserBanCache struct {
	rdb *redis.Client
}

func NewContentModerationEndUserBanCache(rdb *redis.Client) service.ContentModerationEndUserBanStore {
	return &contentModerationEndUserBanCache{rdb: rdb}
}

// BanEndUser 写入封禁记录。幂等：重复封禁同一标识只是覆盖元信息。
func (c *contentModerationEndUserBanCache) BanEndUser(ctx context.Context, identity string, meta service.EndUserBanMeta) error {
	identity = strings.TrimSpace(identity)
	if c == nil || c.rdb == nil || identity == "" {
		return nil
	}
	if meta.Identity == "" {
		meta.Identity = identity
	}
	if meta.Masked == "" {
		meta.Masked = maskEndUserIdentity(identity)
	}
	if meta.BannedAt.IsZero() {
		meta.BannedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal end user ban meta: %w", err)
	}
	return c.rdb.HSet(ctx, contentModerationBannedEndUsersKey, identity, payload).Err()
}

// IsEndUserBanned 查询标识是否在封禁表中（网关拦截点，每请求调用）。
func (c *contentModerationEndUserBanCache) IsEndUserBanned(ctx context.Context, identity string) (bool, error) {
	identity = strings.TrimSpace(identity)
	if c == nil || c.rdb == nil || identity == "" {
		return false, nil
	}
	return c.rdb.HExists(ctx, contentModerationBannedEndUsersKey, identity).Result()
}

// UnbanEndUser 人工解封。幂等：解封不存在的标识返回 false 而非错误。
func (c *contentModerationEndUserBanCache) UnbanEndUser(ctx context.Context, identity string) (bool, error) {
	identity = strings.TrimSpace(identity)
	if c == nil || c.rdb == nil || identity == "" {
		return false, nil
	}
	deleted, err := c.rdb.HDel(ctx, contentModerationBannedEndUsersKey, identity).Result()
	if err != nil {
		return false, err
	}
	return deleted > 0, nil
}

// ListBannedEndUsers 返回全部封禁记录，按封禁时间倒序（最近的在最前）。
// 单条 JSON 损坏时跳过该条而非整体失败——管理页少一行好过整页报错。
func (c *contentModerationEndUserBanCache) ListBannedEndUsers(ctx context.Context) ([]service.EndUserBanMeta, error) {
	if c == nil || c.rdb == nil {
		return nil, nil
	}
	raw, err := c.rdb.HGetAll(ctx, contentModerationBannedEndUsersKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("read end user ban table: %w", err)
	}
	items := make([]service.EndUserBanMeta, 0, len(raw))
	for identity, payload := range raw {
		var meta service.EndUserBanMeta
		if err := json.Unmarshal([]byte(payload), &meta); err != nil {
			continue
		}
		if meta.Identity == "" {
			meta.Identity = identity
		}
		if meta.Masked == "" {
			meta.Masked = maskEndUserIdentity(meta.Identity)
		}
		items = append(items, meta)
	}
	sortEndUserBansByBannedAtDesc(items)
	return items, nil
}

// ClearBannedEndUsers 清空封禁表，返回被清除的条数。
func (c *contentModerationEndUserBanCache) ClearBannedEndUsers(ctx context.Context) (int64, error) {
	if c == nil || c.rdb == nil {
		return 0, nil
	}
	n, err := c.rdb.HLen(ctx, contentModerationBannedEndUsersKey).Result()
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	if err := c.rdb.Del(ctx, contentModerationBannedEndUsersKey).Err(); err != nil {
		return 0, err
	}
	return n, nil
}

// maskEndUserIdentity 取哈希前缀作为展示标识。标识本身已是 sha256 十六进制串，
// 不可逆，取前缀仅为缩短显示长度。
func maskEndUserIdentity(identity string) string {
	if len(identity) > 12 {
		return identity[:12]
	}
	return identity
}

func sortEndUserBansByBannedAtDesc(items []service.EndUserBanMeta) {
	sort.Slice(items, func(i, j int) bool {
		return items[i].BannedAt.After(items[j].BannedAt)
	})
}
