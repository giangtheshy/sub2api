package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrCyberBlockStoreUnavailable 表示屏蔽表存储不可用（未接 Redis 或缓存实现不支持）。
var ErrCyberBlockStoreUnavailable = errors.New("cyber session block store unavailable")

// ListActiveBlocks 返回当前生效的屏蔽记录，按屏蔽时间倒序（最近的排在最前）。
//
// 读侧 fail-safe：存储不可用时返回空列表而非错误——管理页只是少了一块信息，
// 不该整页报错。写侧（UnblockIdentity）相反：管理员点了解封就必须知道成败。
func (s *OpenAIGatewayService) ListActiveBlocks(ctx context.Context) ([]CyberBlockMeta, error) {
	if s == nil {
		return nil, nil
	}
	store := s.cyberSessionBlockStore()
	if store == nil {
		return nil, nil
	}
	items, err := store.ListCyberSessionBlocks(ctx)
	if err != nil {
		return nil, fmt.Errorf("list cyber session blocks: %w", err)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].BlockedAt.After(items[j].BlockedAt)
	})
	return items, nil
}

// ListActiveBlocksFiltered 返回按 search 过滤后的屏蔽记录。search 为空时返回全部。
//
// 过滤在内存中完成：屏蔽表是 TTL 缓存（默认 1 小时），同一时刻的条目量很小，
// 没有分页或索引的必要。归属字段在写入时已快照进 meta，这里无需反查 DB。
func (s *OpenAIGatewayService) ListActiveBlocksFiltered(ctx context.Context, search string) ([]CyberBlockMeta, error) {
	metas, err := s.ListActiveBlocks(ctx)
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(strings.TrimSpace(search))
	if needle == "" {
		return metas, nil
	}
	filtered := make([]CyberBlockMeta, 0, len(metas))
	for _, m := range metas {
		if cyberBlockMatches(m, needle) {
			filtered = append(filtered, m)
		}
	}
	return filtered, nil
}

// cyberBlockMatches 判断一条记录是否命中搜索词。needle 必须已小写化。
// 覆盖管理员手头可能有的所有线索：邮箱、Key 名称、遮蔽后的终端标识、哈希前缀。
func cyberBlockMatches(m CyberBlockMeta, needle string) bool {
	candidates := [...]string{
		m.UserEmail,
		m.APIKeyName,
		m.MaskedUserID,
		m.MaskedSessionID,
		m.Masked,
		m.Key,
	}
	for _, c := range candidates {
		if c != "" && strings.Contains(strings.ToLower(c), needle) {
			return true
		}
	}
	return false
}

// UnblockIdentity 人工解封一个标识。幂等：解封不存在的 key 也算成功。
func (s *OpenAIGatewayService) UnblockIdentity(ctx context.Context, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("cyber block key is required")
	}
	if s == nil {
		return ErrCyberBlockStoreUnavailable
	}
	store := s.cyberSessionBlockStore()
	if store == nil {
		return ErrCyberBlockStoreUnavailable
	}
	if err := store.DeleteCyberSessionBlock(ctx, key); err != nil {
		return fmt.Errorf("delete cyber session block: %w", err)
	}
	return nil
}
