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
