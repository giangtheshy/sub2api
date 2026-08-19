//go:build unit

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newCyberBlockTestCache(t *testing.T) (*gatewayCache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return &gatewayCache{rdb: rdb}, mr
}

func TestCyberSessionBlockMeta_SetListDelete(t *testing.T) {
	ctx := context.Background()
	cache, _ := newCyberBlockTestCache(t)

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, cache.SetCyberSessionBlockedMeta(ctx, "key-a", service.CyberBlockMeta{
		Key: "key-a", Kind: "x_user_id", Masked: "abc123", Signal: "refusal", BlockedAt: now,
	}, time.Hour))
	require.NoError(t, cache.SetCyberSessionBlockedMeta(ctx, "key-b", service.CyberBlockMeta{
		Key: "key-b", Kind: "session", Masked: "def456", Signal: "permission_error", BlockedAt: now,
	}, time.Hour))

	// 写入 meta 后，既有的存在性查询必须照常工作（向后兼容）。
	blocked, err := cache.IsCyberSessionBlocked(ctx, "key-a")
	require.NoError(t, err)
	require.True(t, blocked)

	items, err := cache.ListCyberSessionBlocks(ctx)
	require.NoError(t, err)
	require.Len(t, items, 2)

	byKey := map[string]service.CyberBlockMeta{}
	for _, it := range items {
		byKey[it.Key] = it
	}
	require.Equal(t, "x_user_id", byKey["key-a"].Kind)
	require.Equal(t, "abc123", byKey["key-a"].Masked)
	require.Equal(t, "permission_error", byKey["key-b"].Signal)
	require.False(t, byKey["key-a"].ExpiresAt.IsZero(), "list must expose when the block lapses")

	require.NoError(t, cache.DeleteCyberSessionBlock(ctx, "key-a"))
	blocked, err = cache.IsCyberSessionBlocked(ctx, "key-a")
	require.NoError(t, err)
	require.False(t, blocked, "unblock must take effect immediately")

	items, err = cache.ListCyberSessionBlocks(ctx)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "key-b", items[0].Key)
}

// TTL 过期的条目不得再出现在列表里，且索引要被顺带清理，避免无限增长。
func TestCyberSessionBlockMeta_ExpiredEntriesDropOut(t *testing.T) {
	ctx := context.Background()
	cache, mr := newCyberBlockTestCache(t)

	require.NoError(t, cache.SetCyberSessionBlockedMeta(ctx, "short", service.CyberBlockMeta{
		Key: "short", Kind: "session", Signal: "refusal", BlockedAt: time.Now(),
	}, time.Minute))
	require.NoError(t, cache.SetCyberSessionBlockedMeta(ctx, "long", service.CyberBlockMeta{
		Key: "long", Kind: "session", Signal: "refusal", BlockedAt: time.Now(),
	}, time.Hour))

	mr.FastForward(2 * time.Minute)

	items, err := cache.ListCyberSessionBlocks(ctx)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "long", items[0].Key)

	// 索引里的死条目必须被清掉（惰性回收）。
	members, err := cache.rdb.SMembers(ctx, cyberSessionBlockIndexKey).Result()
	require.NoError(t, err)
	require.Len(t, members, 1)
}

// 旧版写入（无 meta 的裸标记）不应让列表报错或崩溃。
func TestCyberSessionBlockMeta_LegacyEntriesAreTolerated(t *testing.T) {
	ctx := context.Background()
	cache, _ := newCyberBlockTestCache(t)

	require.NoError(t, cache.SetCyberSessionBlocked(ctx, "legacy", time.Hour))
	items, err := cache.ListCyberSessionBlocks(ctx)
	require.NoError(t, err)
	require.Empty(t, items, "legacy markers carry no metadata and simply do not list")

	blocked, err := cache.IsCyberSessionBlocked(ctx, "legacy")
	require.NoError(t, err)
	require.True(t, blocked, "legacy markers must still block")
}

func TestCyberSessionBlockMeta_DeleteIsIdempotent(t *testing.T) {
	ctx := context.Background()
	cache, _ := newCyberBlockTestCache(t)
	require.NoError(t, cache.DeleteCyberSessionBlock(ctx, "never-existed"))
}
