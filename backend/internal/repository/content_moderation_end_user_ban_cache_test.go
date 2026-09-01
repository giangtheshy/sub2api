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

func newEndUserBanCacheTest(t *testing.T) (*contentModerationEndUserBanCache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return &contentModerationEndUserBanCache{rdb: rdb}, mr
}

func TestEndUserBanCache_BanThenIsBanned(t *testing.T) {
	ctx := context.Background()
	cache, _ := newEndUserBanCacheTest(t)

	require.NoError(t, cache.BanEndUser(ctx, "identity-a", service.EndUserBanMeta{ViolationCount: 2}))

	banned, err := cache.IsEndUserBanned(ctx, "identity-a")
	require.NoError(t, err)
	require.True(t, banned)

	banned, err = cache.IsEndUserBanned(ctx, "identity-b")
	require.NoError(t, err)
	require.False(t, banned, "an unrelated identity must not be reported as banned")
}

// 与会话屏蔽表最本质的区别：没有 TTL。
func TestEndUserBanCache_HasNoTTL(t *testing.T) {
	ctx := context.Background()
	cache, mr := newEndUserBanCacheTest(t)

	require.NoError(t, cache.BanEndUser(ctx, "identity-a", service.EndUserBanMeta{}))
	mr.FastForward(365 * 24 * time.Hour)

	banned, err := cache.IsEndUserBanned(ctx, "identity-a")
	require.NoError(t, err)
	require.True(t, banned, "end-user bans must survive indefinitely without admin action")
}

func TestEndUserBanCache_UnbanIsIdempotent(t *testing.T) {
	ctx := context.Background()
	cache, _ := newEndUserBanCacheTest(t)

	require.NoError(t, cache.BanEndUser(ctx, "identity-a", service.EndUserBanMeta{}))

	deleted, err := cache.UnbanEndUser(ctx, "identity-a")
	require.NoError(t, err)
	require.True(t, deleted)

	deleted, err = cache.UnbanEndUser(ctx, "identity-a")
	require.NoError(t, err)
	require.False(t, deleted, "unbanning an already-unbanned identity must not error")

	banned, err := cache.IsEndUserBanned(ctx, "identity-a")
	require.NoError(t, err)
	require.False(t, banned)
}

func TestEndUserBanCache_ListReturnsMetaWithMasked(t *testing.T) {
	ctx := context.Background()
	cache, _ := newEndUserBanCacheTest(t)

	longIdentity := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	require.NoError(t, cache.BanEndUser(ctx, longIdentity, service.EndUserBanMeta{
		ViolationCount: 3,
		Reason:         "block",
	}))

	items, err := cache.ListBannedEndUsers(ctx)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, longIdentity, items[0].Identity)
	require.Equal(t, longIdentity[:12], items[0].Masked, "masked must be the hash prefix, never the full identity display")
	require.Equal(t, 3, items[0].ViolationCount)
	require.False(t, items[0].BannedAt.IsZero())
}

func TestEndUserBanCache_ListEmptyReturnsNilNotError(t *testing.T) {
	ctx := context.Background()
	cache, _ := newEndUserBanCacheTest(t)

	items, err := cache.ListBannedEndUsers(ctx)
	require.NoError(t, err)
	require.Empty(t, items)
}

func TestEndUserBanCache_ClearRemovesAllAndReturnsCount(t *testing.T) {
	ctx := context.Background()
	cache, _ := newEndUserBanCacheTest(t)

	require.NoError(t, cache.BanEndUser(ctx, "identity-a", service.EndUserBanMeta{}))
	require.NoError(t, cache.BanEndUser(ctx, "identity-b", service.EndUserBanMeta{}))

	deleted, err := cache.ClearBannedEndUsers(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2), deleted)

	items, err := cache.ListBannedEndUsers(ctx)
	require.NoError(t, err)
	require.Empty(t, items)
}

func TestEndUserBanCache_BanIsIdempotentOverwrite(t *testing.T) {
	ctx := context.Background()
	cache, _ := newEndUserBanCacheTest(t)

	require.NoError(t, cache.BanEndUser(ctx, "identity-a", service.EndUserBanMeta{ViolationCount: 1}))
	require.NoError(t, cache.BanEndUser(ctx, "identity-a", service.EndUserBanMeta{ViolationCount: 5}))

	items, err := cache.ListBannedEndUsers(ctx)
	require.NoError(t, err)
	require.Len(t, items, 1, "re-banning the same identity must overwrite, not duplicate")
	require.Equal(t, 5, items[0].ViolationCount)
}
