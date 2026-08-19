package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func newCyberBlockAdminService(enabled string) (*OpenAIGatewayService, *comboCacheAndStore) {
	combo := &comboCacheAndStore{}
	svc := &OpenAIGatewayService{
		cache: combo,
		settingService: &SettingService{
			settingRepo: &fakeSettingRepo{vals: map[string]string{
				SettingKeyCyberSessionBlockEnabled:    enabled,
				SettingKeyCyberSessionBlockTTLSeconds: "60",
			}},
		},
	}
	return svc, combo
}

func TestListActiveBlocks_ReturnsMarkedIdentities(t *testing.T) {
	ctx := context.Background()
	svc, _ := newCyberBlockAdminService("true")

	svc.MarkCyberSessionBlockedWithMeta(ctx, "k1", CyberBlockMeta{
		Kind: StickyIdentityKindXUserID, Masked: "abc123", Signal: AnthropicRefusalSignalRefusal,
	})

	items, err := svc.ListActiveBlocks(ctx)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "k1", items[0].Key)
	require.Equal(t, StickyIdentityKindXUserID, items[0].Kind)
	require.Equal(t, "abc123", items[0].Masked)
	require.False(t, items[0].ExpiresAt.IsZero(), "operators need the auto-expiry time")
	require.True(t, svc.IsCyberSessionBlocked(ctx, "k1"))
}

func TestUnblockIdentity_RemovesBlock(t *testing.T) {
	ctx := context.Background()
	svc, _ := newCyberBlockAdminService("true")
	svc.MarkCyberSessionBlockedWithMeta(ctx, "k1", CyberBlockMeta{Kind: StickyIdentityKindSession})
	require.True(t, svc.IsCyberSessionBlocked(ctx, "k1"))

	require.NoError(t, svc.UnblockIdentity(ctx, "k1"))
	require.False(t, svc.IsCyberSessionBlocked(ctx, "k1"))

	items, err := svc.ListActiveBlocks(ctx)
	require.NoError(t, err)
	require.Empty(t, items)
}

// 开关关闭时不写入——屏蔽是可选增强，关掉就该完全静默。
func TestMarkCyberSessionBlockedWithMeta_RespectsDisabledSwitch(t *testing.T) {
	ctx := context.Background()
	svc, _ := newCyberBlockAdminService("false")
	svc.MarkCyberSessionBlockedWithMeta(ctx, "k1", CyberBlockMeta{Kind: StickyIdentityKindSession})

	items, err := svc.ListActiveBlocks(ctx)
	require.NoError(t, err)
	require.Empty(t, items)
}

// 列举是只读的运维视图：存储缺失时返回空而非报错，不该让管理页崩掉。
func TestListActiveBlocks_FailsSafeWithoutStore(t *testing.T) {
	ctx := context.Background()
	var nilSvc *OpenAIGatewayService
	items, err := nilSvc.ListActiveBlocks(ctx)
	require.NoError(t, err)
	require.Empty(t, items)

	items, err = (&OpenAIGatewayService{}).ListActiveBlocks(ctx)
	require.NoError(t, err)
	require.Empty(t, items)
}

// 解封相反：调用方按了按钮，必须得到明确成败，不能假装成功。
func TestUnblockIdentity_ReportsErrors(t *testing.T) {
	ctx := context.Background()
	require.Error(t, (&OpenAIGatewayService{}).UnblockIdentity(ctx, "k1"), "no store → explicit error")

	svc, _ := newCyberBlockAdminService("true")
	require.Error(t, svc.UnblockIdentity(ctx, "  "), "empty key → explicit error")
}

func TestListActiveBlocks_PropagatesStoreError(t *testing.T) {
	ctx := context.Background()
	svc, combo := newCyberBlockAdminService("true")
	combo.store.listErr = errors.New("redis down")

	_, err := svc.ListActiveBlocks(ctx)
	require.Error(t, err)
}
