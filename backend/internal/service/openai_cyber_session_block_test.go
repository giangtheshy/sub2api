package service

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func newCyberBlockTestCtx(headers map[string]string, body string) (*gin.Context, []byte) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/openai/v1/responses", strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.Request = req
	return c, []byte(body)
}

// TestCyberSessionBlockKey verifies the tiered key derivation (delegated to
// StickyIdentity): X-User-Id → explicit session → (apiKey,user) fallback.
// apiKey isolation is preserved; unlike the original F5a behaviour the key is
// NEVER empty — a request without any explicit signal used to bypass blocking
// entirely, which is exactly the hole this closes.
func TestCyberSessionBlockKey(t *testing.T) {
	c1, b1 := newCyberBlockTestCtx(map[string]string{"session_id": "sess-abc"}, `{}`)
	k1 := CyberSessionBlockKey(101, 0, c1, b1)
	require.NotEmpty(t, k1)

	// Same session, different apiKey → different key (isolation).
	c2, b2 := newCyberBlockTestCtx(map[string]string{"session_id": "sess-abc"}, `{}`)
	require.NotEqual(t, k1, CyberSessionBlockKey(202, 0, c2, b2))

	// Same session + same apiKey → stable key.
	c3, b3 := newCyberBlockTestCtx(map[string]string{"session_id": "sess-abc"}, `{}`)
	require.Equal(t, k1, CyberSessionBlockKey(101, 0, c3, b3))

	// prompt_cache_key in body counts as explicit.
	c4, b4 := newCyberBlockTestCtx(nil, `{"prompt_cache_key":"pck-1"}`)
	require.NotEmpty(t, CyberSessionBlockKey(101, 0, c4, b4))

	// No explicit signal → still a stable key from the (apiKey,user) tier.
	c5, b5 := newCyberBlockTestCtx(nil, `{"input":"hello world"}`)
	k5 := CyberSessionBlockKey(101, 7, c5, b5)
	require.NotEmpty(t, k5, "no-session requests must no longer bypass the block table")
	c5b, b5b := newCyberBlockTestCtx(nil, `{"input":"different content"}`)
	require.Equal(t, k5, CyberSessionBlockKey(101, 7, c5b, b5b))
	require.NotEqual(t, k1, k5)

	// X-User-Id 与 session 组合派生：多一个信号 → 另一把更细的 key。
	c7, b7 := newCyberBlockTestCtx(map[string]string{"X-User-Id": "u9", "session_id": "sess-abc"}, `{}`)
	k7 := CyberSessionBlockKey(101, 0, c7, b7)
	require.NotEqual(t, k1, k7)
	c7b, b7b := newCyberBlockTestCtx(map[string]string{"X-User-Id": "u9", "session_id": "sess-zzz"}, `{}`)
	require.NotEqual(t, k7, CyberSessionBlockKey(101, 0, c7b, b7b),
		"a block must stay scoped to one conversation of one end user")

	// 转售隔离：同一把 Key 下不同终端客户绝不能共用屏蔽 key。
	c8, b8 := newCyberBlockTestCtx(map[string]string{"X-User-Id": "cust-a"}, `{}`)
	c9, b9 := newCyberBlockTestCtx(map[string]string{"X-User-Id": "cust-b"}, `{}`)
	require.NotEqual(t, CyberSessionBlockKey(101, 7, c8, b8), CyberSessionBlockKey(101, 7, c9, b9),
		"blocking one reseller customer must not block the whole reseller key")

	// conversation_id header counts as explicit; key is stable and non-empty.
	c6, b6 := newCyberBlockTestCtx(map[string]string{"conversation_id": "conv-xyz"}, `{}`)
	k6 := CyberSessionBlockKey(101, 0, c6, b6)
	require.NotEmpty(t, k6)
	c6b, b6b := newCyberBlockTestCtx(map[string]string{"conversation_id": "conv-xyz"}, `{}`)
	require.Equal(t, k6, CyberSessionBlockKey(101, 0, c6b, b6b), "conversation_id key must be stable")
}

// --- fakes ---

type fakeCyberBlockStore struct {
	blocked map[string]bool
	meta    map[string]CyberBlockMeta
	listErr error
}

var _ CyberSessionBlockStore = (*fakeCyberBlockStore)(nil)

func (f *fakeCyberBlockStore) SetCyberSessionBlocked(_ context.Context, key string, _ time.Duration) error {
	if f.blocked == nil {
		f.blocked = map[string]bool{}
	}
	f.blocked[key] = true
	return nil
}

func (f *fakeCyberBlockStore) IsCyberSessionBlocked(_ context.Context, key string) (bool, error) {
	return f.blocked[key], nil
}

func (f *fakeCyberBlockStore) SetCyberSessionBlockedMeta(_ context.Context, key string, meta CyberBlockMeta, _ time.Duration) error {
	if f.blocked == nil {
		f.blocked = map[string]bool{}
	}
	if f.meta == nil {
		f.meta = map[string]CyberBlockMeta{}
	}
	f.blocked[key] = true
	meta.Key = key
	f.meta[key] = meta
	return nil
}

func (f *fakeCyberBlockStore) ListCyberSessionBlocks(_ context.Context) ([]CyberBlockMeta, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	items := make([]CyberBlockMeta, 0, len(f.meta))
	for _, m := range f.meta {
		items = append(items, m)
	}
	return items, nil
}

func (f *fakeCyberBlockStore) DeleteCyberSessionBlock(_ context.Context, key string) error {
	delete(f.blocked, key)
	delete(f.meta, key)
	return nil
}

// fakeSettingRepo is a minimal SettingRepository stub for unit tests.
// Only GetValue is exercised by GetCyberSessionBlockRuntime; all other methods
// panic so accidental calls are caught immediately.
type fakeSettingRepo struct {
	vals map[string]string
}

func (r *fakeSettingRepo) GetValue(_ context.Context, key string) (string, error) {
	v, ok := r.vals[key]
	if !ok {
		return "", ErrSettingNotFound
	}
	return v, nil
}
func (r *fakeSettingRepo) Get(_ context.Context, _ string) (*Setting, error) {
	panic("fakeSettingRepo.Get not implemented")
}
func (r *fakeSettingRepo) Set(_ context.Context, _, _ string) error {
	panic("fakeSettingRepo.Set not implemented")
}
func (r *fakeSettingRepo) GetMultiple(_ context.Context, _ []string) (map[string]string, error) {
	panic("fakeSettingRepo.GetMultiple not implemented")
}
func (r *fakeSettingRepo) SetMultiple(_ context.Context, _ map[string]string) error {
	panic("fakeSettingRepo.SetMultiple not implemented")
}
func (r *fakeSettingRepo) GetAll(_ context.Context) (map[string]string, error) {
	panic("fakeSettingRepo.GetAll not implemented")
}
func (r *fakeSettingRepo) Delete(_ context.Context, _ string) error {
	panic("fakeSettingRepo.Delete not implemented")
}

var _ SettingRepository = (*fakeSettingRepo)(nil)

// comboCacheAndStore implements both GatewayCache (no-op stubs) and
// CyberSessionBlockStore (delegates to fakeCyberBlockStore) so it can be
// injected as s.cache and successfully type-asserted to CyberSessionBlockStore.
type comboCacheAndStore struct {
	store fakeCyberBlockStore
}

var _ GatewayCache = (*comboCacheAndStore)(nil)
var _ CyberSessionBlockStore = (*comboCacheAndStore)(nil)

func (c *comboCacheAndStore) GetSessionAccountID(_ context.Context, _ int64, _ string) (int64, error) {
	return 0, errors.New("stub")
}
func (c *comboCacheAndStore) SetSessionAccountID(_ context.Context, _ int64, _ string, _ int64, _ time.Duration) error {
	return nil
}
func (c *comboCacheAndStore) RefreshSessionTTL(_ context.Context, _ int64, _ string, _ time.Duration) error {
	return nil
}
func (c *comboCacheAndStore) DeleteSessionAccountID(_ context.Context, _ int64, _ string) error {
	return nil
}

func (c *comboCacheAndStore) SetGrokVideoPendingBilling(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	return nil
}
func (c *comboCacheAndStore) GetGrokVideoPendingBilling(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (c *comboCacheAndStore) ClaimGrokVideoBilled(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return true, nil
}

func (c *comboCacheAndStore) ReleaseGrokVideoBilled(_ context.Context, _ string) error {
	return nil
}

func (c *comboCacheAndStore) SetCyberSessionBlocked(ctx context.Context, key string, ttl time.Duration) error {
	return c.store.SetCyberSessionBlocked(ctx, key, ttl)
}
func (c *comboCacheAndStore) IsCyberSessionBlocked(ctx context.Context, key string) (bool, error) {
	return c.store.IsCyberSessionBlocked(ctx, key)
}
func (c *comboCacheAndStore) SetCyberSessionBlockedMeta(ctx context.Context, key string, meta CyberBlockMeta, ttl time.Duration) error {
	return c.store.SetCyberSessionBlockedMeta(ctx, key, meta, ttl)
}
func (c *comboCacheAndStore) ListCyberSessionBlocks(ctx context.Context) ([]CyberBlockMeta, error) {
	return c.store.ListCyberSessionBlocks(ctx)
}
func (c *comboCacheAndStore) DeleteCyberSessionBlock(ctx context.Context, key string) error {
	return c.store.DeleteCyberSessionBlock(ctx, key)
}

// --- tests ---

// TestIsCyberSessionBlocked_EmptyKeyAndNilService covers the fail-open paths:
// empty key, nil service, store missing → always false / no panic.
func TestIsCyberSessionBlocked_EmptyKeyAndNilService(t *testing.T) {
	var nilSvc *OpenAIGatewayService
	require.False(t, nilSvc.IsCyberSessionBlocked(context.Background(), "k"))
	require.NotPanics(t, func() { nilSvc.MarkCyberSessionBlocked(context.Background(), "k") })

	svc := &OpenAIGatewayService{}
	require.False(t, svc.IsCyberSessionBlocked(context.Background(), ""))
	require.False(t, svc.IsCyberSessionBlocked(context.Background(), "k"), "no store + no settings → fail-open false")
}

// TestCyberSessionBlock_RoundTrip exercises the type-assertion success path:
// mark a session blocked via a combo cache+store, then confirm IsCyberSessionBlocked
// returns true, and an unrelated key returns false.
func TestCyberSessionBlock_RoundTrip(t *testing.T) {
	// SettingService with only settingRepo set — GetCyberSessionBlockRuntime needs
	// nothing else (cfg/proxyRepo/etc. are not touched by this code path).
	settingSvc := &SettingService{
		settingRepo: &fakeSettingRepo{
			vals: map[string]string{
				SettingKeyCyberSessionBlockEnabled:    "true",
				SettingKeyCyberSessionBlockTTLSeconds: "60",
			},
		},
	}

	combo := &comboCacheAndStore{}
	svc := &OpenAIGatewayService{
		cache:          combo,
		settingService: settingSvc,
	}

	ctx := context.Background()
	const testKey = "deadbeef1234"

	// Before marking: not blocked.
	require.False(t, svc.IsCyberSessionBlocked(ctx, testKey))

	// Mark as blocked.
	svc.MarkCyberSessionBlocked(ctx, testKey)

	// After marking: blocked.
	require.True(t, svc.IsCyberSessionBlocked(ctx, testKey))

	// Different key: still not blocked.
	require.False(t, svc.IsCyberSessionBlocked(ctx, "other-key"))
}
