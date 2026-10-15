package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strconv"
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

	// [FORK-BAN-SCOPE] 行为变更：无 X-User-Id、无会话 → 不产出 (apiKey,user) 层 key。
	// 该 key 覆盖转售商整把 Key 的全部终端用户；此类请求只靠 transcript key 屏蔽。
	c5, b5 := newCyberBlockTestCtx(nil, `{"input":"hello world"}`)
	require.Empty(t, CyberSessionBlockKey(101, 7, c5, b5), "apikey_user tier must never be a cyber block key")

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

func TestCyberSessionExplicitBlockKey(t *testing.T) {
	c1, b1 := newCyberBlockTestCtx(map[string]string{"session_id": "sess-abc"}, `{}`)
	k1 := CyberSessionExplicitBlockKey(101, c1, b1)
	require.NotEmpty(t, k1)

	// apiKey isolation: same session under another key must not collide.
	c2, b2 := newCyberBlockTestCtx(map[string]string{"session_id": "sess-abc"}, `{}`)
	require.NotEqual(t, k1, CyberSessionExplicitBlockKey(202, c2, b2))

	// Same session + same apiKey → stable key.
	c3, b3 := newCyberBlockTestCtx(map[string]string{"session_id": "sess-abc"}, `{}`)
	require.Equal(t, k1, CyberSessionExplicitBlockKey(101, c3, b3))

	// prompt_cache_key in body counts as explicit.
	c4, b4 := newCyberBlockTestCtx(nil, `{"prompt_cache_key":"pck-1"}`)
	require.NotEmpty(t, CyberSessionExplicitBlockKey(101, c4, b4))

	// No explicit signal at all → empty (this variant intentionally does not
	// fall back; the (apiKey,user) fallback lives in CyberSessionBlockKey).
	c5, b5 := newCyberBlockTestCtx(nil, `{"input":"hello"}`)
	require.Empty(t, CyberSessionExplicitBlockKey(101, c5, b5))

	// conversation_id header counts as explicit; key is stable and non-empty.
	c6, b6 := newCyberBlockTestCtx(map[string]string{"conversation_id": "conv-xyz"}, `{}`)
	k6 := CyberSessionExplicitBlockKey(101, c6, b6)
	require.NotEmpty(t, k6)
	c6b, b6b := newCyberBlockTestCtx(map[string]string{"conversation_id": "conv-xyz"}, `{}`)
	require.Equal(t, k6, CyberSessionExplicitBlockKey(101, c6b, b6b), "conversation_id key must be stable")
}

func TestCyberTranscriptBlockKeysRequireModelGeneratedHistory(t *testing.T) {
	first := []byte(`{"instructions":"shared","input":[{"role":"user","content":"fixed environment"},{"role":"user","content":"question one"}]}`)
	second := []byte(`{"instructions":"shared","input":[{"role":"user","content":"fixed environment"},{"role":"user","content":"question two"}]}`)
	firstKeys := CyberSessionTranscriptBlockKeys(77, "", first)
	secondKeys := CyberSessionTranscriptBlockKeys(77, "", second)
	require.Len(t, firstKeys, 1)
	require.Len(t, secondKeys, 1)
	require.NotEqual(t, firstKeys[0], secondKeys[0])

	hit := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"}]}`)
	continuation := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"different trigger"},{"role":"assistant","content":"blocked"},{"role":"user","content":"continue"}]}`)
	hitKeys := CyberSessionTranscriptBlockKeys(77, "", hit)
	require.Len(t, hitKeys, 2)
	require.Contains(t, CyberSessionTranscriptLookupKeys(77, "", continuation), hitKeys[1])
}

func TestCyberTranscriptBlockKeysWebSocketResponseCreate(t *testing.T) {
	body := []byte(`{"type":"response.create","response":{"prompt_cache_key":"ws-session","input":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"}]}}`)
	c, _ := newCyberBlockTestCtx(nil, string(body))
	require.NotEmpty(t, CyberSessionExplicitBlockKey(88, c, body))
	require.Len(t, CyberSessionTranscriptBlockKeys(88, "", body), 2)
}

func TestCyberTranscriptLookupKeysAreBoundedAndKeepNewestOrder(t *testing.T) {
	messages := make([]map[string]string, maxOpenAICyberTranscriptLookupKeys+44)
	for i := range messages {
		messages[i] = map[string]string{"role": "user", "content": "message-" + strconv.Itoa(i)}
	}
	body, err := json.Marshal(map[string]any{"messages": messages})
	require.NoError(t, err)

	keys := CyberSessionTranscriptLookupKeys(77, "", body)
	require.Len(t, keys, maxOpenAICyberTranscriptLookupKeys)

	firstRetainedBody, err := json.Marshal(map[string]any{"messages": messages[:45]})
	require.NoError(t, err)
	firstRetainedPrefix := CyberSessionTranscriptLookupKeys(77, "", firstRetainedBody)
	require.Equal(t, firstRetainedPrefix[len(firstRetainedPrefix)-1], keys[0])

	fullKey := CyberSessionTranscriptBlockKeys(77, "", body)[0]
	require.Equal(t, fullKey, keys[len(keys)-1])
}

// --- fakes ---

type fakeCyberBlockStore struct {
	blocked   map[string]bool
	scopes    map[string]bool
	findCalls int
	meta      map[string]CyberBlockMeta
	listErr   error
}

var _ CyberSessionBlockStore = (*fakeCyberBlockStore)(nil)

func (f *fakeCyberBlockStore) SetCyberSessionBlocked(_ context.Context, scopeKey string, keys []string, _ time.Duration) error {
	if f.blocked == nil {
		f.blocked = map[string]bool{}
	}
	for _, key := range keys {
		f.blocked[key] = true
	}
	if scopeKey != "" {
		if f.scopes == nil {
			f.scopes = map[string]bool{}
		}
		f.scopes[scopeKey] = true
	}
	return nil
}

func (f *fakeCyberBlockStore) IsCyberSessionScopeActive(_ context.Context, scopeKey string) (bool, error) {
	return f.scopes[scopeKey], nil
}

func (f *fakeCyberBlockStore) FindCyberSessionBlocked(_ context.Context, keys []string) (string, error) {
	f.findCalls++
	for _, key := range keys {
		if f.blocked[key] {
			return key, nil
		}
	}
	return "", nil
}

func (f *fakeCyberBlockStore) SetCyberSessionBlockedMeta(_ context.Context, scopeKey string, keys []string, meta CyberBlockMeta, _ time.Duration) error {
	if len(keys) == 0 {
		return nil
	}
	if f.blocked == nil {
		f.blocked = map[string]bool{}
	}
	if f.meta == nil {
		f.meta = map[string]CyberBlockMeta{}
	}
	for _, key := range keys {
		f.blocked[key] = true
	}
	if scopeKey != "" {
		if f.scopes == nil {
			f.scopes = map[string]bool{}
		}
		f.scopes[scopeKey] = true
	}
	meta.Key = keys[0]
	meta.Keys = keys
	f.meta[keys[0]] = meta
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
	if m, ok := f.meta[key]; ok {
		for _, k := range m.Keys {
			delete(f.blocked, k)
		}
	}
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

func (c *comboCacheAndStore) SetReasoningContent(_ context.Context, _ string, _ string, _ time.Duration) error {
	return nil
}
func (c *comboCacheAndStore) GetReasoningContent(_ context.Context, _ string) (string, error) {
	return "", ErrReasoningContentNotFound
}

func (c *comboCacheAndStore) SetCyberSessionBlocked(ctx context.Context, scopeKey string, keys []string, ttl time.Duration) error {
	return c.store.SetCyberSessionBlocked(ctx, scopeKey, keys, ttl)
}
func (c *comboCacheAndStore) IsCyberSessionScopeActive(ctx context.Context, scopeKey string) (bool, error) {
	return c.store.IsCyberSessionScopeActive(ctx, scopeKey)
}
func (c *comboCacheAndStore) FindCyberSessionBlocked(ctx context.Context, keys []string) (string, error) {
	return c.store.FindCyberSessionBlocked(ctx, keys)
}
func (c *comboCacheAndStore) SetCyberSessionBlockedMeta(ctx context.Context, scopeKey string, keys []string, meta CyberBlockMeta, ttl time.Duration) error {
	return c.store.SetCyberSessionBlockedMeta(ctx, scopeKey, keys, meta, ttl)
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
func TestFindCyberSessionBlocked_EmptyAndNilService(t *testing.T) {
	var nilSvc *OpenAIGatewayService
	require.Empty(t, nilSvc.FindCyberSessionBlockedForRequest(context.Background(), 1, 0, nil, nil, "", ""))
	require.NotPanics(t, func() { nilSvc.MarkCyberSessionBlocked(context.Background(), "", []string{"k"}) })

	svc := &OpenAIGatewayService{}
	require.Empty(t, svc.FindCyberSessionBlockedForRequest(context.Background(), 1, 0, nil, nil, "", ""))
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

	c, body := newCyberBlockTestCtx(map[string]string{"session_id": "sess-roundtrip"}, `{}`)
	explicitKey := CyberSessionExplicitBlockKey(1, c, body)
	require.Empty(t, svc.FindCyberSessionBlockedForRequest(ctx, 1, 0, c, body, "203.0.113.1", "client/1.0"))

	svc.MarkCyberSessionBlocked(ctx, "", []string{explicitKey, testKey})

	require.Equal(t, explicitKey, svc.FindCyberSessionBlockedForRequest(ctx, 1, 0, c, body, "203.0.113.1", "client/1.0"))
}

func TestFindCyberSessionBlockedForRequestUsesScopeForTranscript(t *testing.T) {
	settingSvc := &SettingService{settingRepo: &fakeSettingRepo{vals: map[string]string{
		SettingKeyCyberSessionBlockEnabled:    "true",
		SettingKeyCyberSessionBlockTTLSeconds: "60",
	}}}
	combo := &comboCacheAndStore{}
	svc := &OpenAIGatewayService{cache: combo, settingService: settingSvc}
	ctx := context.Background()

	hitBody := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"}]}`)
	nextBody := []byte(`{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"different trigger"},{"role":"assistant","content":"blocked"},{"role":"user","content":"continue"}]}`)
	nextCtx, _ := newCyberBlockTestCtx(nil, string(nextBody))
	const clientIP = "203.0.113.20"
	const userAgent = "Codex CLI 1.2.3"
	blockKey := CyberSessionTranscriptBlockKeys(9, "", hitBody)[1]

	// Without an active source scope, transcript candidates are never blocks.
	require.Empty(t, svc.FindCyberSessionBlockedForRequest(ctx, 9, 0, nextCtx, nextBody, clientIP, userAgent))
	scopeKey := CyberSessionScopeKey(9, clientIP, userAgent, "")
	svc.MarkCyberSessionBlocked(ctx, scopeKey, []string{blockKey})
	require.Equal(t, blockKey, svc.FindCyberSessionBlockedForRequest(ctx, 9, 0, nextCtx, nextBody, clientIP, "Codex CLI 1.2.4"))
}

func TestFindCyberSessionBlockedForRequestFailsClosedOnScopedTranscriptOverflow(t *testing.T) {
	settingSvc := &SettingService{settingRepo: &fakeSettingRepo{vals: map[string]string{
		SettingKeyCyberSessionBlockEnabled:    "true",
		SettingKeyCyberSessionBlockTTLSeconds: "60",
	}}}
	combo := &comboCacheAndStore{}
	svc := &OpenAIGatewayService{cache: combo, settingService: settingSvc}
	ctx := context.Background()
	const apiKeyID = int64(9)
	const clientIP = "203.0.113.20"
	const userAgent = "Codex CLI 1.2.3"

	messages := make([]map[string]string, maxOpenAICyberTranscriptLookupKeys+1)
	for i := range messages {
		messages[i] = map[string]string{"role": "user", "content": "message-" + strconv.Itoa(i)}
	}
	body, err := json.Marshal(map[string]any{"messages": messages})
	require.NoError(t, err)
	// [FORK-BAN-SCOPE] 行为变更：只有 scope 带 X-User-Id（单个终端用户）时 overflow 才
	// fail-closed；无 X-User-Id 的情形见 TestFindCyberSessionBlockedForRequestOverflowFailsOpenWithoutEndUser。
	c, _ := newCyberBlockTestCtx(map[string]string{"X-User-Id": "end-user-a"}, string(body))
	require.Empty(t, svc.FindCyberSessionBlockedForRequest(ctx, apiKeyID, 0, c, body, clientIP, userAgent),
		"overflow alone must not bypass the scope gate")
	combo.store.scopes = map[string]bool{CyberSessionScopeKey(apiKeyID, clientIP, userAgent, "end-user-a"): true}

	// 精确查找（sticky key + 显式会话 key，最多两把）永远先跑一次，是有界的；
	// 这里要守住的是 overflow 之后不得再发 transcript 那次无界查找。
	before := combo.store.findCalls
	require.Equal(t, cyberSessionTranscriptLookupOverflowBlockKey,
		svc.FindCyberSessionBlockedForRequest(ctx, apiKeyID, 0, c, body, clientIP, userAgent))
	require.Equal(t, before+1, combo.store.findCalls, "overflow must not issue an unbounded Redis lookup")
}

func TestCyberSessionScopeKeyNormalizesUserAgentVersion(t *testing.T) {
	base := CyberSessionScopeKey(7, "203.0.113.10", "Codex CLI 1.2.3", "")
	require.NotEmpty(t, base)
	require.Equal(t, base, CyberSessionScopeKey(7, "203.0.113.10", "Codex CLI 1.2.4", ""))
	require.NotEqual(t, base, CyberSessionScopeKey(8, "203.0.113.10", "Codex CLI 1.2.3", ""))
	require.NotEqual(t, base, CyberSessionScopeKey(7, "203.0.113.11", "Codex CLI 1.2.3", ""))
}
