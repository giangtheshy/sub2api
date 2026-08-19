package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// 屏蔽标识由"所有可用信号"组合而成，而不是挑一层用。
// 组合得越细，误伤面越小——这对转售场景是硬性要求：
// 一个转售商的某个终端客户违规，不能把整把 API Key 连坐掉。
func TestStickyIdentity_CombinesUserAndSession(t *testing.T) {
	c, b := newCyberBlockTestCtx(map[string]string{
		"X-User-Id":  "u123",
		"session_id": "sess-abc",
	}, `{}`)

	kind, masked, key := StickyIdentity(101, 55, c, b)
	require.Equal(t, StickyIdentityKindXUserIDSession, kind)
	require.NotEmpty(t, key)
	require.NotEmpty(t, masked)
	require.NotContains(t, masked, "u123", "raw identity must never leak into the masked form")
	require.NotContains(t, masked, "sess-abc")

	// 换会话 → 换 key：屏蔽范围收窄到"这个客户的这次会话"。
	c2, b2 := newCyberBlockTestCtx(map[string]string{
		"X-User-Id":  "u123",
		"session_id": "sess-other",
	}, `{}`)
	_, _, key2 := StickyIdentity(101, 55, c2, b2)
	require.NotEqual(t, key, key2)

	// 换终端用户 → 换 key。
	c3, b3 := newCyberBlockTestCtx(map[string]string{
		"X-User-Id":  "u999",
		"session_id": "sess-abc",
	}, `{}`)
	_, _, key3 := StickyIdentity(101, 55, c3, b3)
	require.NotEqual(t, key, key3)

	// 换 API Key → 换 key（跨租户隔离）。
	c4, b4 := newCyberBlockTestCtx(map[string]string{
		"X-User-Id":  "u123",
		"session_id": "sess-abc",
	}, `{}`)
	_, _, key4 := StickyIdentity(202, 55, c4, b4)
	require.NotEqual(t, key, key4)

	// 完全相同的输入 → 稳定同一把 key。
	c5, b5 := newCyberBlockTestCtx(map[string]string{
		"X-User-Id":  "u123",
		"session_id": "sess-abc",
	}, `{}`)
	_, _, key5 := StickyIdentity(101, 55, c5, b5)
	require.Equal(t, key, key5)
}

// 转售场景的核心保证：同一把 Key 下的不同终端客户互不牵连。
func TestStickyIdentity_ResellerCustomersAreIsolated(t *testing.T) {
	const apiKeyID, userID = 101, 55

	// 客户 A 违规（带 X-User-Id，无显式会话）。
	ca, ba := newCyberBlockTestCtx(map[string]string{"X-User-Id": "cust-a"}, `{}`)
	_, _, keyA := StickyIdentity(apiKeyID, userID, ca, ba)

	// 客户 B 正常请求，必须拿到不同的 key。
	cb, bb := newCyberBlockTestCtx(map[string]string{"X-User-Id": "cust-b"}, `{}`)
	_, _, keyB := StickyIdentity(apiKeyID, userID, cb, bb)
	require.NotEqual(t, keyA, keyB, "one customer's block must never spill onto another customer of the same reseller")

	// 转售商自己不带任何标识的请求，也不能撞上客户 A 的屏蔽。
	cc, bc := newCyberBlockTestCtx(nil, `{}`)
	_, _, keyPlain := StickyIdentity(apiKeyID, userID, cc, bc)
	require.NotEqual(t, keyA, keyPlain)
}

// 同一客户的不同会话彼此隔离（会话级颗粒度）。
func TestStickyIdentity_SessionsOfSameCustomerAreIsolated(t *testing.T) {
	c1, b1 := newCyberBlockTestCtx(map[string]string{"X-User-Id": "cust-a", "session_id": "s1"}, `{}`)
	_, _, k1 := StickyIdentity(101, 55, c1, b1)
	c2, b2 := newCyberBlockTestCtx(map[string]string{"X-User-Id": "cust-a", "session_id": "s2"}, `{}`)
	_, _, k2 := StickyIdentity(101, 55, c2, b2)
	require.NotEqual(t, k1, k2)
}

func TestStickyIdentity_SessionOnly(t *testing.T) {
	c, b := newCyberBlockTestCtx(map[string]string{"session_id": "sess-abc"}, `{}`)
	kind, _, key := StickyIdentity(101, 55, c, b)
	require.Equal(t, StickyIdentityKindSession, kind)
	require.NotEmpty(t, key)

	// prompt_cache_key 同样算显式会话信号。
	c2, b2 := newCyberBlockTestCtx(nil, `{"prompt_cache_key":"pck-1"}`)
	kind2, _, key2 := StickyIdentity(101, 55, c2, b2)
	require.Equal(t, StickyIdentityKindSession, kind2)
	require.NotEmpty(t, key2)
	require.NotEqual(t, key, key2)
}

func TestStickyIdentity_XUserIDOnly(t *testing.T) {
	c, b := newCyberBlockTestCtx(map[string]string{"X-User-Id": "u123"}, `{}`)
	kind, _, key := StickyIdentity(101, 55, c, b)
	require.Equal(t, StickyIdentityKindXUserID, kind)
	require.NotEmpty(t, key)

	c2, b2 := newCyberBlockTestCtx(map[string]string{"X-User-Id": "u123"}, `{"input":"different content"}`)
	_, _, key2 := StickyIdentity(101, 55, c2, b2)
	require.Equal(t, key, key2, "request content must not affect the key")
}

// 兜底层：没有任何标识时仍然可屏蔽（旧实现在这里返回空串 = 直接放行）。
// 代价是范围回到整把 Key——没有信息可用来分辨是谁，这是无法回避的。
func TestStickyIdentity_FallsBackToAPIKeyUser(t *testing.T) {
	c, b := newCyberBlockTestCtx(nil, `{"input":"hello world"}`)
	kind, _, key := StickyIdentity(101, 55, c, b)
	require.Equal(t, StickyIdentityKindAPIKeyUser, kind)
	require.NotEmpty(t, key, "no-signal requests must still get a stable key (closes the bypass hole)")

	c2, b2 := newCyberBlockTestCtx(nil, `{"input":"totally different content"}`)
	_, _, key2 := StickyIdentity(101, 55, c2, b2)
	require.Equal(t, key, key2, "fallback key must not depend on request content")

	c3, b3 := newCyberBlockTestCtx(nil, `{}`)
	_, _, key3 := StickyIdentity(101, 66, c3, b3)
	require.NotEqual(t, key, key3)
}

// 不同层级里出现相同原始串时不得碰撞（层级标签参与哈希）。
func TestStickyIdentity_KindsAreDisjoint(t *testing.T) {
	cx, bx := newCyberBlockTestCtx(map[string]string{"X-User-Id": "same"}, `{}`)
	_, _, kx := StickyIdentity(101, 55, cx, bx)
	cs, bs := newCyberBlockTestCtx(map[string]string{"session_id": "same"}, `{}`)
	_, _, ks := StickyIdentity(101, 55, cs, bs)
	require.NotEqual(t, kx, ks)
}

func TestStickyIdentity_NilContext(t *testing.T) {
	kind, _, key := StickyIdentity(101, 55, nil, nil)
	require.Equal(t, StickyIdentityKindAPIKeyUser, kind)
	require.NotEmpty(t, key, "nil context must still yield a usable key, never an empty one")
}
