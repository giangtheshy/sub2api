package service

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func endUserBanTestCtx(headers map[string]string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.Request = req
	return c
}

// 没有 X-User-Id 就无从区分终端用户，必须返回空串让调用方跳过本层。
// 这是本功能最重要的安全边界：绝不能退化成"封整把 Key"。
func TestEndUserBanIdentity_EmptyWithoutXUserID(t *testing.T) {
	masked, key := EndUserBanIdentity(42, endUserBanTestCtx(nil))
	require.Empty(t, key, "no X-User-Id must yield no ban identity")
	require.Empty(t, masked)

	// 只有 session 信号也不行——session 不是终端用户。
	masked, key = EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{
		"session_id": "sess-1",
	}))
	require.Empty(t, key, "session alone must not produce a ban identity")
	require.Empty(t, masked)

	masked, key = EndUserBanIdentity(42, nil)
	require.Empty(t, key, "nil context must be safe")
	require.Empty(t, masked)
}

func TestEndUserBanIdentity_DerivesFromXUserID(t *testing.T) {
	masked, key := EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{
		"X-User-Id": "customer-a",
	}))
	require.Len(t, key, 64, "key must be a full sha256 hex string")
	require.Equal(t, key[:12], masked, "masked must be the hash prefix")
	require.NotContains(t, key, "customer-a", "raw X-User-Id must never appear in the key")
}

// 换会话不能解封——这正是会话屏蔽做不到、本层必须做到的事。
func TestEndUserBanIdentity_StableAcrossSessions(t *testing.T) {
	_, first := EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{
		"X-User-Id":  "customer-a",
		"session_id": "sess-1",
	}))
	_, second := EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{
		"X-User-Id":  "customer-a",
		"session_id": "sess-2",
	}))
	_, none := EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{
		"X-User-Id": "customer-a",
	}))

	require.Equal(t, first, second, "changing session must NOT change the ban identity")
	require.Equal(t, first, none, "session must not participate in the ban identity at all")
}

// 转售商轮换/新增 Key 是常规操作；若 Key 参与派生，换 Key 就能解封。
func TestEndUserBanIdentity_StableAcrossAPIKeys(t *testing.T) {
	c := endUserBanTestCtx(map[string]string{"X-User-Id": "customer-a"})
	_, key := EndUserBanIdentity(42, c)

	// 同一个 userID 下无论用哪把 Key，标识都必须一致。签名里本就没有 apiKeyID，
	// 这条测试锁住该设计，防止后来者"顺手"把它加回去。
	_, sameUserAgain := EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{
		"X-User-Id": "customer-a",
	}))
	require.Equal(t, key, sameUserAgain)
}

func TestEndUserBanIdentity_IsolatesTenantsAndCustomers(t *testing.T) {
	_, customerA := EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{"X-User-Id": "customer-a"}))
	_, customerB := EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{"X-User-Id": "customer-b"}))
	require.NotEqual(t, customerA, customerB,
		"different end users under the same reseller must not collide")

	_, otherTenant := EndUserBanIdentity(43, endUserBanTestCtx(map[string]string{"X-User-Id": "customer-a"}))
	require.NotEqual(t, customerA, otherTenant,
		"same X-User-Id under a different reseller must not collide")
}

// 两套 key 用途不同（永久封禁 vs TTL 冷却），绝不能互相命中。
func TestEndUserBanIdentity_NeverCollidesWithStickyIdentity(t *testing.T) {
	headers := map[string]string{"X-User-Id": "customer-a"}
	_, banKey := EndUserBanIdentity(42, endUserBanTestCtx(headers))
	_, _, stickyKey := StickyIdentity(0, 42, endUserBanTestCtx(headers), nil)
	require.NotEqual(t, banKey, stickyKey,
		"ban key and session-block key must live in separate spaces")
}

func TestEndUserBanIdentity_AcceptsHeaderCaseVariants(t *testing.T) {
	_, canonical := EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{"X-User-Id": "customer-a"}))
	for _, header := range []string{"X-User-ID", "x-user-id"} {
		_, variant := EndUserBanIdentity(42, endUserBanTestCtx(map[string]string{header: "customer-a"}))
		require.Equal(t, canonical, variant, "%s must resolve to the same identity", header)
	}
}
