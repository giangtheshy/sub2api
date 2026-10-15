package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// [FORK-BAN-SCOPE] 转售场景回归测试：一把 API Key、同一 IP+UA 背后是很多终端用户
// （以 X-User-Id 区分）。cyber 会话屏蔽只能落在会话或 X-User-Id 上，绝不能落在整把 Key 上。

const (
	forkScopeAPIKeyID = int64(41)
	forkScopeUserID   = int64(4100)
	forkScopeClientIP = "198.51.100.7"
	forkScopeUA       = "reseller-proxy/2.0.1"
)

func newForkScopeCyberService() (*OpenAIGatewayService, *comboCacheAndStore) {
	settingSvc := &SettingService{settingRepo: &fakeSettingRepo{vals: map[string]string{
		SettingKeyCyberSessionBlockEnabled:    "true",
		SettingKeyCyberSessionBlockTTLSeconds: "60",
	}}}
	combo := &comboCacheAndStore{}
	return &OpenAIGatewayService{cache: combo, settingService: settingSvc}, combo
}

// forkScopeMarkLikeHandler 复刻 handler.buildCyberSessionBlockWritePlan 的写入派生，
// 用来验证写读两侧派生一致（handler 侧另有基于真实 plan 的往返测试）。
func forkScopeMarkLikeHandler(t *testing.T, svc *OpenAIGatewayService, c *gin.Context, body []byte) []string {
	t.Helper()
	apiKey := &APIKey{ID: forkScopeAPIKeyID, UserID: forkScopeUserID}
	endUserID := CyberBlockEndUserID(c)
	meta := CyberSessionBlockMeta(apiKey, c, body)
	var keys []string
	if meta.Key != "" {
		keys = append(keys, meta.Key)
	}
	if k := CyberSessionExplicitBlockKey(forkScopeAPIKeyID, c, body); k != "" {
		keys = append(keys, k)
	}
	transcript := CyberSessionTranscriptBlockKeys(forkScopeAPIKeyID, endUserID, body)
	keys = append(keys, transcript...)
	scope := ""
	if len(transcript) > 0 {
		scope = CyberSessionScopeKey(forkScopeAPIKeyID, forkScopeClientIP, forkScopeUA, endUserID)
	}
	svc.MarkCyberSessionBlockedWithMeta(context.Background(), scope, keys, meta)
	return keys
}

func forkScopeFind(svc *OpenAIGatewayService, c *gin.Context, body []byte) string {
	return svc.FindCyberSessionBlockedForRequest(context.Background(), forkScopeAPIKeyID, forkScopeUserID, c, body, forkScopeClientIP, forkScopeUA)
}

func forkScopeLongBody(t *testing.T, tag string) []byte {
	t.Helper()
	messages := make([]map[string]string, maxOpenAICyberTranscriptLookupKeys+10)
	for i := range messages {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		messages[i] = map[string]string{"role": role, "content": tag + "-" + strconv.Itoa(i)}
	}
	body, err := json.Marshal(map[string]any{"messages": messages})
	require.NoError(t, err)
	return body
}

func TestForkBanScope_OtherEndUserOnSameKeyIsNeverBlocked(t *testing.T) {
	const shortChat = `{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"}]}`
	cases := []struct {
		name      string
		headersA  map[string]string
		headersB  map[string]string
		flagged   string
		nextA     string
		requestB  string
		wantAHit  bool
		longNextA bool
		longB     bool
	}{
		{
			name:     "x_user_id exact key",
			headersA: map[string]string{"X-User-Id": "cust-a"},
			headersB: map[string]string{"X-User-Id": "cust-b"},
			flagged:  `{"input":"bad"}`, nextA: `{"input":"anything"}`, requestB: `{"input":"anything"}`,
			wantAHit: true,
		},
		{
			name:     "constant session_id shared by the reseller",
			headersA: map[string]string{"X-User-Id": "cust-a", "session_id": "reseller-constant"},
			headersB: map[string]string{"X-User-Id": "cust-b", "session_id": "reseller-constant"},
			flagged:  `{"input":"bad"}`, nextA: `{"input":"x"}`, requestB: `{"input":"x"}`,
			wantAHit: true,
		},
		{
			name:     "constant prompt_cache_key shared by the reseller",
			headersA: map[string]string{"X-User-Id": "cust-a"},
			headersB: map[string]string{"X-User-Id": "cust-b"},
			flagged:  `{"prompt_cache_key":"pck-constant","input":"bad"}`,
			nextA:    `{"prompt_cache_key":"pck-constant","input":"x"}`,
			requestB: `{"prompt_cache_key":"pck-constant","input":"x"}`,
			wantAHit: true,
		},
		{
			name:     "identical short prompts (transcript keys)",
			headersA: map[string]string{"X-User-Id": "cust-a"},
			headersB: map[string]string{"X-User-Id": "cust-b"},
			flagged:  shortChat, nextA: shortChat, requestB: shortChat,
			wantAHit: true,
		},
		{
			name:      "transcript overflow (>256 items) with active scope",
			headersA:  map[string]string{"X-User-Id": "cust-a"},
			headersB:  map[string]string{"X-User-Id": "cust-b"},
			flagged:   shortChat,
			wantAHit:  true,
			longNextA: true,
			longB:     true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newForkScopeCyberService()
			cFlag, bFlag := newCyberBlockTestCtx(tc.headersA, tc.flagged)
			forkScopeMarkLikeHandler(t, svc, cFlag, bFlag)

			nextA, reqB := []byte(tc.nextA), []byte(tc.requestB)
			if tc.longNextA {
				nextA = forkScopeLongBody(t, "a")
			}
			if tc.longB {
				reqB = forkScopeLongBody(t, "b")
			}
			cA, _ := newCyberBlockTestCtx(tc.headersA, string(nextA))
			cB, _ := newCyberBlockTestCtx(tc.headersB, string(reqB))
			if tc.wantAHit {
				require.NotEmpty(t, forkScopeFind(svc, cA, nextA), "the flagged end user must stay blocked")
			}
			require.Empty(t, forkScopeFind(svc, cB, reqB), "another end user on the same key must not be blocked")
		})
	}
}

// 无 X-User-Id 且 transcript 超限时：scope 覆盖转售商全部终端用户，必须 fail-open。
func TestForkBanScope_OverflowWithoutEndUserFailsOpen(t *testing.T) {
	svc, combo := newForkScopeCyberService()
	const shortChat = `{"messages":[{"role":"user","content":"setup"},{"role":"assistant","content":"ready"},{"role":"user","content":"trigger"}]}`
	cFlag, bFlag := newCyberBlockTestCtx(nil, shortChat)
	forkScopeMarkLikeHandler(t, svc, cFlag, bFlag)
	require.True(t, combo.store.scopes[CyberSessionScopeKey(forkScopeAPIKeyID, forkScopeClientIP, forkScopeUA, "")])

	long := forkScopeLongBody(t, "other")
	cLong, _ := newCyberBlockTestCtx(nil, string(long))
	require.Empty(t, forkScopeFind(svc, cLong, long), "unrelated long conversation must not get the overflow sentinel")

	// fail-open 仍会查保留的最近前缀：直接把最新前缀写入后可命中。
	retained := CyberSessionTranscriptLookupKeys(forkScopeAPIKeyID, "", long)
	svc.MarkCyberSessionBlocked(context.Background(), "", []string{retained[len(retained)-1]})
	require.Equal(t, retained[len(retained)-1], forkScopeFind(svc, cLong, long))
}

// B2：不带任何标识的违规请求不得通过 (apiKey,user) key 封住其他不带标识的请求。
func TestForkBanScope_HeaderlessFlagDoesNotBlockOtherHeaderlessRequests(t *testing.T) {
	svc, combo := newForkScopeCyberService()
	cFlag, bFlag := newCyberBlockTestCtx(nil, `{"input":"bad prompt"}`)
	keys := forkScopeMarkLikeHandler(t, svc, cFlag, bFlag)
	require.NotEmpty(t, keys, "transcript key still blocks the flagged conversation")

	_, _, wideKey := StickyIdentity(forkScopeAPIKeyID, forkScopeUserID, cFlag, bFlag)
	require.False(t, combo.store.blocked[wideKey], "apikey_user key must never be written")
	for _, m := range combo.store.meta {
		require.Equal(t, StickyIdentityKindTranscript, m.Kind)
	}

	cOther, bOther := newCyberBlockTestCtx(nil, `{"input":"innocent question"}`)
	require.Empty(t, forkScopeFind(svc, cOther, bOther))

	// 被标记的同一段内容仍被挡（transcript key）。
	cSame, bSame := newCyberBlockTestCtx(nil, `{"input":"bad prompt"}`)
	require.NotEmpty(t, forkScopeFind(svc, cSame, bSame))
}

// 写入侧最后一道闸：即使调用方递进 apikey_user 层 key，也不会落库。
func TestForkBanScope_MarkDropsAPIKeyWideKey(t *testing.T) {
	svc, combo := newForkScopeCyberService()
	c, b := newCyberBlockTestCtx(nil, `{}`)
	info := StickyIdentityDetailed(forkScopeAPIKeyID, forkScopeUserID, c, b)
	require.Equal(t, StickyIdentityKindAPIKeyUser, info.Kind)
	svc.MarkCyberSessionBlockedWithMeta(context.Background(), "", []string{info.Key, "transcript-key"},
		CyberBlockMeta{Key: info.Key, Kind: info.Kind})
	require.False(t, combo.store.blocked[info.Key])
	require.True(t, combo.store.blocked["transcript-key"])
	require.Equal(t, StickyIdentityKindTranscript, combo.store.meta["transcript-key"].Kind)
}

// B5：Claude Code 会话（X-Claude-Code-Session-Id > metadata.user_id）参与屏蔽标识。
func TestForkBanScope_ClaudeCodeSessionIdentity(t *testing.T) {
	const s1 = "11111111-1111-4111-8111-111111111111"
	const s2 = "22222222-2222-4222-8222-222222222222"
	device := strings.Repeat("ab", 32)
	legacy := func(session string) string {
		return `{"metadata":{"user_id":"user_` + device + `_account__session_` + session + `"},"messages":[]}`
	}
	jsonFmt := func(session string) string {
		inner, _ := json.Marshal(map[string]string{"device_id": device, "account_uuid": "", "session_id": session})
		outer, _ := json.Marshal(map[string]any{"metadata": map[string]string{"user_id": string(inner)}, "messages": []any{}})
		return string(outer)
	}
	apiKey := &APIKey{ID: forkScopeAPIKeyID, UserID: forkScopeUserID}
	metaOf := func(headers map[string]string, body string) CyberBlockMeta {
		c, b := newCyberBlockTestCtx(headers, body)
		return CyberSessionBlockMeta(apiKey, c, b)
	}

	header1 := metaOf(map[string]string{"X-User-Id": "u1", "X-Claude-Code-Session-Id": s1}, `{"messages":[]}`)
	require.Equal(t, StickyIdentityKindXUserIDSession, header1.Kind)
	require.NotEmpty(t, header1.Key)

	cases := []struct {
		name     string
		headers  map[string]string
		body     string
		sameAsS1 bool
	}{
		{"same session via header", map[string]string{"X-User-Id": "u1", "X-Claude-Code-Session-Id": s1}, `{"messages":[{"role":"user","content":"x"}]}`, true},
		{"same session via legacy metadata.user_id", map[string]string{"X-User-Id": "u1"}, legacy(s1), true},
		{"same session via JSON metadata.user_id", map[string]string{"X-User-Id": "u1"}, jsonFmt(s1), true},
		{"header wins over metadata", map[string]string{"X-User-Id": "u1", "X-Claude-Code-Session-Id": s1}, legacy(s2), true},
		{"new session escapes", map[string]string{"X-User-Id": "u1", "X-Claude-Code-Session-Id": s2}, `{"messages":[]}`, false},
		{"new session via metadata escapes", map[string]string{"X-User-Id": "u1"}, legacy(s2), false},
		{"other end user same session", map[string]string{"X-User-Id": "u2", "X-Claude-Code-Session-Id": s1}, `{"messages":[]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := metaOf(tc.headers, tc.body)
			require.Equal(t, StickyIdentityKindXUserIDSession, m.Kind)
			if tc.sameAsS1 {
				require.Equal(t, header1.Key, m.Key)
			} else {
				require.NotEqual(t, header1.Key, m.Key)
			}
		})
	}

	// 只有 Claude Code 会话、无 X-User-Id：会话层，仍是单会话范围（非整把 Key）。
	sessOnly := metaOf(map[string]string{"X-Claude-Code-Session-Id": s1}, `{}`)
	require.Equal(t, StickyIdentityKindSession, sessOnly.Kind)
	require.NotEmpty(t, sessOnly.Key)

	// 永久封禁标识刻意不含会话：同一 X-User-Id 换会话仍是同一个封禁主体。
	c1, _ := newCyberBlockTestCtx(map[string]string{"X-User-Id": "u1", "X-Claude-Code-Session-Id": s1}, `{}`)
	c2, _ := newCyberBlockTestCtx(map[string]string{"X-User-Id": "u1", "X-Claude-Code-Session-Id": s2}, `{}`)
	_, ban1 := EndUserBanIdentity(forkScopeUserID, c1)
	_, ban2 := EndUserBanIdentity(forkScopeUserID, c2)
	require.Equal(t, ban1, ban2)
}

// B3：Anthropic 顶层 system 参与 transcript 派生；Claude Code 的 billing header 块被忽略。
func TestForkBanScope_TranscriptHashesSystemAndIgnoresBillingHeader(t *testing.T) {
	base := `{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.0; cch=%s;"},{"type":"text","text":"You are agent %s","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}`
	format := func(cch, agent string) []byte {
		return []byte(fmt.Sprintf(base, cch, agent))
	}
	k1 := CyberSessionTranscriptBlockKeys(forkScopeAPIKeyID, "", format("aaaaa", "A"))
	k2 := CyberSessionTranscriptBlockKeys(forkScopeAPIKeyID, "", format("bbbbb", "A"))
	k3 := CyberSessionTranscriptBlockKeys(forkScopeAPIKeyID, "", format("aaaaa", "B"))
	require.Equal(t, k1, k2, "per-request billing header must not change the transcript key")
	require.NotEqual(t, k1, k3, "different system prompts must not share a transcript key")

	// X-User-Id 混入：同内容不同终端用户不同 key；空 X-User-Id 与上游派生一致。
	require.NotEqual(t,
		CyberSessionTranscriptBlockKeys(forkScopeAPIKeyID, "u1", format("a", "A")),
		CyberSessionTranscriptBlockKeys(forkScopeAPIKeyID, "u2", format("a", "A")))
}

// C1：403 permission_error 只有在文案指向使用政策违规时才算终端用户违规。
func TestForkBanScope_PermissionErrorOnlyCountsUsagePolicy(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"This request violates our Usage Policy (https://www.anthropic.com/legal/aup)", true},
		{"Request blocked: potential cyber misuse detected", true},
		{"Your organization has been blocked", false},
		{"This organization has been disabled.", false},
		{"Your account has been disabled for violating our Usage Policy", false},
		{"This credential is only authorized for use with Claude Code and cannot be used for other API requests.", false},
		{"OAuth token does not meet scope requirement user:profile", false},
		{"Request not allowed", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": "permission_error", "message": tc.msg}})
			require.NoError(t, err)
			got, msg := DetectAnthropicPermissionError(403, payload)
			require.Equal(t, tc.want, got)
			if tc.want {
				require.Equal(t, tc.msg, msg)
			}
		})
	}
}
