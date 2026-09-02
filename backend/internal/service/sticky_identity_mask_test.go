package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestMaskIdentityValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"single char", "a", "*"},
		{"four chars fully masked", "abcd", "****"},
		{"five chars keeps one each side", "abcde", "a*******e"},
		{"eight chars keeps one each side", "user1234", "u*******4"},
		{"nine chars keeps two each side", "user12345", "us*******45"},
		{"eleven chars keeps two each side", "user1234567", "us*******67"},
		{"twelve chars keeps four each side", "user12345678", "user*******5678"},
		{"long value keeps four each side", "usr_8f3a1b2c3d4ec21", "usr_*******ec21"},
		{"trims surrounding space", "  usr_8f3a1b2c3d4ec21  ", "usr_*******ec21"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, MaskIdentityValue(tt.in))
		})
	}
}

// 多字节字符必须按 rune 切分，否则遮蔽串会出现半个字符的乱码。
func TestMaskIdentityValue_SplitsOnRunesNotBytes(t *testing.T) {
	// 11 个 rune → 2+2 档；若按 byte 切分，中文会被截成乱码。
	got := MaskIdentityValue("用户标识符一二三四五六")
	require.Equal(t, "用户*******五六", got)
	require.True(t, utf8.ValidString(got))
}

// 遮蔽段长度固定，不随原值长度变化——否则展示串会泄露原值长度。
func TestMaskIdentityValue_HidesOriginalLength(t *testing.T) {
	short := MaskIdentityValue("abcd12345678")
	long := MaskIdentityValue("abcd1234567890123456789012345678")
	require.Equal(t, len([]rune(short)), len([]rune(long)))
}

func stickyMaskTestContext(headers map[string]string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.Request = req
	return c
}

// 关键回归：新增遮蔽字段绝不能改变 key 的派生结果，
// 否则升级瞬间所有在途屏蔽项都会失配、等于集体解封。
func TestStickyIdentityDetailed_KeyMatchesLegacyDerivation(t *testing.T) {
	cases := []map[string]string{
		{},
		{"X-User-Id": "usr_8f3a1b2c3d4ec21"},
		{"X-User-Id": "usr_8f3a1b2c3d4ec21", "session_id": "sess_abcdef123456"},
		{"session_id": "sess_abcdef123456"},
	}
	for _, headers := range cases {
		c := stickyMaskTestContext(headers)
		kind, masked, key := StickyIdentity(7, 42, c, nil)
		info := StickyIdentityDetailed(7, 42, c, nil)

		require.Equal(t, kind, info.Kind)
		require.Equal(t, masked, info.Masked)
		require.Equal(t, key, info.Key)
	}
}

func TestStickyIdentityDetailed_ExposesMaskedSignals(t *testing.T) {
	c := stickyMaskTestContext(map[string]string{
		"X-User-Id": "usr_8f3a1b2c3d4ec21",
	})
	info := StickyIdentityDetailed(7, 42, c, nil)

	require.Equal(t, StickyIdentityKindXUserID, info.Kind)
	require.Equal(t, "usr_*******ec21", info.MaskedUserID)
	require.Empty(t, info.MaskedSessionID)
	// 原始值绝不出现在任何返回字段里。
	require.NotContains(t, info.MaskedUserID, "8f3a1b2c3d4e")
}

// 无请求级信号时退回 (apiKey,user)，此时没有可遮蔽的原始标识。
func TestStickyIdentityDetailed_APIKeyUserFallbackHasNoMaskedSignals(t *testing.T) {
	info := StickyIdentityDetailed(7, 42, stickyMaskTestContext(nil), nil)

	require.Equal(t, StickyIdentityKindAPIKeyUser, info.Kind)
	require.Empty(t, info.MaskedUserID)
	require.Empty(t, info.MaskedSessionID)
	require.NotEmpty(t, info.Key)
}
