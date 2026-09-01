package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 与会话屏蔽管理页同一条纪律：service 未接入时返回空列表而非 500。
func TestListEndUserBans_WithoutServiceReturnsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin/risk-control/end-user-bans", nil)

	h := NewContentModerationHandler(nil, nil)
	h.ListEndUserBans(c)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.Empty(t, payload.Data)
}

// 解封是写操作：缺 identity 必须明确拒绝，不能静默成功。
func TestUnbanEndUser_RejectsEmptyIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodDelete, "/admin/risk-control/end-user-bans/", nil)
	c.Params = gin.Params{{Key: "identity", Value: "  "}}

	h := NewContentModerationHandler(nil, nil)
	h.UnbanEndUser(c)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// 存储不可用时写操作必须明确报错，不能假装成功——管理员需要知道按钮没生效。
func TestUnbanEndUser_RejectsWhenServiceUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodDelete, "/admin/risk-control/end-user-bans/abc123", nil)
	c.Params = gin.Params{{Key: "identity", Value: "abc123"}}

	h := NewContentModerationHandler(nil, nil)
	h.UnbanEndUser(c)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestClearEndUserBans_RejectsWhenServiceUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodDelete, "/admin/risk-control/end-user-bans/all", nil)

	h := NewContentModerationHandler(nil, nil)
	h.ClearEndUserBans(c)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}
