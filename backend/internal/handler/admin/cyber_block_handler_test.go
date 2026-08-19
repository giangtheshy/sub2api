package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 屏蔽管理是纯运维视图：网关服务未接入时必须返回空列表而不是 500，
// 否则风控页会整页挂掉。
func TestListBlocks_WithoutGatewayServiceReturnsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin/risk-control/blocks", nil)

	h := NewContentModerationHandler(nil, nil)
	h.ListBlocks(c)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.Empty(t, payload.Data)
}

// 解封是写操作：缺 key 必须明确拒绝，不能静默成功。
func TestUnblock_RejectsEmptyKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodDelete, "/admin/risk-control/blocks/", nil)
	c.Params = gin.Params{{Key: "key", Value: "  "}}

	h := NewContentModerationHandler(nil, nil)
	h.Unblock(c)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}
