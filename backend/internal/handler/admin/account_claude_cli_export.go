package admin

import (
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// ExportClaudeCLICredentials renders an Anthropic OAuth account as the
// credentials file Claude Code reads, so an operator can use a subscription
// already onboarded here from their own machine without logging in again.
//
// GET /api/v1/admin/accounts/:id/claude-cli-credentials
//
// The response carries a live OAuth token in the clear. That is the entire
// point of the endpoint, so it cannot be redacted — instead the route is
// registered in auditSensitiveReads, which is the same treatment the account
// backup export gets, and every call is recorded with who made it.
func (h *AccountHandler) ExportClaudeCLICredentials(c *gin.Context) {
	accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid account ID")
		return
	}

	account, err := h.adminService.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	// Anything other than an explicit affirmative withholds the refresh token.
	// A malformed or absent parameter must not be the thing that hands a CLI
	// the ability to rotate this account's credential, so the parse fails
	// towards withholding rather than towards sharing.
	includeRefresh, _ := strconv.ParseBool(c.DefaultQuery("include_refresh_token", "false"))

	export, err := service.BuildClaudeCLICredentials(account, service.ClaudeCLIExportOptions{
		IncludeRefreshToken: includeRefresh,
	})
	if err != nil {
		// The rejections are all "this account cannot produce such a file"
		// (wrong platform, wrong type, no token), which is a bad request for
		// this resource rather than a server fault.
		response.BadRequest(c, err.Error())
		return
	}

	response.Success(c, export)
}
