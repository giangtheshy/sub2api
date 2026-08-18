package service

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
)

// AllowsModel reports whether this group is permitted to serve requestedModel.
//
// An empty list means no restriction. That default is load-bearing: the column
// is added empty for every group that already exists, so the opposite reading
// ("empty allows nothing") would take every deployment offline on upgrade.
//
// Entries match either exactly or as a trailing wildcard ("claude-sonnet-*"),
// reusing matchWildcard so the semantics are identical to the account-level
// model mapping an operator already knows.
func (g *Group) AllowsModel(requestedModel string) bool {
	if g == nil || len(g.AllowedModels) == 0 {
		return true
	}

	model := strings.ToLower(strings.TrimSpace(requestedModel))
	configured := false
	for _, pattern := range g.AllowedModels {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			// A stray newline in a textarea produces a blank entry. Treating it
			// as a pattern would match nothing and quietly narrow the group, so
			// it is skipped — but it also must not count as configuration, or a
			// list of nothing but blanks would lock the group out entirely.
			continue
		}
		configured = true
		if pattern == model || matchWildcard(pattern, model) {
			return true
		}
	}
	return !configured
}

// normalizeAllowedModels trims, drops blanks and de-duplicates the operator's
// input before it is persisted. Doing it here rather than at match time keeps
// the stored value equal to what the panel will show back, so an operator never
// sees a list that behaves differently from how it reads.
func normalizeAllowedModels(models []string) []string {
	if len(models) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(models))
	out := make([]string, 0, len(models))
	for _, model := range models {
		model = strings.TrimSpace(model)
		if model == "" {
			continue
		}
		key := strings.ToLower(model)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, model)
	}
	return out
}

// evaluateGroupModelAllowance is the shared decision. It is a free function
// because two independent gateway services (Anthropic-family and OpenAI-family)
// enforce the same rule while resolving the group by different routes; sharing
// the decision keeps them from drifting apart.
//
// A nil group passes. By the time this runs the caller has already resolved the
// group for its own purposes, so nil means a transient fault — and this is a
// packaging boundary, not a security boundary, so it must not amplify a DB
// hiccup into a total outage.
func evaluateGroupModelAllowance(group *Group, requestedModel string) error {
	if group == nil || group.AllowsModel(requestedModel) {
		return nil
	}
	slog.Warn("group allow-list blocked request",
		"group_id", group.ID, "group", group.Name, "model", requestedModel)
	return fmt.Errorf("%w: %s", ErrModelNotAllowedByGroup, requestedModel)
}

// groupModelAllowanceApplies reports whether there is anything to check. Some
// callers select an account without a model at all; there is nothing to compare
// and rejecting would break those endpoints for any group configuring a list.
func groupModelAllowanceApplies(groupID *int64, requestedModel string) bool {
	return groupID != nil && *groupID > 0 && strings.TrimSpace(requestedModel) != ""
}

// groupFromRequestContext returns the resolved group the scheduler already put
// on the context, if it is the one being asked about.
func groupFromRequestContext(ctx context.Context, groupID int64) *Group {
	if group, ok := ctx.Value(ctxkey.Group).(*Group); ok && IsGroupContextValid(group) && group.ID == groupID {
		return group
	}
	return nil
}

// checkGroupModelAllowance enforces the group's model allow-list before any
// account is considered.
//
// It runs beside checkChannelPricingRestriction and shares that call's
// contract: groupID must already be the *resolved* group, because Claude Code
// fallback may have moved the request to a different group and the allow-list
// that matters belongs to the group actually serving the request.
func (s *GatewayService) checkGroupModelAllowance(ctx context.Context, groupID *int64, requestedModel string) error {
	if !groupModelAllowanceApplies(groupID, requestedModel) {
		return nil
	}
	group := groupFromRequestContext(ctx, *groupID)
	if group == nil {
		if s.groupRepo == nil {
			return nil
		}
		loaded, err := s.resolveGroupByID(ctx, *groupID)
		if err != nil {
			slog.Warn("group model allow-list skipped: group load failed",
				"group_id", *groupID, "model", requestedModel, "error", err)
			return nil
		}
		group = loaded
	}
	return evaluateGroupModelAllowance(group, requestedModel)
}

// checkGroupModelAllowance is the OpenAI-family twin. It resolves the group the
// same way resolveOpenAIProfitControlGate does — context first (the direct-call
// path that carries almost all traffic), scheduler snapshot only when the
// scheduled group differs from the authenticated one, as with composite
// routing.
func (s *OpenAIGatewayService) checkGroupModelAllowance(ctx context.Context, groupID *int64, requestedModel string) error {
	if s == nil || !groupModelAllowanceApplies(groupID, requestedModel) {
		return nil
	}
	group := groupFromRequestContext(ctx, *groupID)
	if group == nil {
		if s.schedulerSnapshot == nil {
			return nil
		}
		loaded, err := s.schedulerSnapshot.GetGroupByIDLite(ctx, *groupID)
		if err != nil {
			slog.Warn("group model allow-list skipped: group load failed",
				"group_id", *groupID, "model", requestedModel, "error", err)
			return nil
		}
		group = loaded
	}
	return evaluateGroupModelAllowance(group, requestedModel)
}
