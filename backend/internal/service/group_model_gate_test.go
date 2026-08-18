package service

import (
	"context"
	"errors"
	"testing"
)

func gateCtxWithGroup(g *Group) context.Context {
	s := &GatewayService{}
	return s.withGroupContext(context.Background(), g)
}

// No group means no group restriction; direct-platform traffic must not be
// blocked by a rule that has nowhere to come from.
func TestGroupModelGatePassesWithoutAGroup(t *testing.T) {
	s := &GatewayService{}

	if err := s.checkGroupModelAllowance(context.Background(), nil, "claude-opus-5"); err != nil {
		t.Errorf("gate rejected a request that has no group: %v", err)
	}
}

func TestGroupModelGateRejectsWithADistinctSentinel(t *testing.T) {
	group := &Group{ID: 7, Name: "sonnet-only", Status: "active", Platform: PlatformAnthropic, Hydrated: true,
		AllowedModels: []string{"claude-sonnet-*"}}
	id := group.ID
	s := &GatewayService{}

	err := s.checkGroupModelAllowance(gateCtxWithGroup(group), &id, "claude-opus-5")

	if err == nil {
		t.Fatal("gate allowed a model outside the group's list")
	}
	if !errors.Is(err, ErrModelNotAllowedByGroup) {
		t.Errorf("err = %v; must be ErrModelNotAllowedByGroup so the handler can answer 403", err)
	}
	// Sharing ErrNoAvailableAccounts would make a permanent configuration
	// rejection look like a transient capacity shortfall: clients would retry
	// a 503 that can never succeed, and it would land in capacity alerting.
	if errors.Is(err, ErrNoAvailableAccounts) {
		t.Error("rejection must not also be ErrNoAvailableAccounts")
	}
}

func TestGroupModelGateAllowsListedModel(t *testing.T) {
	group := &Group{ID: 7, Name: "sonnet-only", Status: "active", Platform: PlatformAnthropic, Hydrated: true,
		AllowedModels: []string{"claude-sonnet-*"}}
	id := group.ID
	s := &GatewayService{}

	if err := s.checkGroupModelAllowance(gateCtxWithGroup(group), &id, "claude-sonnet-4-5"); err != nil {
		t.Errorf("gate rejected a listed model: %v", err)
	}
}

// Every group in an existing deployment starts with an empty list.
func TestGroupModelGateAllowsEverythingWhenUnconfigured(t *testing.T) {
	group := &Group{ID: 7, Name: "default", Status: "active", Platform: PlatformAnthropic, Hydrated: true}
	id := group.ID
	s := &GatewayService{}

	if err := s.checkGroupModelAllowance(gateCtxWithGroup(group), &id, "claude-opus-5"); err != nil {
		t.Errorf("gate rejected traffic for an unconfigured group: %v", err)
	}
}

// An empty model name reaches this path from endpoints that do not carry one
// (a plain account selection). There is nothing to compare, and rejecting it
// would break those endpoints for every group that configures a list.
func TestGroupModelGateIgnoresAnEmptyModel(t *testing.T) {
	group := &Group{ID: 7, Name: "sonnet-only", Status: "active", Platform: PlatformAnthropic, Hydrated: true,
		AllowedModels: []string{"claude-sonnet-*"}}
	id := group.ID
	s := &GatewayService{}

	if err := s.checkGroupModelAllowance(gateCtxWithGroup(group), &id, ""); err != nil {
		t.Errorf("gate rejected a request that carries no model: %v", err)
	}
}

// The OpenAI family schedules through a different service that resolves the
// group by its own route. Without this test the gate could silently apply to
// Anthropic traffic only, and the hole would be invisible — an allow-list that
// works for some endpoints is worse than none, because it is believed.
func TestOpenAIGroupModelGateEnforcesTheSameRule(t *testing.T) {
	group := &Group{ID: 11, Name: "gpt5-only", Status: "active", Platform: PlatformOpenAI,
		Hydrated: true, AllowedModels: []string{"gpt-5.2*"}}
	id := group.ID
	anthropic := &GatewayService{}
	ctx := anthropic.withGroupContext(context.Background(), group)
	s := &OpenAIGatewayService{}

	if err := s.checkGroupModelAllowance(ctx, &id, "gpt-5.2-pro"); err != nil {
		t.Errorf("listed model rejected: %v", err)
	}

	err := s.checkGroupModelAllowance(ctx, &id, "gpt-4o-audio-preview")
	if !errors.Is(err, ErrModelNotAllowedByGroup) {
		t.Errorf("err = %v, want ErrModelNotAllowedByGroup", err)
	}
}
