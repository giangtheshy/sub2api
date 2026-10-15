package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// endUserBanTestStore 是内存版封禁表，语义与 Redis 实现一致（无 TTL）。
type endUserBanTestStore struct {
	mu      sync.Mutex
	banned  map[string]EndUserBanMeta
	banErr  error
	readErr error
}

func newEndUserBanTestStore() *endUserBanTestStore {
	return &endUserBanTestStore{banned: map[string]EndUserBanMeta{}}
}

func (s *endUserBanTestStore) BanEndUser(ctx context.Context, identity string, meta EndUserBanMeta) error {
	if s.banErr != nil {
		return s.banErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.banned[identity] = meta
	return nil
}

func (s *endUserBanTestStore) IsEndUserBanned(ctx context.Context, identity string) (bool, error) {
	if s.readErr != nil {
		return false, s.readErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.banned[identity]
	return ok, nil
}

func (s *endUserBanTestStore) UnbanEndUser(ctx context.Context, identity string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.banned[identity]
	delete(s.banned, identity)
	return ok, nil
}

func (s *endUserBanTestStore) ListBannedEndUsers(ctx context.Context) ([]EndUserBanMeta, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]EndUserBanMeta, 0, len(s.banned))
	for _, m := range s.banned {
		out = append(out, m)
	}
	return out, nil
}

func (s *endUserBanTestStore) ClearBannedEndUsers(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := int64(len(s.banned))
	s.banned = map[string]EndUserBanMeta{}
	return n, nil
}

func (s *endUserBanTestStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.banned)
}

func (s *endUserBanTestStore) has(identity string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.banned[identity]
	return ok
}

func endUserBanTestConfig(threshold int) *ContentModerationConfig {
	return &ContentModerationConfig{
		EndUserBanEnabled:    true,
		EndUserBanThreshold:  threshold,
		ViolationWindowHours: 24,
	}
}

func endUserBanTestService(repo ContentModerationRepository, store ContentModerationEndUserBanStore) *ContentModerationService {
	return &ContentModerationService{repo: repo, endUserBanStore: store}
}

func flaggedLog(identity string, at time.Time) ContentModerationLog {
	return ContentModerationLog{
		EndUserIdentity: identity,
		Flagged:         true,
		Action:          ContentModerationActionBlock,
		CreatedAt:       at,
	}
}

// 达到阈值就封禁，且只封该终端用户。
func TestApplyFlaggedEndUserSideEffects_BansAtThreshold(t *testing.T) {
	repo := &contentModerationTestRepo{}
	now := time.Now()
	repo.logs = append(repo.logs, flaggedLog("identity-a", now.Add(-time.Minute)))
	store := newEndUserBanTestStore()
	svc := endUserBanTestService(repo, store)

	log := &ContentModerationLog{Flagged: true, EndUserIdentity: "identity-a"}
	banned := svc.applyFlaggedEndUserSideEffects(context.Background(), endUserBanTestConfig(2), log)

	require.True(t, banned)
	require.True(t, log.EndUserBanned, "the log row must carry the ban flag as the reset anchor")
	require.True(t, store.has("identity-a"))
	require.Equal(t, 1, store.count(), "only the offending end user may be banned")
}

func TestApplyFlaggedEndUserSideEffects_NoBanBelowThreshold(t *testing.T) {
	repo := &contentModerationTestRepo{}
	store := newEndUserBanTestStore()
	svc := endUserBanTestService(repo, store)

	log := &ContentModerationLog{Flagged: true, EndUserIdentity: "identity-a"}
	banned := svc.applyFlaggedEndUserSideEffects(context.Background(), endUserBanTestConfig(3), log)

	require.False(t, banned)
	require.False(t, log.EndUserBanned)
	require.Equal(t, 0, store.count())
}

// 这是本功能的验收条件：同一把 Key 下的另一个客户不受牵连。
func TestApplyFlaggedEndUserSideEffects_DoesNotAffectSiblingCustomers(t *testing.T) {
	repo := &contentModerationTestRepo{}
	now := time.Now()
	repo.logs = append(repo.logs,
		flaggedLog("identity-a", now.Add(-2*time.Minute)),
		flaggedLog("identity-a", now.Add(-time.Minute)),
		flaggedLog("identity-b", now.Add(-time.Minute)),
	)
	store := newEndUserBanTestStore()
	svc := endUserBanTestService(repo, store)

	logA := &ContentModerationLog{Flagged: true, EndUserIdentity: "identity-a"}
	require.True(t, svc.applyFlaggedEndUserSideEffects(context.Background(), endUserBanTestConfig(3), logA))

	logB := &ContentModerationLog{Flagged: true, EndUserIdentity: "identity-b"}
	require.False(t, svc.applyFlaggedEndUserSideEffects(context.Background(), endUserBanTestConfig(3), logB),
		"a sibling customer with fewer violations must stay unbanned")

	require.True(t, store.has("identity-a"))
	require.False(t, store.has("identity-b"))
}

// 没有 X-User-Id 时本层必须完全不动作——绝不能退化成封整把 Key。
func TestApplyFlaggedEndUserSideEffects_SkipsWithoutIdentity(t *testing.T) {
	repo := &contentModerationTestRepo{}
	now := time.Now()
	for i := 0; i < 5; i++ {
		repo.logs = append(repo.logs, flaggedLog("", now.Add(-time.Minute)))
	}
	store := newEndUserBanTestStore()
	svc := endUserBanTestService(repo, store)

	log := &ContentModerationLog{Flagged: true, EndUserIdentity: ""}
	banned := svc.applyFlaggedEndUserSideEffects(context.Background(), endUserBanTestConfig(1), log)

	require.False(t, banned)
	require.False(t, log.EndUserBanned)
	require.Equal(t, 0, store.count(), "an empty identity must never produce a ban")
}

func TestApplyFlaggedEndUserSideEffects_RespectsSwitchAndThreshold(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ContentModerationConfig
	}{
		{"disabled switch", &ContentModerationConfig{EndUserBanEnabled: false, EndUserBanThreshold: 1, ViolationWindowHours: 24}},
		{"zero threshold", &ContentModerationConfig{EndUserBanEnabled: true, EndUserBanThreshold: 0, ViolationWindowHours: 24}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newEndUserBanTestStore()
			svc := endUserBanTestService(&contentModerationTestRepo{}, store)
			log := &ContentModerationLog{Flagged: true, EndUserIdentity: "identity-a"}
			require.False(t, svc.applyFlaggedEndUserSideEffects(context.Background(), tt.cfg, log))
			require.Equal(t, 0, store.count())
		})
	}
}

// 已封禁的标识重复命中：不重复写入，但仍标记本行以推进计数锚点。
func TestApplyFlaggedEndUserSideEffects_AlreadyBannedStillAnchors(t *testing.T) {
	store := newEndUserBanTestStore()
	store.banned["identity-a"] = EndUserBanMeta{Identity: "identity-a"}
	svc := endUserBanTestService(&contentModerationTestRepo{}, store)

	log := &ContentModerationLog{Flagged: true, EndUserIdentity: "identity-a"}
	banned := svc.applyFlaggedEndUserSideEffects(context.Background(), endUserBanTestConfig(1), log)

	require.False(t, banned, "re-hitting an existing ban is not a new ban")
	require.True(t, log.EndUserBanned, "the row must still anchor the counter reset")
}

// 存储故障不得阻断主链路，也不得误封。
func TestApplyFlaggedEndUserSideEffects_FailsClosedOnStoreError(t *testing.T) {
	store := newEndUserBanTestStore()
	store.readErr = errors.New("redis down")
	svc := endUserBanTestService(&contentModerationTestRepo{}, store)

	log := &ContentModerationLog{Flagged: true, EndUserIdentity: "identity-a"}
	require.False(t, svc.applyFlaggedEndUserSideEffects(context.Background(), endUserBanTestConfig(1), log))
	require.False(t, log.EndUserBanned)
}

func TestApplyFlaggedEndUserSideEffects_NilStoreIsSafe(t *testing.T) {
	svc := endUserBanTestService(&contentModerationTestRepo{}, nil)
	log := &ContentModerationLog{Flagged: true, EndUserIdentity: "identity-a"}
	require.NotPanics(t, func() {
		require.False(t, svc.applyFlaggedEndUserSideEffects(context.Background(), endUserBanTestConfig(1), log))
	})
}

// 解封后计数从零起算：旧历史不能让人刚解封就被立刻再封。
func TestCountResetsAfterEndUserBan(t *testing.T) {
	repo := &contentModerationTestRepo{}
	now := time.Now()
	old := flaggedLog("identity-a", now.Add(-10*time.Minute))
	old.EndUserBanned = true
	repo.logs = append(repo.logs,
		flaggedLog("identity-a", now.Add(-20*time.Minute)),
		old,
	)

	count, err := repo.CountFlaggedByEndUserSince(context.Background(), "identity-a", now.Add(-time.Hour), false)
	require.NoError(t, err)
	require.Equal(t, 0, count, "rows at or before the last ban must not be counted again")
}

// 两层封禁互相独立：终端用户层触发不代表账号层也触发。
func TestEndUserAndAccountBanLayersAreIndependent(t *testing.T) {
	repo := &contentModerationTestRepo{}
	now := time.Now()
	userID := int64(7)
	for i := 0; i < 2; i++ {
		l := flaggedLog("identity-a", now.Add(-time.Duration(i+1)*time.Minute))
		l.UserID = &userID
		repo.logs = append(repo.logs, l)
	}
	store := newEndUserBanTestStore()
	userRepo := &contentModerationTestUserRepo{user: &User{ID: userID, Role: RoleUser, Status: StatusActive}}
	svc := &ContentModerationService{repo: repo, endUserBanStore: store, userRepo: userRepo}

	cfg := &ContentModerationConfig{
		EndUserBanEnabled:    true,
		EndUserBanThreshold:  3,
		AutoBanEnabled:       true,
		BanThreshold:         15, // 账号层阈值远高于终端用户层
		ViolationWindowHours: 24,
	}
	log := &ContentModerationLog{Flagged: true, EndUserIdentity: "identity-a", UserID: &userID}

	require.True(t, svc.applyFlaggedEndUserSideEffects(context.Background(), cfg, log))
	require.False(t, svc.applyFlaggedAccountSideEffects(context.Background(), cfg, log))

	require.True(t, store.has("identity-a"), "the end user must be banned")
	require.Equal(t, StatusActive, userRepo.user.Status,
		"the reseller account must stay active while only one of its customers is banned")
}

// [FORK-BAN-SCOPE] 转售商场景：所有终端客户共用一个 sub2api 账号。带 X-User-Id 的违规
// 无论累计多少次（跨多个终端客户）都不得禁用账号，只封达到阈值的终端用户；
// 不带 X-User-Id 的违规仍按原逻辑封账号。
func TestPersistContentModerationLog_BanScopeByEndUserIdentity(t *testing.T) {
	const userID = int64(42)
	tests := []struct {
		name             string
		identities       []string // 每个元素是一次违规请求的终端用户标识，空串表示无 X-User-Id
		wantUserStatus   string
		wantBannedEndIDs []string
		wantUnbannedIDs  []string
	}{
		{
			name:            "different end users exceed account threshold, account stays active",
			identities:      []string{"eu-1", "eu-2", "eu-3", "eu-4", "eu-5", "eu-6"},
			wantUserStatus:  StatusActive,
			wantUnbannedIDs: []string{"eu-1", "eu-2", "eu-3", "eu-4", "eu-5", "eu-6"},
		},
		{
			name:             "one end user hits its threshold, only that end user banned",
			identities:       []string{"eu-1", "eu-2", "eu-1", "eu-3", "eu-1", "eu-4"},
			wantUserStatus:   StatusActive,
			wantBannedEndIDs: []string{"eu-1"},
			wantUnbannedIDs:  []string{"eu-2", "eu-3", "eu-4"},
		},
		{
			name:           "header-less request after many end-user violations does not inherit their count",
			identities:     []string{"eu-1", "eu-2", "eu-3", "eu-4", "eu-5", ""},
			wantUserStatus: StatusActive,
		},
		{
			name:           "header-less violations still ban the account",
			identities:     []string{"", "", ""},
			wantUserStatus: StatusDisabled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &contentModerationTestRepo{}
			store := newEndUserBanTestStore()
			userRepo := &contentModerationTestUserRepo{user: &User{ID: userID, Role: RoleUser, Status: StatusActive}}
			svc := &ContentModerationService{repo: repo, endUserBanStore: store, userRepo: userRepo}
			cfg := &ContentModerationConfig{
				AutoBanEnabled:       true,
				BanThreshold:         3,
				EndUserBanEnabled:    true,
				EndUserBanThreshold:  3,
				ViolationWindowHours: 24,
			}
			base := time.Now().Add(-time.Hour)
			for i, identity := range tt.identities {
				uid := userID
				log := &ContentModerationLog{
					UserID:          &uid,
					Flagged:         true,
					Action:          ContentModerationActionKeywordBlock,
					EndUserIdentity: identity,
					CreatedAt:       base.Add(time.Duration(i) * time.Minute),
				}
				svc.persistContentModerationLog(context.Background(), cfg, log, "", false, true)
				if identity != "" {
					require.False(t, log.AutoBanned, "a log carrying X-User-Id must never be marked as account auto-ban")
				}
			}
			require.Equal(t, tt.wantUserStatus, userRepo.user.Status)
			for _, id := range tt.wantBannedEndIDs {
				require.True(t, store.has(id), "end user %s should be banned", id)
			}
			for _, id := range tt.wantUnbannedIDs {
				require.False(t, store.has(id), "end user %s should not be banned", id)
			}
		})
	}
}

// [FORK-BAN-SCOPE] cyber_policy 事件走同一规则：带 X-User-Id 不封账号。
func TestApplyFlaggedAccountSideEffects_SkipsWhenEndUserIdentityPresent(t *testing.T) {
	userID := int64(9)
	userRepo := &contentModerationTestUserRepo{user: &User{ID: userID, Role: RoleUser, Status: StatusActive}}
	svc := &ContentModerationService{repo: &contentModerationTestRepo{}, userRepo: userRepo}
	cfg := &ContentModerationConfig{AutoBanEnabled: true, BanThreshold: 1, ViolationWindowHours: 24}

	withID := &ContentModerationLog{Flagged: true, UserID: &userID, EndUserIdentity: "identity-a"}
	require.False(t, svc.applyFlaggedAccountSideEffects(context.Background(), cfg, withID))
	require.False(t, withID.AutoBanned)
	require.Equal(t, StatusActive, userRepo.user.Status)

	withoutID := &ContentModerationLog{Flagged: true, UserID: &userID}
	require.True(t, svc.applyFlaggedAccountSideEffects(context.Background(), cfg, withoutID))
	require.Equal(t, StatusDisabled, userRepo.user.Status)
}
