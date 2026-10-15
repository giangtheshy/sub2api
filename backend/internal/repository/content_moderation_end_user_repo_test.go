package repository

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestCountFlaggedByEndUserSince_FiltersByIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	since := time.Now().Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("WHERE end_user_identity = $1")).
		WithArgs("identity-a", since, false).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	count, err := repo.CountFlaggedByEndUserSince(context.Background(), "identity-a", since, false)

	require.NoError(t, err)
	require.Equal(t, 2, count)
	require.NoError(t, mock.ExpectationsWereMet())
}

// hash_block 是"预检命中已知风险哈希"，不是新的违规行为，两层封禁都不该计它。
func TestCountFlaggedByEndUserSince_ExcludesHashBlock(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	since := time.Now().Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("AND action <> 'hash_block'")).
		WithArgs("identity-a", since, false).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	count, err := repo.CountFlaggedByEndUserSince(context.Background(), "identity-a", since, false)

	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCountFlaggedByEndUserSince_ExcludesCyberPolicyWhenRequested(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	since := time.Now().Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("AND ($3::bool IS FALSE OR action <> 'cyber_policy')")).
		WithArgs("identity-a", since, true).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	count, err := repo.CountFlaggedByEndUserSince(context.Background(), "identity-a", since, true)

	require.NoError(t, err)
	require.Equal(t, 3, count)
	require.NoError(t, mock.ExpectationsWereMet())
}

// 风控白名单期间落下的 log-only 行只是证据：移出白名单后也不得回溯计入终端用户封禁，
// 与账号层 CountFlaggedByUserSince 的排除口径一致。
func TestCountFlaggedByEndUserSince_ExcludesLogOnlyModes(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	since := time.Now().Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("AND mode <> 'cyber_log_only'\n  AND mode <> 'risk_control_log_only'")).
		WithArgs("identity-a", since, false).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	count, err := repo.CountFlaggedByEndUserSince(context.Background(), "identity-a", since, false)

	require.NoError(t, err)
	require.Zero(t, count)
	require.NoError(t, mock.ExpectationsWereMet())
}

// 重置锚点必须是 end_user_banned 而不是 auto_banned：两层解封互不影响。
func TestCountFlaggedByEndUserSince_ResetsOnEndUserBanAnchor(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	since := time.Now().Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("WHERE end_user_identity = $1 AND end_user_banned = TRUE")).
		WithArgs("identity-a", since, false).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	count, err := repo.CountFlaggedByEndUserSince(context.Background(), "identity-a", since, false)

	require.NoError(t, err)
	require.Equal(t, 0, count)
	require.NoError(t, mock.ExpectationsWereMet())
}

// [FORK-BAN-SCOPE] 账号层计数只统计无终端用户标识的行：转售商下多个终端客户的违规
// 不能累加成整个账号的封号。
func TestCountFlaggedByUserSince_ExcludesEndUserIdentityRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	since := time.Now().Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("AND COALESCE(end_user_identity, '') = ''")).
		WithArgs(int64(1001), since, false).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	count, err := repo.CountFlaggedByUserSince(context.Background(), 1001, since, false)

	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.NoError(t, mock.ExpectationsWereMet())
}

// 空标识不查库：没有 X-User-Id 就没有终端用户可言。
func TestCountFlaggedByEndUserSince_EmptyIdentitySkipsQuery(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	repo := NewContentModerationRepository(db)
	count, err := repo.CountFlaggedByEndUserSince(context.Background(), "   ", time.Now().Add(-time.Hour), false)

	require.NoError(t, err)
	require.Equal(t, 0, count)
	require.NoError(t, mock.ExpectationsWereMet(), "no query may be issued for an empty identity")
}
