package services

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"

	"leaflock/crypto"
	"leaflock/database"
)

type mockTemplatesDB struct {
	mock.Mock
}

func (m *mockTemplatesDB) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	callArgs := append([]interface{}{ctx, sql}, args...)
	ret := m.Called(callArgs...)
	return ret.Get(0).(pgx.Row)
}

func (m *mockTemplatesDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	panic("unexpected call to Query")
}

func (m *mockTemplatesDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	callArgs := append([]interface{}{ctx, sql}, args...)
	ret := m.Called(callArgs...)
	rows := ret.Get(0).(int64)
	tag := pgconn.NewCommandTag("INSERT " + fmt.Sprintf("%d", rows))
	return tag, ret.Error(1)
}

func (m *mockTemplatesDB) Begin(ctx context.Context) (pgx.Tx, error) {
	panic("unexpected call to Begin")
}

type mockTemplatesRow struct {
	mock.Mock
}

func (m *mockTemplatesRow) Scan(dest ...interface{}) error {
	ret := m.Called(dest...)
	return ret.Error(0)
}

func TestSeedDefaultTemplatesSkipWhenExisting(t *testing.T) {
	db := &mockTemplatesDB{}
	row := &mockTemplatesRow{}
	db.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(row)
	row.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*int) = 5
	}).Return(nil)

	key := make([]byte, 32)
	cryptoSvc := crypto.NewCryptoService(key)

	err := SeedDefaultTemplates(db, cryptoSvc)
	assert.NoError(t, err)
	db.AssertNumberOfCalls(t, "Exec", 0)
}

func TestSeedDefaultTemplatesInsertsDefaults(t *testing.T) {
	db := &mockTemplatesDB{}
	row := &mockTemplatesRow{}
	db.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(row)
	row.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*int) = 0
	}).Return(nil)

	insertCalls := 0
	db.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(
		func(args mock.Arguments) {
			insertCalls++
			userID := args[2]
			assert.Nil(t, userID)

			tags, ok := args[6].([]string)
			assert.True(t, ok, "tags should be string slice")
			assert.Contains(t, tags, "system")
			icon, ok := args[7].(string)
			assert.True(t, ok)
			assert.NotEmpty(t, icon)
			isPublic, ok := args[8].(bool)
			assert.True(t, ok)
			assert.True(t, isPublic)
			usageCount, ok := args[9].(int)
			assert.True(t, ok)
			assert.Zero(t, usageCount)
		},
	).Return(int64(1), nil)

	key := make([]byte, 32)
	cryptoSvc := crypto.NewCryptoService(key)

	err := SeedDefaultTemplates(db, cryptoSvc)
	assert.NoError(t, err)
	assert.Equal(t, len(defaultTemplates), insertCalls)
}

func TestSeedDefaultTemplatesQueryError(t *testing.T) {
	db := &mockTemplatesDB{}
	row := &mockTemplatesRow{}
	db.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(row)
	row.On("Scan", mock.Anything).Return(errors.New("db failure"))

	key := make([]byte, 32)
	cryptoSvc := crypto.NewCryptoService(key)

	err := SeedDefaultTemplates(db, cryptoSvc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check existing templates")
}

func TestSeedDefaultTemplatesInsertError(t *testing.T) {
	db := &mockTemplatesDB{}
	row := &mockTemplatesRow{}
	db.On("QueryRow", mock.Anything, mock.Anything, mock.Anything).Return(row)
	row.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		*args[0].(*int) = 0
	}).Return(nil)

	db.On("Exec", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(0), assert.AnError)

	key := make([]byte, 32)
	cryptoSvc := crypto.NewCryptoService(key)

	err := SeedDefaultTemplates(db, cryptoSvc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to insert template")
}

var _ database.Database = (*mockTemplatesDB)(nil)
