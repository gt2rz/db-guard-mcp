package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gt2rz/db-guard-mcp/internal/security"
)

// ErrQueryTimeout is returned when PostgreSQL cancels a statement because it
// exceeded the configured statement_timeout.
var ErrQueryTimeout = errors.New("query exceeded the configured timeout")

// Explain runs EXPLAIN [ANALYZE] (BUFFERS, FORMAT JSON) inside a read-only
// transaction and returns the PII-masked plan.
//
// The query MUST have been validated with security.ValidateReadOnlySQL before
// calling this function.
func Explain(ctx context.Context, pool *pgxpool.Pool, query string, analyze bool, timeoutMS int64) (string, error) {
	if timeoutMS <= 0 {
		timeoutMS = 10_000
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{
		AccessMode: pgx.ReadOnly,
		IsoLevel:   pgx.RepeatableRead,
	})
	if err != nil {
		return "", fmt.Errorf("begin read-only transaction: %w", err)
	}
	// The rollback must survive a cancelled request context.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", timeoutMS)); err != nil {
		return "", fmt.Errorf("set statement_timeout: %w", err)
	}

	prefix := "EXPLAIN (FORMAT JSON)"
	if analyze {
		prefix = "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)"
	}

	var raw []byte
	if err := tx.QueryRow(ctx, prefix+" "+query).Scan(&raw); err != nil {
		if isTimeout(err) {
			return "", fmt.Errorf("%w: %v", ErrQueryTimeout, err)
		}
		return "", fmt.Errorf("run EXPLAIN: %w", err)
	}

	return security.MaskPII(string(raw)), nil
}

func isTimeout(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) && pgErr.SQLState() == "57014" {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}
