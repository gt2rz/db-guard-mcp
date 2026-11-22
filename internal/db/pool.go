// Package db contains the read-only PostgreSQL access layer. Every connection
// opened by this package is configured with default_transaction_read_only=on,
// so even a bug in the SQL guard cannot mutate the database.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds the connection and execution limits for the database layer.
type Config struct {
	// DatabaseURL is a libpq-compatible connection string.
	DatabaseURL string
	// QueryTimeout bounds every statement executed by DB-Guard.
	QueryTimeout time.Duration
	// MaxSampleRows is the hard ceiling for safe_sample_query.
	MaxSampleRows int
}

// DefaultConfig returns sensible defaults for a local/staging database.
func DefaultConfig() Config {
	return Config{
		QueryTimeout:  10 * time.Second,
		MaxSampleRows: 25,
	}
}

// NewPool opens a small connection pool and verifies connectivity.
//
// Defense in depth: default_transaction_read_only=on is sent as a startup
// parameter, so every session is read-only before any query is executed.
func NewPool(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 10 * time.Second
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}

	poolCfg.MaxConns = 4
	poolCfg.MinConns = 0
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.ConnConfig.RuntimeParams["application_name"] = "db-guard-mcp"
	poolCfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	poolCfg.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprintf("%d", cfg.QueryTimeout.Milliseconds())

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}

	return pool, nil
}

// WithTimeout derives a context with the configured query timeout.
func WithTimeout(ctx context.Context, cfg Config) (context.Context, context.CancelFunc) {
	timeout := cfg.QueryTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}
