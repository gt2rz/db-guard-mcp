package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gt2rz/db-guard-mcp/internal/security"
)

// TableScanStat summarises sequential scan and bloat metrics for a table.
type TableScanStat struct {
	Schema      string     `json:"schema"`
	Table       string     `json:"table"`
	SeqScans    int64      `json:"seq_scans"`
	SeqTuples   int64      `json:"seq_tuples_read"`
	IndexScans  int64      `json:"index_scans"`
	LiveTuples  int64      `json:"live_tuples"`
	DeadTuples  int64      `json:"dead_tuples"`
	DeadRatio   float64    `json:"dead_ratio"`
	LastVacuum  *time.Time `json:"last_vacuum,omitempty"`
	LastAutovac *time.Time `json:"last_autovacuum,omitempty"`
}

// SlowQueryStat is a sanitised row from pg_stat_statements.
type SlowQueryStat struct {
	Query       string  `json:"query"`
	Calls       int64   `json:"calls"`
	MeanTimeMs  float64 `json:"mean_time_ms"`
	TotalTimeMs float64 `json:"total_time_ms"`
	Rows        int64   `json:"rows"`
}

// PerformanceReport is the payload returned by get_performance_metrics.
type PerformanceReport struct {
	HighSeqScanTables []TableScanStat `json:"high_seq_scan_tables"`
	BloatCandidates   []TableScanStat `json:"bloat_candidates"`
	SlowQueries       []SlowQueryStat `json:"slow_queries"`
	Notes             []string        `json:"notes,omitempty"`
}

// GetPerformanceMetrics collects sequential scan, bloat and slow query data.
func GetPerformanceMetrics(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	report := PerformanceReport{
		HighSeqScanTables: []TableScanStat{},
		BloatCandidates:   []TableScanStat{},
		SlowQueries:       []SlowQueryStat{},
	}

	highSeq, err := highSequentialScanTables(ctx, pool, 15)
	if err != nil {
		return "", err
	}
	report.HighSeqScanTables = highSeq

	bloat, err := bloatCandidates(ctx, pool, 10)
	if err != nil {
		return "", err
	}
	report.BloatCandidates = bloat

	slowQueries, note, err := slowQueries(ctx, pool)
	if err != nil {
		return "", err
	}
	report.SlowQueries = slowQueries
	if note != "" {
		report.Notes = append(report.Notes, note)
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode performance report: %w", err)
	}
	return string(encoded), nil
}

const tableStatsSelect = `
	SELECT schemaname,
	       relname,
	       COALESCE(seq_scan, 0),
	       COALESCE(seq_tup_read, 0),
	       COALESCE(idx_scan, 0),
	       COALESCE(n_live_tup, 0),
	       COALESCE(n_dead_tup, 0),
	       last_vacuum,
	       last_autovacuum
	FROM pg_stat_user_tables
`

func highSequentialScanTables(ctx context.Context, pool *pgxpool.Pool, limit int) ([]TableScanStat, error) {
	query := tableStatsSelect + `
		WHERE COALESCE(seq_scan, 0) > 0
		ORDER BY COALESCE(seq_tup_read, 0) DESC
		LIMIT $1;
	`
	return scanTableStats(ctx, pool, query, limit)
}

func bloatCandidates(ctx context.Context, pool *pgxpool.Pool, limit int) ([]TableScanStat, error) {
	query := tableStatsSelect + `
		WHERE COALESCE(n_dead_tup, 0) > 0
		ORDER BY COALESCE(n_dead_tup, 0) DESC
		LIMIT $1;
	`
	return scanTableStats(ctx, pool, query, limit)
}

func scanTableStats(ctx context.Context, pool *pgxpool.Pool, query string, limit int) ([]TableScanStat, error) {
	rows, err := pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query pg_stat_user_tables: %w", err)
	}
	defer rows.Close()

	stats := make([]TableScanStat, 0, limit)
	for rows.Next() {
		var stat TableScanStat
		if err := rows.Scan(
			&stat.Schema,
			&stat.Table,
			&stat.SeqScans,
			&stat.SeqTuples,
			&stat.IndexScans,
			&stat.LiveTuples,
			&stat.DeadTuples,
			&stat.LastVacuum,
			&stat.LastAutovac,
		); err != nil {
			return nil, fmt.Errorf("scan table stats: %w", err)
		}
		if total := stat.LiveTuples + stat.DeadTuples; total > 0 {
			stat.DeadRatio = float64(stat.DeadTuples) / float64(total)
		}
		stats = append(stats, stat)
	}
	return stats, rows.Err()
}

func slowQueries(ctx context.Context, pool *pgxpool.Pool) ([]SlowQueryStat, string, error) {
	var hasExtension bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`,
	).Scan(&hasExtension); err != nil {
		return nil, "", fmt.Errorf("check pg_stat_statements: %w", err)
	}
	if !hasExtension {
		return []SlowQueryStat{}, "pg_stat_statements is not installed; only table scan metrics are available", nil
	}

	const query = `
		SELECT query,
		       calls,
		       mean_exec_time,
		       total_exec_time,
		       rows
		FROM pg_stat_statements
		WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
		  AND query NOT ILIKE '%pg_stat_statements%'
		ORDER BY total_exec_time DESC
		LIMIT 10;
	`
	rows, err := pool.Query(ctx, query)
	if err != nil {
		// The extension can be installed without the view being readable by
		// the current role. Degrade gracefully instead of failing the tool.
		return []SlowQueryStat{}, slowQueriesUnavailable, nil
	}
	defer rows.Close()

	result := make([]SlowQueryStat, 0, 10)
	for rows.Next() {
		var stat SlowQueryStat
		if err := rows.Scan(&stat.Query, &stat.Calls, &stat.MeanTimeMs, &stat.TotalTimeMs, &stat.Rows); err != nil {
			return []SlowQueryStat{}, slowQueriesUnavailable, nil
		}
		stat.Query = security.MaskPII(stat.Query)
		result = append(result, stat)
	}
	if err := rows.Err(); err != nil {
		// pgx reports errors such as "pg_stat_statements must be loaded via
		// shared_preload_libraries" (SQLSTATE 55000) at iteration time, not at
		// Query time. Keep whatever rows were read and degrade gracefully.
		return result, slowQueriesUnavailable, nil
	}
	return result, "", nil
}

const slowQueriesUnavailable = "pg_stat_statements is installed but unavailable to this role (not preloaded or insufficient privileges); only table scan metrics are available"
