package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MissingIndex describes a foreign key column without a leading index and the
// DDL that would fix it.
type MissingIndex struct {
	Schema       string `json:"schema"`
	Table        string `json:"table"`
	Column       string `json:"column"`
	Constraint   string `json:"constraint"`
	SuggestedDDL string `json:"suggested_ddl"`
}

// MissingIndexReport is the payload returned by find_missing_indexes.
type MissingIndexReport struct {
	MissingForeignKeyIndexes []MissingIndex  `json:"missing_foreign_key_indexes"`
	HighSeqScanTables        []TableScanStat `json:"high_seq_scan_tables"`
	Notes                    []string        `json:"notes,omitempty"`
}

// FindMissingIndexes detects unindexed foreign keys and reports tables with
// heavy sequential scans. It never executes DDL: it only returns suggestions.
func FindMissingIndexes(ctx context.Context, pool *pgxpool.Pool, limit int) (string, error) {
	if limit <= 0 {
		limit = 50
	}

	missing, err := missingForeignKeyIndexes(ctx, pool, limit)
	if err != nil {
		return "", err
	}

	seqScans, err := highSequentialScanTables(ctx, pool, 10)
	if err != nil {
		return "", err
	}

	report := MissingIndexReport{
		MissingForeignKeyIndexes: missing,
		HighSeqScanTables:        seqScans,
		Notes: []string{
			"Suggested DDL is never executed by DB-Guard; review and run it manually.",
			"CREATE INDEX CONCURRENTLY cannot run inside a transaction block.",
			"Only single-column foreign keys are evaluated; composite keys need a manual review.",
		},
	}
	if len(missing) == 0 {
		report.Notes = append(report.Notes, "Every foreign key has a leading index.")
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode index report: %w", err)
	}
	return string(encoded), nil
}

func missingForeignKeyIndexes(ctx context.Context, pool *pgxpool.Pool, limit int) ([]MissingIndex, error) {
	const query = `
		SELECT n.nspname,
		       c.relname,
		       att.attname,
		       con.conname
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = con.conkey[1]
		WHERE con.contype = 'f'
		  AND array_length(con.conkey, 1) = 1
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname NOT LIKE 'pg_toast%'
		  AND NOT EXISTS (
		      SELECT 1
		      FROM pg_index i
		      WHERE i.indrelid = con.conrelid
		        AND i.indkey[0] = con.conkey[1]
		  )
		ORDER BY n.nspname, c.relname, att.attname
		LIMIT $1;
	`
	rows, err := pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("query unindexed foreign keys: %w", err)
	}
	defer rows.Close()

	result := make([]MissingIndex, 0, limit)
	for rows.Next() {
		var item MissingIndex
		if err := rows.Scan(&item.Schema, &item.Table, &item.Column, &item.Constraint); err != nil {
			return nil, fmt.Errorf("scan unindexed foreign key: %w", err)
		}
		item.SuggestedDDL = buildIndexDDL(item.Schema, item.Table, item.Column)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read unindexed foreign keys: %w", err)
	}
	return result, nil
}

// buildIndexDDL returns a ready-to-review CREATE INDEX CONCURRENTLY statement.
func buildIndexDDL(schema, table, column string) string {
	name := indexName(table, column)
	relation := pgx.Identifier{schema, table}.Sanitize()
	quotedColumn := pgx.Identifier{column}.Sanitize()
	return fmt.Sprintf(
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS %s ON %s (%s);",
		pgx.Identifier{name}.Sanitize(),
		relation,
		quotedColumn,
	)
}

// indexName builds a deterministic, PostgreSQL-safe index name limited to the
// 63-byte identifier limit.
func indexName(table, column string) string {
	raw := "idx_" + table + "_" + column
	var builder strings.Builder
	for _, r := range strings.ToLower(raw) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	name := strings.Trim(builder.String(), "_")
	if name == "" || name == "idx" {
		name = "idx_db_guard"
	}
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}
