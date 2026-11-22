package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gt2rz/db-guard-mcp/internal/security"
)

// SampleColumn describes a column returned by safe_sample_query.
type SampleColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// SampleResult is the payload returned by safe_sample_query.
type SampleResult struct {
	Schema  string           `json:"schema"`
	Table   string           `json:"table"`
	Limit   int              `json:"limit"`
	Columns []SampleColumn   `json:"columns"`
	Rows    []map[string]any `json:"rows"`
	Note    string           `json:"note"`
}

// SafeSample returns at most maxRows rows of a relation with every value
// converted to text and PII-masked. It never accepts raw SQL: only a schema
// and table name, which are safely quoted.
func SafeSample(ctx context.Context, pool *pgxpool.Pool, schema, table string, limit, maxRows int, timeout time.Duration) (string, error) {
	if schema == "" {
		schema = "public"
	}
	if limit <= 0 {
		limit = 10
	}
	if maxRows <= 0 {
		maxRows = 25
	}
	if limit > maxRows {
		limit = maxRows
	}

	relCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var oid uint32
	var relkind string
	err := pool.QueryRow(relCtx, `
		SELECT c.oid, c.relkind::text
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2;
	`, schema, table).Scan(&oid, &relkind)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("relation %s.%s does not exist or is not visible", schema, table)
		}
		return "", fmt.Errorf("resolve relation: %w", err)
	}
	switch relkind {
	case "r", "p", "v", "m", "f":
	default:
		return "", fmt.Errorf("relation %s.%s is not a table or view", schema, table)
	}

	columns, err := relationColumns(relCtx, pool, oid)
	if err != nil {
		return "", err
	}
	if len(columns) == 0 {
		return "", fmt.Errorf("relation %s.%s has no readable columns", schema, table)
	}

	selectList := ""
	for i, column := range columns {
		if i > 0 {
			selectList += ", "
		}
		selectList += pgx.Identifier{column.Name}.Sanitize() + "::text AS " + pgx.Identifier{column.Name}.Sanitize()
	}
	statement := fmt.Sprintf(
		"SELECT %s FROM %s LIMIT $1",
		selectList,
		pgx.Identifier{schema, table}.Sanitize(),
	)

	tx, err := pool.BeginTx(relCtx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", fmt.Errorf("begin read-only transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(relCtx, fmt.Sprintf("SET LOCAL statement_timeout = %d", timeout.Milliseconds())); err != nil {
		return "", fmt.Errorf("set statement_timeout: %w", err)
	}

	rows, err := tx.Query(relCtx, statement, limit)
	if err != nil {
		return "", fmt.Errorf("sample relation: %w", err)
	}
	defer rows.Close()

	result := SampleResult{
		Schema:  schema,
		Table:   table,
		Limit:   limit,
		Columns: columns,
		Rows:    make([]map[string]any, 0, limit),
		Note:    "Every value is cast to text and passed through the PII redaction filter before leaving the process.",
	}

	for rows.Next() {
		values := make([]*string, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return "", fmt.Errorf("scan sampled row: %w", err)
		}

		row := make(map[string]any, len(columns))
		for i, column := range columns {
			if values[i] == nil {
				row[column.Name] = nil
				continue
			}
			row[column.Name] = security.MaskPII(*values[i])
		}
		result.Rows = append(result.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("read sampled rows: %w", err)
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode sample: %w", err)
	}
	return string(encoded), nil
}

func relationColumns(ctx context.Context, pool *pgxpool.Pool, oid uint32) ([]SampleColumn, error) {
	const query = `
		SELECT a.attname, format_type(a.atttypid, a.atttypmod)
		FROM pg_attribute a
		WHERE a.attrelid = $1
		  AND a.attnum > 0
		  AND NOT a.attisdropped
		ORDER BY a.attnum;
	`
	rows, err := pool.Query(ctx, query, oid)
	if err != nil {
		return nil, fmt.Errorf("load relation columns: %w", err)
	}
	defer rows.Close()

	columns := make([]SampleColumn, 0, 16)
	for rows.Next() {
		var column SampleColumn
		if err := rows.Scan(&column.Name, &column.Type); err != nil {
			return nil, fmt.Errorf("scan relation column: %w", err)
		}
		columns = append(columns, column)
	}
	return columns, rows.Err()
}
