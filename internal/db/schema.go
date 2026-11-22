package db

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gt2rz/db-guard-mcp/internal/security"
)

// ColumnInfo describes a single column of a table or view.
type ColumnInfo struct {
	Name       string  `json:"name"`
	DataType   string  `json:"type"`
	Nullable   bool    `json:"nullable"`
	Default    *string `json:"default,omitempty"`
	PrimaryKey bool    `json:"primary_key"`
}

// IndexInfo describes an existing index.
type IndexInfo struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Unique     bool   `json:"unique"`
	Primary    bool   `json:"primary"`
}

// ForeignKeyInfo describes an existing foreign key constraint.
type ForeignKeyInfo struct {
	Name              string   `json:"name"`
	Columns           []string `json:"columns"`
	ReferencesSchema  string   `json:"references_schema"`
	ReferencesTable   string   `json:"references_table"`
	ReferencesColumns []string `json:"references_columns"`
}

// TableInfo is the compact, model-friendly representation of a relation.
type TableInfo struct {
	Schema        string           `json:"schema"`
	Name          string           `json:"name"`
	Kind          string           `json:"kind"`
	EstimatedRows int64            `json:"estimated_rows"`
	Columns       []ColumnInfo     `json:"columns"`
	Indexes       []IndexInfo      `json:"indexes"`
	ForeignKeys   []ForeignKeyInfo `json:"foreign_keys"`
}

// GetDatabaseSchema returns every user relation with its columns, indexes and
// foreign keys as an indented JSON document.
//
// Column defaults and index definitions are PII-masked because they can embed
// literals (for example a partial index predicate or a seeded email).
func GetDatabaseSchema(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	tables := make(map[string]*TableInfo)

	if err := loadRelations(ctx, pool, tables); err != nil {
		return "", err
	}
	if err := loadColumns(ctx, pool, tables); err != nil {
		return "", err
	}
	if err := loadIndexes(ctx, pool, tables); err != nil {
		return "", err
	}
	if err := loadForeignKeys(ctx, pool, tables); err != nil {
		return "", err
	}

	result := make([]*TableInfo, 0, len(tables))
	for _, table := range tables {
		result = append(result, table)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Schema != result[j].Schema {
			return result[i].Schema < result[j].Schema
		}
		return result[i].Name < result[j].Name
	})

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode schema: %w", err)
	}
	return string(encoded), nil
}

func loadRelations(ctx context.Context, pool *pgxpool.Pool, tables map[string]*TableInfo) error {
	const query = `
		SELECT n.nspname,
		       c.relname,
		       c.relkind::text,
		       CASE WHEN c.reltuples < 0 THEN 0 ELSE c.reltuples::bigint END
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname NOT LIKE 'pg_toast%'
		  AND n.nspname NOT LIKE 'pg_temp%'
		ORDER BY n.nspname, c.relname;
	`
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("load relations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var schema, name, kind string
		var estimatedRows int64
		if err := rows.Scan(&schema, &name, &kind, &estimatedRows); err != nil {
			return fmt.Errorf("scan relation: %w", err)
		}
		tables[schema+"."+name] = &TableInfo{
			Schema:        schema,
			Name:          name,
			Kind:          relationKind(kind),
			EstimatedRows: estimatedRows,
			Columns:       []ColumnInfo{},
			Indexes:       []IndexInfo{},
			ForeignKeys:   []ForeignKeyInfo{},
		}
	}
	return rows.Err()
}

func loadColumns(ctx context.Context, pool *pgxpool.Pool, tables map[string]*TableInfo) error {
	const query = `
		SELECT n.nspname,
		       c.relname,
		       a.attname,
		       format_type(a.atttypid, a.atttypmod),
		       NOT a.attnotnull,
		       pg_get_expr(d.adbin, d.adrelid),
		       COALESCE(pk.is_primary, false)
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		LEFT JOIN LATERAL (
			SELECT true AS is_primary
			FROM pg_index i
			WHERE i.indrelid = c.oid
			  AND i.indisprimary
			  AND a.attnum = ANY (i.indkey)
		) pk ON true
		WHERE a.attnum > 0
		  AND NOT a.attisdropped
		  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname NOT LIKE 'pg_toast%'
		  AND n.nspname NOT LIKE 'pg_temp%'
		ORDER BY n.nspname, c.relname, a.attnum;
	`
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("load columns: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var schema, table, name, dataType string
		var nullable, primaryKey bool
		var defaultValue *string

		if err := rows.Scan(&schema, &table, &name, &dataType, &nullable, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan column: %w", err)
		}
		if info, ok := tables[schema+"."+table]; ok {
			maskedDefault := defaultValue
			if defaultValue != nil {
				value := security.MaskPII(*defaultValue)
				maskedDefault = &value
			}
			info.Columns = append(info.Columns, ColumnInfo{
				Name:       name,
				DataType:   dataType,
				Nullable:   nullable,
				Default:    maskedDefault,
				PrimaryKey: primaryKey,
			})
		}
	}
	return rows.Err()
}

func loadIndexes(ctx context.Context, pool *pgxpool.Pool, tables map[string]*TableInfo) error {
	const query = `
		SELECT n.nspname,
		       c.relname,
		       ic.relname,
		       pg_get_indexdef(i.indexrelid),
		       i.indisunique,
		       i.indisprimary
		FROM pg_index i
		JOIN pg_class ic ON ic.oid = i.indexrelid
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname NOT LIKE 'pg_toast%'
		  AND n.nspname NOT LIKE 'pg_temp%'
		ORDER BY n.nspname, c.relname, ic.relname;
	`
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("load indexes: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var schema, table, name, definition string
		var unique, primary bool
		if err := rows.Scan(&schema, &table, &name, &definition, &unique, &primary); err != nil {
			return fmt.Errorf("scan index: %w", err)
		}
		if info, ok := tables[schema+"."+table]; ok {
			info.Indexes = append(info.Indexes, IndexInfo{
				Name:       name,
				Definition: security.MaskPII(definition),
				Unique:     unique,
				Primary:    primary,
			})
		}
	}
	return rows.Err()
}

func loadForeignKeys(ctx context.Context, pool *pgxpool.Pool, tables map[string]*TableInfo) error {
	const query = `
		SELECT n.nspname,
		       c.relname,
		       con.conname,
		       (
		           SELECT array_agg(att.attname ORDER BY keys.ord)
		           FROM unnest(con.conkey) WITH ORDINALITY AS keys(attnum, ord)
		           JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = keys.attnum
		       ),
		       fn.nspname,
		       fc.relname,
		       (
		           SELECT array_agg(att.attname ORDER BY keys.ord)
		           FROM unnest(con.confkey) WITH ORDINALITY AS keys(attnum, ord)
		           JOIN pg_attribute att ON att.attrelid = con.confrelid AND att.attnum = keys.attnum
		       )
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_class fc ON fc.oid = con.confrelid
		JOIN pg_namespace fn ON fn.oid = fc.relnamespace
		WHERE con.contype = 'f'
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname NOT LIKE 'pg_toast%'
		  AND n.nspname NOT LIKE 'pg_temp%'
		ORDER BY n.nspname, c.relname, con.conname;
	`
	rows, err := pool.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("load foreign keys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var schema, table, name, refSchema, refTable string
		var columns, refColumns []string
		if err := rows.Scan(&schema, &table, &name, &columns, &refSchema, &refTable, &refColumns); err != nil {
			return fmt.Errorf("scan foreign key: %w", err)
		}
		if info, ok := tables[schema+"."+table]; ok {
			info.ForeignKeys = append(info.ForeignKeys, ForeignKeyInfo{
				Name:              name,
				Columns:           columns,
				ReferencesSchema:  refSchema,
				ReferencesTable:   refTable,
				ReferencesColumns: refColumns,
			})
		}
	}
	return rows.Err()
}

func relationKind(relkind string) string {
	switch relkind {
	case "r":
		return "table"
	case "p":
		return "partitioned_table"
	case "v":
		return "view"
	case "m":
		return "materialized_view"
	case "f":
		return "foreign_table"
	default:
		return relkind
	}
}
