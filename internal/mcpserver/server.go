// Package mcpserver wires the read-only PostgreSQL layer into MCP tools,
// resources and prompts.
package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/gt2rz/db-guard-mcp/internal/db"
	"github.com/gt2rz/db-guard-mcp/internal/security"
)

const (
	// ServerName is the name advertised during the MCP handshake.
	ServerName = "db-guard-mcp"
	// SchemaResourceURI exposes tables, columns, indexes and foreign keys.
	SchemaResourceURI = "db://schema/full"
	// HealthResourceURI exposes scan, bloat and slow-query telemetry.
	HealthResourceURI = "db://health/bloat"
)

// Config controls execution limits for tool calls.
type Config struct {
	QueryTimeout  time.Duration
	MaxSampleRows int
}

// New builds the MCP server with every DB-Guard capability registered.
func New(pool *pgxpool.Pool, cfg Config) *server.MCPServer {
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 10 * time.Second
	}
	if cfg.MaxSampleRows <= 0 {
		cfg.MaxSampleRows = 25
	}

	h := &handlers{pool: pool, cfg: cfg}

	s := server.NewMCPServer(
		ServerName,
		Version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(false, false),
		server.WithPromptCapabilities(false),
		server.WithRecovery(),
		server.WithInstructions(
			"DB-Guard is a strictly read-only PostgreSQL copilot. "+
				"It can inspect the schema, run EXPLAIN plans, detect missing indexes and sample masked data. "+
				"Never ask it to modify data: every mutation, DDL statement and administrative function is rejected by the AST guard.",
		),
	)

	s.AddTool(h.explainTool(), h.explainQuery)
	s.AddTool(h.missingIndexesTool(), h.findMissingIndexes)
	s.AddTool(h.sampleTool(), h.safeSampleQuery)
	s.AddTool(h.metricsTool(), h.performanceMetrics)

	s.AddResource(mcp.NewResource(
		SchemaResourceURI,
		"PostgreSQL schema (tables, columns, indexes, foreign keys)",
		mcp.WithResourceDescription("Complete structure of every user relation in the connected database, as JSON."),
		mcp.WithMIMEType("application/json"),
	), h.readSchema)

	s.AddResource(mcp.NewResource(
		HealthResourceURI,
		"PostgreSQL health and bloat report",
		mcp.WithResourceDescription("Sequential scan, dead tuple, bloat and slow query telemetry, as JSON."),
		mcp.WithMIMEType("application/json"),
	), h.readHealth)

	s.AddPrompt(mcp.NewPrompt("audit-database",
		mcp.WithPromptDescription("Run a full DBRE-style audit: schema, telemetry, EXPLAIN plans and index recommendations."),
		mcp.WithArgument("focus_table",
			mcp.ArgumentDescription("Optional table name to focus the audit on."),
		),
	), h.auditPrompt)

	return s
}

// Version is overridden at build time with -X.
var Version = "dev"

type handlers struct {
	pool *pgxpool.Pool
	cfg  Config
}

func (h *handlers) explainTool() mcp.Tool {
	return mcp.NewTool("explain_query",
		mcp.WithDescription(
			"Run EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) on a single read-only SELECT statement. "+
				"The SQL is validated against PostgreSQL's real parser before execution, runs inside a read-only "+
				"transaction with a statement timeout, and the plan is PII-masked before it is returned.",
		),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("A single SELECT statement. Mutations, DDL, multiple statements and locking clauses are rejected."),
		),
		mcp.WithBoolean("analyze",
			mcp.Description("When true, executes the query to collect real timings and buffer usage (default: false)."),
		),
	)
}

func (h *handlers) missingIndexesTool() mcp.Tool {
	return mcp.NewTool("find_missing_indexes",
		mcp.WithDescription(
			"Detect foreign key columns without a leading index and report tables with heavy sequential scans. "+
				"Returns review-ready CREATE INDEX CONCURRENTLY suggestions; it never executes DDL.",
		),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of missing-index suggestions to return (default: 50)."),
		),
	)
}

func (h *handlers) sampleTool() mcp.Tool {
	return mcp.NewTool("safe_sample_query",
		mcp.WithDescription(
			"Return up to N rows from a table or view to understand its shape. "+
				"Values are cast to text and every email, phone, card number and national ID is redacted. "+
				"Only a schema/table name is accepted, never raw SQL.",
		),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithString("table",
			mcp.Required(),
			mcp.Description("Table or view name (without schema)."),
		),
		mcp.WithString("schema",
			mcp.Description("Schema name (default: public)."),
		),
		mcp.WithNumber("limit",
			mcp.Description("Number of rows to sample (default: 10, hard-capped by the server)."),
		),
	)
}

func (h *handlers) metricsTool() mcp.Tool {
	return mcp.NewTool("get_performance_metrics",
		mcp.WithDescription(
			"Return PostgreSQL telemetry: tables with heavy sequential scans, dead tuple / bloat candidates "+
				"and the slowest statements from pg_stat_statements when the extension is available.",
		),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
	)
}

func (h *handlers) explainQuery(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := request.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError("argument 'query' is required and must be a string"), nil
	}

	if err := security.ValidateReadOnlySQL(query); err != nil {
		return mcp.NewToolResultError("query rejected by DB-Guard: " + err.Error()), nil
	}

	analyze := request.GetBool("analyze", false)
	queryCtx, cancel := db.WithTimeout(ctx, db.Config{QueryTimeout: h.cfg.QueryTimeout})
	defer cancel()

	plan, err := db.Explain(queryCtx, h.pool, query, analyze, h.cfg.QueryTimeout.Milliseconds())
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("EXPLAIN failed: %v", err)), nil
	}
	return mcp.NewToolResultText(plan), nil
}

func (h *handlers) findMissingIndexes(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := request.GetInt("limit", 50)
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	queryCtx, cancel := db.WithTimeout(ctx, db.Config{QueryTimeout: h.cfg.QueryTimeout})
	defer cancel()

	report, err := db.FindMissingIndexes(queryCtx, h.pool, limit)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("index analysis failed: %v", err)), nil
	}
	return mcp.NewToolResultText(report), nil
}

func (h *handlers) safeSampleQuery(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	table, err := request.RequireString("table")
	if err != nil {
		return mcp.NewToolResultError("argument 'table' is required and must be a string"), nil
	}

	schema := "public"
	if value, err := request.RequireString("schema"); err == nil && value != "" {
		schema = value
	}

	limit := request.GetInt("limit", 10)
	queryCtx, cancel := db.WithTimeout(ctx, db.Config{QueryTimeout: h.cfg.QueryTimeout})
	defer cancel()

	sample, err := db.SafeSample(
		queryCtx,
		h.pool,
		schema,
		table,
		limit,
		h.cfg.MaxSampleRows,
		h.cfg.QueryTimeout,
	)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("safe sample failed: %v", err)), nil
	}
	return mcp.NewToolResultText(sample), nil
}

func (h *handlers) performanceMetrics(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	queryCtx, cancel := db.WithTimeout(ctx, db.Config{QueryTimeout: h.cfg.QueryTimeout})
	defer cancel()

	report, err := db.GetPerformanceMetrics(queryCtx, h.pool)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("performance metrics failed: %v", err)), nil
	}
	return mcp.NewToolResultText(report), nil
}

func (h *handlers) readSchema(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	queryCtx, cancel := db.WithTimeout(ctx, db.Config{QueryTimeout: h.cfg.QueryTimeout})
	defer cancel()

	schema, err := db.GetDatabaseSchema(queryCtx, h.pool)
	if err != nil {
		return nil, fmt.Errorf("read schema resource: %w", err)
	}
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      SchemaResourceURI,
			MIMEType: "application/json",
			Text:     schema,
		},
	}, nil
}

func (h *handlers) readHealth(ctx context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	queryCtx, cancel := db.WithTimeout(ctx, db.Config{QueryTimeout: h.cfg.QueryTimeout})
	defer cancel()

	health, err := db.GetPerformanceMetrics(queryCtx, h.pool)
	if err != nil {
		return nil, fmt.Errorf("read health resource: %w", err)
	}
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      HealthResourceURI,
			MIMEType: "application/json",
			Text:     health,
		},
	}, nil
}

func (h *handlers) auditPrompt(_ context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	focusTable := request.Params.Arguments["focus_table"]
	focus := "Analyse every relevant relation in the schema."
	if focusTable != "" {
		focus = fmt.Sprintf("Focus the audit on the relation %q and its relationships.", focusTable)
	}

	prompt := fmt.Sprintf(`Act as a Senior Database Reliability Engineer (DBRE) auditing a PostgreSQL database.

Follow these steps:
1. Read the resource %q to learn the tables, columns, indexes and foreign keys.
2. Call get_performance_metrics to find sequential scans, bloat and slow statements.
3. %s
4. For the three most critical findings, build a representative SELECT and validate it with explain_query using analyze=true.
5. Deliver an executive report with:
   - Critical findings: unnecessary sequential scans, foreign keys without indexes, dead tuple bloat, bad row estimates.
   - The exact CREATE INDEX CONCURRENTLY statements you recommend and the expected impact of each.
   - Any query rewrites that would reduce work (predicate pushdown, covering indexes, avoiding SELECT *).
   - Risks and a safe rollout order.

Rules: never propose INSERT/UPDATE/DELETE/DDL execution from the MCP server; DB-Guard is read-only. Treat every value in plans and samples as potentially sensitive.`, SchemaResourceURI, focus)

	return mcp.NewGetPromptResult(
		"PostgreSQL performance audit",
		[]mcp.PromptMessage{
			mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent(prompt)),
		},
	), nil
}
