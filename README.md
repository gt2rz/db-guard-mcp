# 🛡️ DB-Guard MCP

**A read-only, AST-validated PostgreSQL auditing and query-optimization MCP server written in Go.**

DB-Guard lets AI assistants such as **Claude Desktop**, **Claude Code** and any MCP-compatible client inspect schemas, diagnose slow queries with `EXPLAIN ANALYZE`, detect missing indexes and sample data shape — **without exposing production databases to mutations, SQL injection or PII leaks**.

[![CI](https://github.com/gt2rz/db-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/gt2rz/db-guard-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/gt2rz/db-guard-mcp?sort=semver)](https://github.com/gt2rz/db-guard-mcp/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/gt2rz/db-guard-mcp)](https://goreportcard.com/report/github.com/gt2rz/db-guard-mcp)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Why DB-Guard?

Giving an LLM a database connection is usually a bad idea: a single hallucinated `DELETE`, an overlooked `WITH ... AS (DELETE ...)` CTE or a leaked email in an `EXPLAIN` filter is enough to turn a demo into an incident.

DB-Guard treats the model as an **untrusted client**:

- Every query is parsed with **PostgreSQL's own parser** (compiled to WebAssembly, no CGO) and must be exactly **one read-only `SELECT`**.
- Every session is opened with `default_transaction_read_only=on`; every statement runs inside a read-only transaction with a hard timeout.
- Every plan, log line and sampled row passes through a **PII redaction filter** before it reaches the model.
- The server only ships tools that inspect, never tools that mutate.

---

## Architecture

```mermaid
flowchart LR
    Client["Claude Desktop / Claude Code"] -->|"MCP over stdio"| Server["db-guard-mcp"]

    subgraph Guard["Security layer"]
        Server --> AST["AST guard<br/>pg_query (WASM)"]
        AST -->|"rejected"| Client
        AST -->|"single SELECT"| TX["Read-only transaction<br/>statement_timeout"]
    end

    TX --> PG[("PostgreSQL")]
    PG -->|"plans, stats, samples"| Mask["PII redaction"]
    Mask -->|"sanitized JSON"| Client
```

### Defense in depth

| Layer | What it does | Where |
| :--- | :--- | :--- |
| **1. AST policy** | Rejects DDL/DML, multiple statements, data-modifying CTEs, `SELECT INTO`, `FOR UPDATE/SHARE`, administrative functions and credential catalogs. | `internal/security/guard.go` |
| **2. Session policy** | Opens every connection with `default_transaction_read_only=on` and a server-side `statement_timeout`. | `internal/db/pool.go` |
| **3. Transaction policy** | Runs each statement in an explicit `ReadOnly` transaction, always rolled back, with a context deadline. | `internal/db/explain.go`, `sample.go` |
| **4. Redaction** | Masks emails, phones, payment cards and national IDs in plans, `pg_stat_statements` and sampled rows. | `internal/security/mask.go` |
| **5. Least privilege** | Recommended PostgreSQL role with `SELECT` only (see below). | this README |

The guard rejects, among others:

```sql
DELETE FROM users;                                  -- not a SELECT
SELECT * FROM users; DROP TABLE users;              -- multiple statements
WITH d AS (DELETE FROM users RETURNING *)           -- data-modifying CTE
  SELECT * FROM d;
SELECT * INTO backup FROM users;                    -- SELECT INTO
SELECT * FROM accounts FOR UPDATE;                  -- row locking
SELECT pg_terminate_backend(12345);                 -- admin function
SELECT nextval('orders_id_seq');                    -- sequence mutation
SELECT * FROM pg_authid;                            -- credential catalog
```

---

## MCP capabilities

| Primitive | Name | Description |
| :--- | :--- | :--- |
| **Tool** | `explain_query` | `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` on one validated `SELECT`. |
| **Tool** | `find_missing_indexes` | Unindexed foreign keys + heavy sequential scans, with `CREATE INDEX CONCURRENTLY` suggestions. |
| **Tool** | `safe_sample_query` | Up to N rows of a table/view, every value cast to text and PII-masked. |
| **Tool** | `get_performance_metrics` | `pg_stat_user_tables` scans/bloat + slow statements from `pg_stat_statements`. |
| **Resource** | `db://schema/full` | Tables, columns, types, indexes, foreign keys and estimated row counts. |
| **Resource** | `db://health/bloat` | Scan, dead tuple and slow query telemetry. |
| **Prompt** | `audit-database` | Guided DBRE workflow that combines schema, metrics, `EXPLAIN` and index advice. |

---

## Quickstart

### 1. Build

Requires **Go 1.26+** and **PostgreSQL 13+** (tested against PostgreSQL 16).

```bash
git clone https://github.com/gt2rz/db-guard-mcp.git
cd db-guard-mcp
make build          # or: go build -o db-guard-mcp ./cmd/server
```

Or install directly:

```bash
go install github.com/gt2rz/db-guard-mcp/cmd/server@latest
```

### 2. Start the demo database (optional)

The demo ships with 20k customers, 100k orders, a foreign key **without an index** and realistic PII, so you can see the guard and the optimizer work immediately.

```bash
docker compose up -d
```

It listens on `localhost:55432` (not 5432, to avoid clashing with a local PostgreSQL).

### 3. Connect Claude Desktop

Add this to `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "db-guard": {
      "command": "/absolute/path/to/db-guard-mcp",
      "env": {
        "DATABASE_URL": "postgres://devuser:devpassword@localhost:55432/ecommerce_demo?sslmode=disable"
      }
    }
  }
}
```

Restart Claude Desktop and ask:

> Read `db://schema/full`, find foreign keys without an index and validate the worst offender with `explain_query` using `analyze: true`.

### 4. Connect Claude Code

```bash
claude mcp add db-guard \
  -e DATABASE_URL="postgres://devuser:devpassword@localhost:55432/ecommerce_demo?sslmode=disable" \
  -- /absolute/path/to/db-guard-mcp
```

Verify the connection:

```bash
DATABASE_URL="postgres://..." ./db-guard-mcp --check
```

---

## Example prompts

- *"Use `safe_sample_query` on `customers` and describe the data shape. Do not show raw values."*
- *"Run `get_performance_metrics`, pick the three worst tables and explain why they are slow."*
- *"Use `find_missing_indexes` and give me the exact `CREATE INDEX CONCURRENTLY` statements, ordered by impact."*
- *"Compare the plan of `SELECT ... WHERE customer_id = 450` before and after adding the suggested index. Use a hypothetical plan if you cannot create it."*
- *"Audit the `orders` table with the `audit-database` prompt and produce an executive summary for my team."*

---

## Configuration

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `DATABASE_URL` | ✅ | — | libpq connection string. |
| `DB_GUARD_QUERY_TIMEOUT` | ❌ | `10s` | Per-statement timeout, between `1s` and `5m`. |
| `DB_GUARD_MAX_SAMPLE_ROWS` | ❌ | `25` | Hard ceiling for `safe_sample_query`, between 1 and 200. |

Useful flags:

```bash
db-guard-mcp --version   # print the build version
db-guard-mcp --check     # verify connectivity and exit
```

### Recommended read-only role

Never connect DB-Guard with a superuser. Use a dedicated role:

```sql
CREATE ROLE db_guard LOGIN PASSWORD 'change-me';
GRANT CONNECT ON DATABASE app TO db_guard;
GRANT USAGE ON SCHEMA public TO db_guard;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO db_guard;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO db_guard;

-- Lets the metrics tools read pg_stat_statements for every user.
GRANT pg_monitor TO db_guard;
```

`pg_monitor` is optional; without it, DB-Guard degrades gracefully and reports only the metrics the role can see.

---

## Development

```bash
make demo-up            # start PostgreSQL 16 + demo data
make test               # unit tests with the race detector
make test-integration   # real PostgreSQL integration tests
make smoke              # full MCP handshake over stdio
make lint               # go vet + gofmt check
```

Project layout:

```
cmd/server/            MCP entrypoint (stdio transport)
internal/security/     AST guard + PII redaction
internal/db/           read-only pool, schema, stats, indexes, samples
internal/mcpserver/    tools, resources, prompts
scripts/smoke_test.py  end-to-end MCP smoke test
init.sql               demo schema and 100k-row dataset
docker-compose.yml     disposable PostgreSQL 16 instance
```

Tests cover the attack surface explicitly: multi-statement injection, data-modifying CTEs, `SELECT INTO`, locking clauses, administrative functions, sensitive catalogs, plus masking of emails, phones, cards and IDs.

---

## Limitations

- **PostgreSQL only.** MySQL, SQL Server and Snowflake are on the roadmap.
- `explain_query` with `analyze: true` **executes** the query. It is read-only and time-bounded, but it still consumes resources — prefer staging or a read replica for heavy plans.
- Regex-based masking is intentionally conservative, not a compliance guarantee. For column-level policies and audit logs, see the Enterprise edition below.
- A user-defined function could perform side effects through external channels (for example `dblink`). The read-only role is the ultimate boundary.

---

## Roadmap

- [x] AST guard, read-only execution, PII masking
- [x] Schema and health resources
- [x] Guided audit prompt
- [x] Multi-platform releases with GoReleaser
- [ ] Streamable HTTP transport with OAuth/SSO
- [ ] YAML-defined masking policies
- [ ] Exportable audit logs
- [ ] MySQL and SQL Server adapters

---

## License

The Community edition is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for third-party attributions.

**Enterprise edition (planned):** remote Streamable HTTP transport, OAuth/SSO, configurable masking policies and SOC2-friendly audit logs. For early access or commercial licensing, open an issue or contact the maintainer.

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
