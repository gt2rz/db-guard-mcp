// Package security implements the defense-in-depth rules that keep DB-Guard
// read-only: SQL validation on PostgreSQL's real parse tree (compiled to WASM,
// no CGO) and PII redaction for everything that is sent back to the model.
package security

import (
	"errors"
	"fmt"
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	pg_query "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Sentinel errors returned by ValidateReadOnlySQL. Callers can match them with
// errors.Is when they need to distinguish a policy rejection from a syntax
// error.
var (
	ErrEmptyQuery         = errors.New("empty SQL query")
	ErrSyntax             = errors.New("SQL syntax error")
	ErrMultipleStatements = errors.New("only a single statement per call is allowed")
	ErrNotReadOnly        = errors.New("only read-only SELECT statements are allowed")
	ErrSelectInto         = errors.New("SELECT INTO is not allowed")
	ErrLockingClause      = errors.New("row locking clauses (FOR UPDATE/SHARE) are not allowed")
	ErrBlockedFunction    = errors.New("blocked function")
	ErrBlockedRelation    = errors.New("access to this system relation is blocked")
)

// blockedFunctions are administrative, side-effectful or data-exfiltrating
// functions. The list is matched against the last component of the function
// name, so schema-qualified calls such as pg_catalog.pg_sleep are caught too.
var blockedFunctions = map[string]struct{}{
	// Process / server administration.
	"pg_terminate_backend":        {},
	"pg_cancel_backend":           {},
	"pg_reload_conf":              {},
	"pg_rotate_logfile":           {},
	"pg_switch_wal":               {},
	"pg_promote":                  {},
	"pg_create_restore_point":     {},
	"pg_export_snapshot":          {},
	"pg_notify":                   {},
	"pg_logical_emit_message":     {},
	"pg_import_system_collations": {},
	"pg_stat_reset":               {},
	// Filesystem / large objects.
	"pg_read_file":        {},
	"pg_read_binary_file": {},
	"pg_ls_dir":           {},
	"pg_stat_file":        {},
	"lo_import":           {},
	"lo_export":           {},
	// Blocking / denial of service.
	"pg_sleep":       {},
	"pg_sleep_for":   {},
	"pg_sleep_until": {},
	// Sequence and session mutation.
	"nextval":    {},
	"setval":     {},
	"set_config": {},
	// Dynamic SQL execution.
	"query_to_xml":               {},
	"query_to_xmlschema":         {},
	"query_to_xml_and_xmlschema": {},
	"cursor_to_xml":              {},
	"cursor_to_xmlschema":        {},
}

// blockedPrefixes catch whole families of dangerous functions.
var blockedPrefixes = []string{
	"dblink",                 // remote execution / SSRF
	"lo_",                    // large object mutation
	"pg_advisory_",           // session-level locks (DoS)
	"pg_try_advisory_",       // session-level locks (DoS)
	"pg_replication_slot_",   // replication administration
	"pg_replication_origin_", // replication administration
	"pg_create_",             // replication slots, restore points
	"pg_drop_",               // replication slots
	"pg_copy_",               // replication slot copies
	"pg_backup_",             // base backup control
	"pg_ls_",                 // directory listings
	"pg_file_",               // adminpack filesystem access
	"pg_stat_reset",          // statistics administration
	"pg_logical_slot_",       // logical decoding consumption
	"pg_wal_replay_",         // recovery control
}

// blockedRelations are catalogs that can leak credential material. The MCP
// database role should never be a superuser, but this is cheap insurance.
var blockedRelations = map[string]struct{}{
	"pg_authid":       {},
	"pg_shadow":       {},
	"pg_user_mapping": {},
}

// ValidateReadOnlySQL parses sql with PostgreSQL's own parser and rejects
// anything that is not exactly one read-only SELECT statement.
//
// It blocks, among other things:
//   - multiple statements (SELECT 1; DROP TABLE users)
//   - every DDL/DML statement (INSERT, UPDATE, DELETE, MERGE, DROP, COPY...)
//   - data-modifying CTEs (WITH d AS (DELETE ...) SELECT * FROM d)
//   - SELECT ... INTO and row locking clauses
//   - administrative and side-effectful function calls anywhere in the tree
func ValidateReadOnlySQL(sql string) error {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return ErrEmptyQuery
	}

	tree, err := pg_query.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSyntax, err)
	}

	if len(tree.GetStmts()) != 1 {
		return fmt.Errorf("%w (received %d)", ErrMultipleStatements, len(tree.GetStmts()))
	}

	stmt := tree.GetStmts()[0].GetStmt()
	if stmt == nil {
		return ErrNotReadOnly
	}

	// The top-level node must be a SELECT. Everything else (including EXPLAIN,
	// SET, BEGIN and utility statements) is rejected here.
	if stmt.GetSelectStmt() == nil {
		return fmt.Errorf("%w (top-level statement is %s)", ErrNotReadOnly, nodeKind(stmt))
	}

	return walkNode(stmt)
}

// walkNode inspects a parse-tree node and then recursively descends into all of
// its children.
func walkNode(node *pgquery.Node) error {
	if node == nil {
		return nil
	}
	msg := node.ProtoReflect()
	if !msg.IsValid() {
		return nil
	}

	oneof := msg.Descriptor().Oneofs().ByName("node")
	if oneof == nil {
		return nil
	}
	field := msg.WhichOneof(oneof)
	if field == nil {
		return nil
	}

	kind := string(field.Name())

	// Any statement node nested inside a SELECT (CTE, sub-select, ...) must
	// itself be a SELECT. This is what catches data-modifying CTEs.
	if strings.HasSuffix(kind, "_stmt") && kind != "select_stmt" {
		return fmt.Errorf("%w: nested %s is not allowed", ErrNotReadOnly, strings.TrimSuffix(kind, "_stmt"))
	}

	switch kind {
	case "select_stmt":
		sel := node.GetSelectStmt()
		if sel.GetIntoClause() != nil {
			return ErrSelectInto
		}
		if len(sel.GetLockingClause()) > 0 {
			return ErrLockingClause
		}
	case "func_call":
		name := funcCallName(node.GetFuncCall())
		if isBlockedFunction(name) {
			return fmt.Errorf("%w: %q", ErrBlockedFunction, name)
		}
	case "range_var":
		name := strings.ToLower(node.GetRangeVar().GetRelname())
		if _, blocked := blockedRelations[name]; blocked {
			return fmt.Errorf("%w: %q", ErrBlockedRelation, name)
		}
	}

	return walkFields(msg)
}

// walkFields visits every populated field of a protobuf message.
func walkFields(msg protoreflect.Message) error {
	var walkErr error
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		walkErr = walkValue(fd, v)
		return walkErr == nil
	})
	return walkErr
}

func walkValue(fd protoreflect.FieldDescriptor, v protoreflect.Value) error {
	if fd.IsList() {
		list := v.List()
		for i := 0; i < list.Len(); i++ {
			if err := walkSingular(fd, list.Get(i)); err != nil {
				return err
			}
		}
		return nil
	}

	if fd.IsMap() {
		var walkErr error
		v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
			walkErr = walkSingular(fd, mv)
			return walkErr == nil
		})
		return walkErr
	}

	return walkSingular(fd, v)
}

func walkSingular(fd protoreflect.FieldDescriptor, v protoreflect.Value) error {
	if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
		return nil
	}

	msg := v.Message()
	if !msg.IsValid() {
		return nil
	}

	// Node is the tagged union that wraps every AST node; inspect it and let
	// walkNode descend into its fields.
	if node, ok := msg.Interface().(*pgquery.Node); ok {
		return walkNode(node)
	}

	return walkFields(msg)
}

func nodeKind(node *pgquery.Node) string {
	msg := node.ProtoReflect()
	oneof := msg.Descriptor().Oneofs().ByName("node")
	if oneof == nil {
		return "unknown"
	}
	field := msg.WhichOneof(oneof)
	if field == nil {
		return "unknown"
	}
	return strings.TrimSuffix(string(field.Name()), "_stmt")
}

// funcCallName returns the lowercased, unqualified name of a function call.
func funcCallName(fc *pgquery.FuncCall) string {
	if fc == nil {
		return ""
	}
	parts := fc.GetFuncname()
	for i := len(parts) - 1; i >= 0; i-- {
		if s := parts[i].GetString_(); s != nil {
			return strings.ToLower(s.GetSval())
		}
	}
	return ""
}

func isBlockedFunction(name string) bool {
	if name == "" {
		return false
	}
	if _, blocked := blockedFunctions[name]; blocked {
		return true
	}
	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
