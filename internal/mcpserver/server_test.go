package mcpserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

func newTestHandlers() *handlers {
	return &handlers{
		cfg: Config{
			QueryTimeout:  2 * time.Second,
			MaxSampleRows: 25,
		},
	}
}

func callTool(t *testing.T, h *handlers, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	request := mcp.CallToolRequest{}
	request.Params.Name = name
	request.Params.Arguments = args

	var (
		result *mcp.CallToolResult
		err    error
	)
	switch name {
	case "explain_query":
		result, err = h.explainQuery(context.Background(), request)
	case "find_missing_indexes":
		result, err = h.findMissingIndexes(context.Background(), request)
	case "safe_sample_query":
		result, err = h.safeSampleQuery(context.Background(), request)
	case "get_performance_metrics":
		result, err = h.performanceMetrics(context.Background(), request)
	default:
		t.Fatalf("unknown tool %q", name)
	}
	if err != nil {
		t.Fatalf("%s returned a protocol error: %v", name, err)
	}
	return result
}

func firstText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()

	if len(result.Content) == 0 {
		t.Fatal("tool result has no content")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected text content, got %T", result.Content[0])
	}
	return text.Text
}

func TestExplainQueryRejectsMutationsBeforeTouchingTheDatabase(t *testing.T) {
	t.Parallel()

	h := newTestHandlers()
	result := callTool(t, h, "explain_query", map[string]any{
		"query": "WITH deleted AS (DELETE FROM users RETURNING *) SELECT * FROM deleted;",
	})

	if !result.IsError {
		t.Fatal("expected a tool error for a data-modifying CTE")
	}
	if !strings.Contains(firstText(t, result), "query rejected by DB-Guard") {
		t.Fatalf("unexpected error text: %q", firstText(t, result))
	}
}

func TestExplainQueryRequiresQueryArgument(t *testing.T) {
	t.Parallel()

	h := newTestHandlers()
	result := callTool(t, h, "explain_query", map[string]any{})

	if !result.IsError {
		t.Fatal("expected a tool error when query is missing")
	}
}

func TestSafeSampleRequiresTableArgument(t *testing.T) {
	t.Parallel()

	h := newTestHandlers()
	result := callTool(t, h, "safe_sample_query", map[string]any{})

	if !result.IsError {
		t.Fatal("expected a tool error when table is missing")
	}
}

func TestAuditPrompt(t *testing.T) {
	t.Parallel()

	h := newTestHandlers()

	t.Run("default focus", func(t *testing.T) {
		result, err := h.auditPrompt(context.Background(), mcp.GetPromptRequest{
			Params: mcp.GetPromptParams{Name: "audit-database"},
		})
		if err != nil {
			t.Fatalf("auditPrompt returned error: %v", err)
		}
		if len(result.Messages) != 1 {
			t.Fatalf("expected 1 message, got %d", len(result.Messages))
		}
		text, ok := result.Messages[0].Content.(mcp.TextContent)
		if !ok {
			t.Fatalf("expected text content, got %T", result.Messages[0].Content)
		}
		if !strings.Contains(text.Text, SchemaResourceURI) {
			t.Fatalf("prompt does not reference %s", SchemaResourceURI)
		}
		if !strings.Contains(text.Text, "Analyse every relevant relation") {
			t.Fatalf("unexpected default focus: %q", text.Text)
		}
	})

	t.Run("focus table", func(t *testing.T) {
		result, err := h.auditPrompt(context.Background(), mcp.GetPromptRequest{
			Params: mcp.GetPromptParams{
				Name:      "audit-database",
				Arguments: map[string]string{"focus_table": "orders"},
			},
		})
		if err != nil {
			t.Fatalf("auditPrompt returned error: %v", err)
		}
		text := result.Messages[0].Content.(mcp.TextContent).Text
		if !strings.Contains(text, `"orders"`) {
			t.Fatalf("prompt does not mention the focus table: %q", text)
		}
	})
}

func TestNewRegistersCapabilities(t *testing.T) {
	t.Parallel()

	// A nil pool is fine here: New only stores dependencies and registers
	// handlers, it does not touch the database.
	s := New(nil, Config{QueryTimeout: time.Second, MaxSampleRows: 5})
	if s == nil {
		t.Fatal("New returned nil")
	}
}
