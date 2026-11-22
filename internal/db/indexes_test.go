package db

import (
	"strings"
	"testing"
)

func TestIndexName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		table  string
		column string
		want   string
	}{
		{
			name:   "simple",
			table:  "orders",
			column: "customer_id",
			want:   "idx_orders_customer_id",
		},
		{
			name:   "mixed case and dashes",
			table:  "Orders",
			column: "customer-id",
			want:   "idx_orders_customer_id",
		},
		{
			name:   "unicode",
			table:  "usuários",
			column: "correo",
			want:   "idx_usu_rios_correo",
		},
		{
			name:   "only separators",
			table:  "---",
			column: "---",
			want:   "idx_db_guard",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := indexName(tt.table, tt.column); got != tt.want {
				t.Fatalf("indexName(%q, %q) = %q, want %q", tt.table, tt.column, got, tt.want)
			}
		})
	}
}

func TestIndexNameRespectsPostgresLimit(t *testing.T) {
	t.Parallel()

	got := indexName(strings.Repeat("a", 80), strings.Repeat("b", 20))
	if len(got) > 63 {
		t.Fatalf("index name has %d bytes, want <= 63: %q", len(got), got)
	}
}

func TestBuildIndexDDL(t *testing.T) {
	t.Parallel()

	got := buildIndexDDL("public", "orders", "customer_id")
	want := `CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_orders_customer_id" ON "public"."orders" ("customer_id");`
	if got != want {
		t.Fatalf("buildIndexDDL() = %q, want %q", got, want)
	}
}

func TestBuildIndexDDLQuotesUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	got := buildIndexDDL("public", `orders"; DROP TABLE users; --`, "customer_id")
	if strings.Contains(got, `"; DROP TABLE users; --`) && !strings.Contains(got, `"orders""; DROP TABLE users; --"`) {
		t.Fatalf("identifier was not safely quoted: %q", got)
	}
}
