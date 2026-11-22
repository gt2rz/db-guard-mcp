//go:build integration

package db

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func integrationConfig(t *testing.T) Config {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration tests")
	}

	cfg := DefaultConfig()
	cfg.DatabaseURL = url
	cfg.QueryTimeout = 15 * time.Second
	cfg.MaxSampleRows = 10
	return cfg
}

func TestIntegration(t *testing.T) {
	ctx := context.Background()
	cfg := integrationConfig(t)

	pool, err := NewPool(ctx, cfg)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)

	t.Run("schema resource", func(t *testing.T) {
		schema, err := GetDatabaseSchema(ctx, pool)
		if err != nil {
			t.Fatalf("GetDatabaseSchema: %v", err)
		}
		for _, want := range []string{`"customers"`, `"orders"`, `"completed_orders"`, "customer_id"} {
			if !strings.Contains(schema, want) {
				t.Fatalf("schema does not contain %q", want)
			}
		}
	})

	t.Run("explain is read only and masked", func(t *testing.T) {
		plan, err := Explain(ctx, pool, "SELECT count(*) FROM orders WHERE customer_id = 450", true, 10_000)
		if err != nil {
			t.Fatalf("Explain: %v", err)
		}
		if !strings.Contains(plan, "Plan") {
			t.Fatalf("unexpected plan: %s", plan)
		}
	})

	t.Run("sample masks PII", func(t *testing.T) {
		sample, err := SafeSample(ctx, pool, "public", "customers", 5, 10, 10*time.Second)
		if err != nil {
			t.Fatalf("SafeSample: %v", err)
		}
		if strings.Contains(sample, "@example.com") {
			t.Fatalf("sample leaked an email: %s", sample)
		}
		if !strings.Contains(sample, "[EMAIL_REDACTED]") {
			t.Fatalf("sample does not contain the email placeholder: %s", sample)
		}
		if !strings.Contains(sample, "[ID_REDACTED]") {
			t.Fatalf("sample does not contain the ID placeholder: %s", sample)
		}
	})

	t.Run("performance metrics", func(t *testing.T) {
		metrics, err := GetPerformanceMetrics(ctx, pool)
		if err != nil {
			t.Fatalf("GetPerformanceMetrics: %v", err)
		}
		if !strings.Contains(metrics, "high_seq_scan_tables") {
			t.Fatalf("unexpected metrics payload: %s", metrics)
		}
	})

	t.Run("missing foreign key index", func(t *testing.T) {
		report, err := FindMissingIndexes(ctx, pool, 50)
		if err != nil {
			t.Fatalf("FindMissingIndexes: %v", err)
		}
		if !strings.Contains(report, "idx_orders_customer_id") {
			t.Fatalf("expected a suggestion for orders.customer_id: %s", report)
		}
	})

	t.Run("read-only session", func(t *testing.T) {
		var readOnly string
		if err := pool.QueryRow(ctx, "SHOW default_transaction_read_only").Scan(&readOnly); err != nil {
			t.Fatalf("SHOW default_transaction_read_only: %v", err)
		}
		if readOnly != "on" {
			t.Fatalf("expected a read-only session, got %q", readOnly)
		}
	})
}
