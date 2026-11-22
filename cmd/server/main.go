// Command db-guard-mcp is a read-only PostgreSQL auditing MCP server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"github.com/gt2rz/db-guard-mcp/internal/db"
	"github.com/gt2rz/db-guard-mcp/internal/mcpserver"
)

// version is injected at build time by GoReleaser.
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	checkOnly := flag.Bool("check", false, "verify the database connection and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg)
	if err != nil {
		log.Fatalf("database error: %v", err)
	}
	defer pool.Close()

	if *checkOnly {
		log.Printf("db-guard-mcp %s: database connection OK", version)
		return
	}

	mcpserver.Version = version
	mcpServer := mcpserver.New(pool, mcpserver.Config{
		QueryTimeout:  cfg.QueryTimeout,
		MaxSampleRows: cfg.MaxSampleRows,
	})

	log.Printf("db-guard-mcp %s: connected in read-only mode, serving MCP over stdio", version)
	if err := server.ServeStdio(mcpServer); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

func loadConfig() (db.Config, error) {
	cfg := db.DefaultConfig()
	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.DatabaseURL == "" {
		return cfg, fmt.Errorf("DATABASE_URL is required (example: postgres://user:pass@localhost:5432/db?sslmode=disable)")
	}

	if raw := os.Getenv("DB_GUARD_QUERY_TIMEOUT"); raw != "" {
		timeout, err := time.ParseDuration(raw)
		if err != nil {
			return cfg, fmt.Errorf("invalid DB_GUARD_QUERY_TIMEOUT %q: %w", raw, err)
		}
		if timeout < time.Second || timeout > 5*time.Minute {
			return cfg, fmt.Errorf("DB_GUARD_QUERY_TIMEOUT must be between 1s and 5m")
		}
		cfg.QueryTimeout = timeout
	}

	if raw := os.Getenv("DB_GUARD_MAX_SAMPLE_ROWS"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			return cfg, fmt.Errorf("DB_GUARD_MAX_SAMPLE_ROWS must be an integer between 1 and 200")
		}
		cfg.MaxSampleRows = limit
	}

	return cfg, nil
}
