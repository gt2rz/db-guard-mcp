#!/usr/bin/env python3
"""End-to-end smoke test for db-guard-mcp over the stdio transport.

Usage:
    python3 scripts/smoke_test.py ./db-guard-mcp

It expects a reachable demo database in DATABASE_URL (docker compose up -d).
The script performs an MCP handshake, lists capabilities, calls every tool and
asserts that a mutation is rejected by the AST guard.
"""

import json
import os
import select
import subprocess
import sys
import time

BINARY = sys.argv[1] if len(sys.argv) > 1 else "./db-guard-mcp"
TIMEOUT_SECONDS = 60

REQUESTS = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "db-guard-smoke", "version": "0.0.1"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "explain_query",
            "arguments": {
                "query": "SELECT count(*) FROM orders WHERE customer_id = 450",
                "analyze": True,
            },
        },
    },
    {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "explain_query",
            "arguments": {"query": "WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d"},
        },
    },
    {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "safe_sample_query",
            "arguments": {"table": "customers", "limit": 3},
        },
    },
    {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {"name": "find_missing_indexes", "arguments": {}},
    },
    {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "get_performance_metrics", "arguments": {}},
    },
    {"jsonrpc": "2.0", "id": 8, "method": "resources/read", "params": {"uri": "db://schema/full"}},
    {"jsonrpc": "2.0", "id": 9, "method": "prompts/get", "params": {"name": "audit-database"}},
]


def read_responses(process: subprocess.Popen, expected: int) -> dict:
    responses = {}
    deadline = time.monotonic() + TIMEOUT_SECONDS

    while len(responses) < expected:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out after receiving {len(responses)}/{expected} responses")

        ready, _, _ = select.select([process.stdout], [], [], remaining)
        if not ready:
            continue

        line = process.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout before answering every request")

        message = json.loads(line)
        if "id" in message:
            responses[message["id"]] = message

    return responses


def main() -> int:
    env = dict(os.environ)
    env.setdefault(
        "DATABASE_URL",
        "postgres://devuser:devpassword@localhost:55432/ecommerce_demo?sslmode=disable",
    )

    process = subprocess.Popen(
        [BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    try:
        for request in REQUESTS:
            process.stdin.write(json.dumps(request) + "\n")
        process.stdin.flush()

        responses = read_responses(process, expected=len([r for r in REQUESTS if "id" in r]))
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    if process.returncode != 0:
        print(process.stderr.read(), file=sys.stderr)
        print(f"server exited with {process.returncode}", file=sys.stderr)
        return 1

    failures = []

    def text_of(response_id: int) -> str:
        result = responses[response_id].get("result", {})
        content = result.get("content", [])
        return content[0].get("text", "") if content else ""

    tools = {tool["name"] for tool in responses[2]["result"]["tools"]}
    expected_tools = {"explain_query", "find_missing_indexes", "safe_sample_query", "get_performance_metrics"}
    if not expected_tools.issubset(tools):
        failures.append(f"missing tools: {expected_tools - tools}")

    if "Plan" not in text_of(3):
        failures.append("explain_query did not return a plan")

    if not responses[4]["result"].get("isError"):
        failures.append("data-modifying CTE was not rejected")

    sample = text_of(5)
    if "@example.com" in sample:
        failures.append("safe_sample_query leaked an email")
    if "[EMAIL_REDACTED]" not in sample:
        failures.append("safe_sample_query did not redact emails")

    if "idx_orders_customer_id" not in text_of(6):
        failures.append("find_missing_indexes did not detect orders.customer_id")

    if "high_seq_scan_tables" not in text_of(7):
        failures.append("get_performance_metrics returned an unexpected payload")

    schema_contents = responses[8]["result"]["contents"][0]["text"]
    if '"customers"' not in schema_contents:
        failures.append("schema resource does not contain the customers table")

    prompt = responses[9]["result"]["messages"][0]["content"]["text"]
    if "db://schema/full" not in prompt:
        failures.append("audit prompt does not reference the schema resource")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print("OK: handshake, 4 tools, the schema resource and the audit prompt work end to end")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
