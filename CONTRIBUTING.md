# Contributing to DB-Guard MCP

Thanks for taking the time to improve DB-Guard. This project handles database
connections for AI assistants, so security and predictability matter more than
cleverness.

## Development setup

Requirements:

- Go 1.26+
- Docker (optional, for the demo database)
- Python 3 (optional, for the end-to-end smoke test)

```bash
git clone https://github.com/gt2rz/db-guard-mcp.git
cd db-guard-mcp
make demo-up
make test
make test-integration
make smoke
```

## Workflow

1. Fork the repository and create a branch from `main`
   (`git checkout -b feat/short-description`).
2. Keep changes focused. One logical change per pull request.
3. Run the full local check before opening the PR:

   ```bash
   make lint
   make test
   make test-integration
   ```

4. Describe the problem, the solution and any security implications in the PR.

## Adding capabilities

- Tools, resources and prompts live in `internal/mcpserver/server.go`.
- Database access belongs in `internal/db`; it must remain read-only.
- Any new SQL path must go through `security.ValidateReadOnlySQL` when it
  accepts user-provided SQL, and through `security.MaskPII` before returning
  data to the model.
- Add a test for every new rejection rule or masking rule.

## Code style

- Run `gofmt -s -w .`.
- Prefer standard library and explicit error wrapping (`%w`).
- Keep exported identifiers documented.
- No `panic` outside tests.
- Do not log connection strings or query results.

## Commit messages

Use a short imperative subject line, optionally with a conventional prefix:

```
feat: add MySQL adapter skeleton
fix: reject nested COPY statements
docs: document the read-only role
test: cover blocked functions in CTEs
```

## Contributor License Agreement

By submitting a pull request or any other contribution, you agree that:

1. Your contribution is licensed under the Apache License 2.0, and
2. You grant the project maintainer a perpetual, worldwide, non-exclusive,
   royalty-free right to use, modify and distribute your contribution in both
   the open-source Community edition and any commercial or Enterprise edition
   of DB-Guard MCP.

Only submit work you have the right to license.

## Reporting security issues

Please do not open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md).
