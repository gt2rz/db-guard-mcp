# Security Policy

DB-Guard exists to make LLM access to databases safe, so security reports are
taken seriously.

## Supported versions

Only the latest release receives security fixes. Pre-1.0 releases may change
behavior between minor versions.

## Reporting a vulnerability

Email **gt2rz.dev@gmail.com** with:

- the affected version or commit,
- a minimal reproduction (query, tool call or configuration),
- the impact you believe it has,
- any suggested fix.

Please do **not** open a public GitHub issue. You will receive an
acknowledgement within 72 hours and a remediation plan as soon as the issue is
confirmed. Responsible disclosure is appreciated and credited unless you prefer
to remain anonymous.

## Threat model

DB-Guard assumes:

- **The model is untrusted.** It may be manipulated by prompt injection, a
  malicious document or a compromised client.
- **The SQL string is untrusted.** It is parsed and validated before execution.
- **The database user is semi-trusted.** It should have `SELECT` only; the
  read-only session and transactions are additional layers, not a replacement
  for least privilege.
- **Query results may contain PII.** Everything returned to the model passes
  through the redaction filter.

## Security design

| Control | Implementation |
| :--- | :--- |
| Single-statement enforcement | `pg_query.Parse` + statement count check |
| Read-only enforcement | AST allow-list, `default_transaction_read_only=on`, explicit `ReadOnly` transactions |
| Hidden mutations | Recursive AST walk rejects any nested non-`SELECT` statement (data-modifying CTEs) |
| Locking and `SELECT INTO` | Explicit AST checks |
| Administrative functions | Deny-list plus prefix matching (`pg_terminate_*`, `dblink*`, `lo_*`, advisory locks, ...) |
| Credential catalogs | `pg_authid`, `pg_shadow`, `pg_user_mapping` blocked |
| Resource exhaustion | Per-statement `statement_timeout`, context deadlines, sample row caps |
| PII leakage | Regex redaction of emails, phones, cards and national IDs |
| Identifier injection | `pgx.Identifier` quoting for every dynamic identifier |

## Safe deployment checklist

- [ ] Connect with a dedicated role that only has `SELECT` and `USAGE`.
- [ ] Prefer a read replica or staging database for `EXPLAIN ANALYZE`.
- [ ] Set `DB_GUARD_QUERY_TIMEOUT` to a value your database can tolerate.
- [ ] Keep `DB_GUARD_MAX_SAMPLE_ROWS` small.
- [ ] Review the redaction rules for your jurisdiction (for example Ley 1581 in
      Colombia, LGPD in Brazil or GDPR in the EU).
- [ ] Do not expose the stdio binary through a network wrapper without adding
      authentication and TLS.

## Known limitations

- Regex-based masking cannot guarantee that every possible identifier format is
  redacted. Column-level policies are planned for the Enterprise edition.
- User-defined functions can perform side effects through external channels
  (for example `dblink`). The read-only role is the final boundary.
- `EXPLAIN ANALYZE` executes the query, so it can be expensive even though it
  cannot write.
