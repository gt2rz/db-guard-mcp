-- Demo dataset for DB-Guard MCP.
--
-- It intentionally ships with:
--   * a foreign key (orders.customer_id) that has no index,
--   * 100k orders so sequential scans are visible in pg_stat_user_tables,
--   * realistic PII in customers so the redaction filter can be verified.

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

CREATE TABLE customers (
    id           SERIAL PRIMARY KEY,
    full_name    TEXT NOT NULL,
    email        TEXT NOT NULL,
    phone        TEXT NOT NULL,
    national_id  TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE orders (
    id           SERIAL PRIMARY KEY,
    customer_id  INT NOT NULL REFERENCES customers (id),
    status       TEXT NOT NULL,
    total_amount NUMERIC(10, 2) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX orders_created_at_idx ON orders (created_at);

CREATE VIEW completed_orders AS
    SELECT id, customer_id, total_amount, created_at
    FROM orders
    WHERE status = 'COMPLETED';

INSERT INTO customers (full_name, email, phone, national_id)
SELECT
    'Customer ' || g,
    'customer' || g || '@example.com',
    '+57 300 ' || lpad((g % 1000)::text, 3, '0') || ' ' || lpad(((g * 7) % 10000)::text, 4, '0'),
    (10000000 + g)::text
FROM generate_series(1, 20000) AS g;

INSERT INTO orders (customer_id, status, total_amount, created_at)
SELECT
    (random() * 19999 + 1)::int,
    CASE WHEN random() > 0.2 THEN 'COMPLETED' ELSE 'PENDING' END,
    round((random() * 500 + 10)::numeric, 2),
    now() - (random() * interval '180 days')
FROM generate_series(1, 100000) AS g;

ANALYZE customers;
ANALYZE orders;

-- Generate some traffic so pg_stat_user_tables and pg_stat_statements have
-- something to report on first boot.
SELECT count(*) FROM orders WHERE customer_id = 450 AND status = 'PENDING';
SELECT count(*) FROM orders WHERE created_at > now() - interval '30 days';
