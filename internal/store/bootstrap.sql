-- SPDX-License-Identifier: BUSL-1.1
CREATE TABLE IF NOT EXISTS cratectl.bootstrap_receipts (
 tenant text PRIMARY KEY REFERENCES cratectl.tenants(tenant),
 installation_id text NOT NULL UNIQUE CHECK(installation_id ~ '^[a-f0-9]{64}$'),
 administrator_hash text NOT NULL, worker_hash text NOT NULL,
 actor text NOT NULL, expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
