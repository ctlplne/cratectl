-- SPDX-License-Identifier: BUSL-1.1
-- Migration 4: source configuration epochs and immutable change receipts.
ALTER TABLE cratectl.repositories ADD COLUMN source_revision bigint NOT NULL DEFAULT 0 CHECK(source_revision>=0);
ALTER TABLE cratectl.retrievals ADD COLUMN source_revision bigint NOT NULL DEFAULT 0 CHECK(source_revision>=0);
ALTER TABLE cratectl.artifacts ADD COLUMN source_revision bigint NOT NULL DEFAULT 0 CHECK(source_revision>=0);
ALTER TABLE cratectl.tags ADD COLUMN source_revision bigint NOT NULL DEFAULT 0 CHECK(source_revision>=0);
ALTER TABLE cratectl.native_sources ADD COLUMN source_revision bigint NOT NULL DEFAULT 0 CHECK(source_revision>=0);
ALTER TABLE cratectl.native_sources DROP CONSTRAINT native_sources_pkey;
ALTER TABLE cratectl.native_sources ADD PRIMARY KEY(tenant,repository,source_revision,key);
CREATE TABLE cratectl.repository_configurations (
 tenant text NOT NULL, repository text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), previous_revision bigint NOT NULL CHECK(previous_revision>=0),
 previous_settings jsonb NOT NULL, settings jsonb NOT NULL,
 reason text NOT NULL CHECK(octet_length(reason)<=1024), actor text NOT NULL,
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp(), change_sequence bigint NOT NULL CHECK(change_sequence>0),
 PRIMARY KEY(tenant,repository,revision),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
ALTER TABLE cratectl.repository_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.repository_configurations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.repository_configurations
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
REVOKE ALL ON cratectl.repository_configurations FROM PUBLIC,cratectl_app;
GRANT SELECT,INSERT ON cratectl.repository_configurations TO cratectl_app;
