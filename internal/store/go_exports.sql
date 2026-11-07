-- SPDX-License-Identifier: BUSL-1.1
-- Immutable manifest/item identity is separate from renewable session state.
CREATE TABLE cratectl.artifact_exports (
 tenant text NOT NULL, id text NOT NULL CHECK(id ~ '^[a-f0-9]{64}$'),
 repository text NOT NULL, source_revision bigint NOT NULL CHECK(source_revision>=0),
 module text NOT NULL CHECK(octet_length(module) BETWEEN 1 AND 512),
 version text NOT NULL CHECK(octet_length(version) BETWEEN 1 AND 128),
 actor text NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 256),
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),
 manifest_size bigint NOT NULL CHECK(manifest_size BETWEEN 1 AND 32768),
 state text NOT NULL CHECK(state IN ('open','acknowledged','cancelled','expired')),
 generation bigint NOT NULL CHECK(generation>0),
 created_sequence bigint NOT NULL CHECK(created_sequence>0),
 change_sequence bigint NOT NULL CHECK(change_sequence>=created_sequence),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL, max_expires_at timestamptz NOT NULL,
 CHECK(expires_at>created_at AND expires_at<=max_expires_at),
 CHECK(max_expires_at<=created_at+interval '24 hours'),
 PRIMARY KEY(tenant,id), UNIQUE(tenant,created_sequence),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name),
 FOREIGN KEY(tenant,created_sequence) REFERENCES cratectl.events(tenant,sequence) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(tenant,change_sequence) REFERENCES cratectl.events(tenant,sequence) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX artifact_exports_manifest ON cratectl.artifact_exports(tenant,manifest_digest);
CREATE TABLE cratectl.artifact_export_items (
 tenant text NOT NULL, export_id text NOT NULL,
 ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 2),
 path text NOT NULL CHECK(octet_length(path) BETWEEN 1 AND 2048),
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),
 size bigint NOT NULL CHECK(size BETWEEN 0 AND 536870912),
 PRIMARY KEY(tenant,export_id,ordinal), UNIQUE(tenant,export_id,path),
 FOREIGN KEY(tenant,export_id) REFERENCES cratectl.artifact_exports(tenant,id)
);
CREATE INDEX artifact_export_items_digest ON cratectl.artifact_export_items(tenant,digest,export_id);
ALTER TABLE cratectl.artifact_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.artifact_exports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.artifact_exports
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
ALTER TABLE cratectl.artifact_export_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.artifact_export_items FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.artifact_export_items
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
REVOKE ALL ON cratectl.artifact_exports,cratectl.artifact_export_items FROM PUBLIC,cratectl_app;
GRANT SELECT,INSERT ON cratectl.artifact_exports,cratectl.artifact_export_items TO cratectl_app;
GRANT UPDATE(state,generation,change_sequence,changed_at,expires_at) ON cratectl.artifact_exports TO cratectl_app;
ALTER TABLE cratectl.inventory_entries ADD COLUMN export_references bigint NOT NULL DEFAULT 0 CHECK(export_references>=0);
