-- SPDX-License-Identifier: BUSL-1.1
-- One immutable common manifest and ordered selection, independent of legacy exports.
CREATE TABLE cratectl.artifact_export_sets (
 tenant text NOT NULL, id text NOT NULL CHECK(id ~ '^[a-f0-9]{64}$'),
 actor text NOT NULL CHECK(octet_length(actor) BETWEEN 1 AND 256),
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),
 manifest_size bigint NOT NULL CHECK(manifest_size BETWEEN 1 AND 8388608),
 root_count integer NOT NULL CHECK(root_count BETWEEN 1 AND 256),
 artifact_bytes bigint NOT NULL CHECK(artifact_bytes BETWEEN 0 AND 68719476736),
 state text NOT NULL CHECK(state IN ('open','acknowledged','cancelled','expired')),
 generation bigint NOT NULL CHECK(generation>0),
 created_sequence bigint NOT NULL CHECK(created_sequence>0),
 change_sequence bigint NOT NULL CHECK(change_sequence>=created_sequence),
 created_at timestamptz NOT NULL, changed_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL, max_expires_at timestamptz NOT NULL,
 CHECK(expires_at>created_at AND expires_at<=max_expires_at),
 CHECK(max_expires_at<=created_at+interval '24 hours'),
 PRIMARY KEY(tenant,id), UNIQUE(tenant,created_sequence),
 FOREIGN KEY(tenant,created_sequence) REFERENCES cratectl.events(tenant,sequence) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(tenant,change_sequence) REFERENCES cratectl.events(tenant,sequence) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX artifact_export_sets_manifest ON cratectl.artifact_export_sets(tenant,manifest_digest);
CREATE INDEX artifact_export_sets_due ON cratectl.artifact_export_sets(tenant,expires_at,id) WHERE state IN ('open','acknowledged');
CREATE TABLE cratectl.artifact_export_set_roots (
 tenant text NOT NULL, set_id text NOT NULL,
 ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 255),
 repository text NOT NULL, source_revision bigint NOT NULL CHECK(source_revision>=0),
 module text NOT NULL CHECK(octet_length(module) BETWEEN 1 AND 512),
 version text NOT NULL CHECK(octet_length(version) BETWEEN 1 AND 128),
 PRIMARY KEY(tenant,set_id,ordinal), UNIQUE(tenant,set_id,module,version),
 FOREIGN KEY(tenant,set_id) REFERENCES cratectl.artifact_export_sets(tenant,id),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
CREATE TABLE cratectl.artifact_export_set_items (
 tenant text NOT NULL, set_id text NOT NULL,
 root_ordinal integer NOT NULL, ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 2),
 path text NOT NULL CHECK(octet_length(path) BETWEEN 1 AND 2048),
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),
 size bigint NOT NULL CHECK(size BETWEEN 0 AND 536870912),
 PRIMARY KEY(tenant,set_id,root_ordinal,ordinal), UNIQUE(tenant,set_id,path),
 FOREIGN KEY(tenant,set_id,root_ordinal) REFERENCES cratectl.artifact_export_set_roots(tenant,set_id,ordinal)
);
CREATE INDEX artifact_export_set_items_digest ON cratectl.artifact_export_set_items(tenant,digest,set_id);
ALTER TABLE cratectl.artifact_export_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.artifact_export_sets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.artifact_export_sets
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
ALTER TABLE cratectl.artifact_export_set_roots ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.artifact_export_set_roots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.artifact_export_set_roots
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
ALTER TABLE cratectl.artifact_export_set_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.artifact_export_set_items FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.artifact_export_set_items
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
REVOKE ALL ON cratectl.artifact_export_sets,cratectl.artifact_export_set_roots,cratectl.artifact_export_set_items FROM PUBLIC,cratectl_app;
GRANT SELECT,INSERT ON cratectl.artifact_export_sets,cratectl.artifact_export_set_roots,cratectl.artifact_export_set_items TO cratectl_app;
GRANT UPDATE(state,generation,change_sequence,changed_at,expires_at) ON cratectl.artifact_export_sets TO cratectl_app;
