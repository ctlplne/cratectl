-- SPDX-License-Identifier: BUSL-1.1
-- Immutable graph evidence shares the schema17 selected-payload lifecycle.
-- Do not widen or rewrite the existing selected-root manifest or old row bytes.
CREATE TABLE cratectl.artifact_export_set_requirements (
 tenant text NOT NULL, set_id text NOT NULL,
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),
 manifest_size bigint NOT NULL CHECK(manifest_size BETWEEN 1 AND 16777216),
 main_digest text NOT NULL CHECK(main_digest ~ '^[a-f0-9]{64}$'),
 main_size bigint NOT NULL CHECK(main_size BETWEEN 1 AND 1048576),
 proof_digest text NOT NULL CHECK(proof_digest ~ '^[a-f0-9]{64}$'),
 proof_size bigint NOT NULL CHECK(proof_size BETWEEN 1 AND 2097152),
 source_count integer NOT NULL CHECK(source_count BETWEEN 1 AND 1024),
 prepared_at timestamptz NOT NULL,
 observed_sequence bigint NOT NULL CHECK(observed_sequence>=0),
 observed_hash text NOT NULL,
 CHECK((observed_sequence=0 AND observed_hash='') OR (observed_sequence>0 AND observed_hash ~ '^[a-f0-9]{64}$')),
 PRIMARY KEY(tenant,set_id),
 FOREIGN KEY(tenant,set_id) REFERENCES cratectl.artifact_export_sets(tenant,id)
);
CREATE INDEX artifact_export_set_requirements_manifest ON cratectl.artifact_export_set_requirements(tenant,manifest_digest);
CREATE INDEX artifact_export_set_requirements_main ON cratectl.artifact_export_set_requirements(tenant,main_digest);
CREATE INDEX artifact_export_set_requirements_proof ON cratectl.artifact_export_set_requirements(tenant,proof_digest);
CREATE TABLE cratectl.artifact_export_set_requirement_sources (
 tenant text NOT NULL, set_id text NOT NULL,
 ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 1023),
 repository text NOT NULL, source_revision bigint NOT NULL CHECK(source_revision>=0),
 module text NOT NULL CHECK(octet_length(module) BETWEEN 1 AND 512),
 version text NOT NULL CHECK(octet_length(version) BETWEEN 1 AND 128),
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),
 manifest_size bigint NOT NULL CHECK(manifest_size BETWEEN 1 AND 32768),
 mod_digest text NOT NULL CHECK(mod_digest ~ '^[a-f0-9]{64}$'),
 mod_size bigint NOT NULL CHECK(mod_size BETWEEN 1 AND 1048576),
 PRIMARY KEY(tenant,set_id,ordinal), UNIQUE(tenant,set_id,module,version),
 FOREIGN KEY(tenant,set_id) REFERENCES cratectl.artifact_export_set_requirements(tenant,set_id),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
CREATE INDEX artifact_export_set_requirement_sources_manifest ON cratectl.artifact_export_set_requirement_sources(tenant,manifest_digest);
CREATE INDEX artifact_export_set_requirement_sources_mod ON cratectl.artifact_export_set_requirement_sources(tenant,mod_digest);
ALTER TABLE cratectl.artifact_export_set_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.artifact_export_set_requirements FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.artifact_export_set_requirements
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
ALTER TABLE cratectl.artifact_export_set_requirement_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.artifact_export_set_requirement_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.artifact_export_set_requirement_sources
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
REVOKE ALL ON cratectl.artifact_export_set_requirements,cratectl.artifact_export_set_requirement_sources FROM PUBLIC,cratectl_app;
GRANT SELECT,INSERT ON cratectl.artifact_export_set_requirements,cratectl.artifact_export_set_requirement_sources TO cratectl_app;
