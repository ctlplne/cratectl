-- SPDX-License-Identifier: BUSL-1.1
-- An old fork label without original authenticated observations is an incident,
-- never newly manufactured cryptographic proof. Preserve its exact event anchor.
CREATE TABLE cratectl.go_checksum_legacy_incidents (
 tenant text NOT NULL, event_sequence bigint NOT NULL CHECK(event_sequence>0),
 event_hash text NOT NULL CHECK(event_hash ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,event_sequence), UNIQUE(tenant,event_sequence,event_hash),
 FOREIGN KEY(tenant,event_sequence) REFERENCES cratectl.events(tenant,sequence)
);
CREATE TABLE cratectl.go_checksum_legacy_reviews (
 tenant text NOT NULL, event_sequence bigint NOT NULL,
 incident_hash text NOT NULL, key_digest text NOT NULL CHECK(key_digest ~ '^[a-f0-9]{64}$'),
 repository text NOT NULL, source_revision bigint NOT NULL CHECK(source_revision>=0),
 verifier_key text NOT NULL CHECK(octet_length(verifier_key) BETWEEN 1 AND 4096),
 checkpoint_revision bigint NOT NULL CHECK(checkpoint_revision>=0),
 checkpoint bytea NOT NULL CHECK(octet_length(checkpoint) BETWEEN 1 AND 16384),
 review_reference_sha256 text NOT NULL CHECK(review_reference_sha256 ~ '^[a-f0-9]{64}$'),
 reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 1024),
 actor text NOT NULL, change_sequence bigint NOT NULL CHECK(change_sequence>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,event_sequence,key_digest),
 FOREIGN KEY(tenant,event_sequence,incident_hash) REFERENCES cratectl.go_checksum_legacy_incidents(tenant,event_sequence,event_hash),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name),
 FOREIGN KEY(tenant,change_sequence) REFERENCES cratectl.events(tenant,sequence) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE cratectl.go_checksum_legacy_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.go_checksum_legacy_incidents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.go_checksum_legacy_incidents
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
ALTER TABLE cratectl.go_checksum_legacy_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.go_checksum_legacy_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.go_checksum_legacy_reviews
 USING(tenant=current_setting('cratectl.tenant',true)) WITH CHECK(tenant=current_setting('cratectl.tenant',true));
REVOKE ALL ON cratectl.go_checksum_legacy_incidents,cratectl.go_checksum_legacy_reviews FROM PUBLIC,cratectl_app;
GRANT SELECT,INSERT ON cratectl.go_checksum_legacy_incidents,cratectl.go_checksum_legacy_reviews TO cratectl_app;

-- These role-specific policies exist only inside the exclusive schema
-- transaction. Keep FORCE on, including for a nonsuperuser migration owner.
CREATE POLICY go_checksum_legacy_migration_owner ON cratectl.events FOR SELECT TO CURRENT_USER USING(true);
CREATE POLICY go_checksum_legacy_migration_owner ON cratectl.go_checksum_failures FOR SELECT TO CURRENT_USER USING(true);
CREATE POLICY go_checksum_legacy_migration_owner ON cratectl.go_checksum_forks FOR SELECT TO CURRENT_USER USING(true);
CREATE POLICY go_checksum_legacy_migration_owner ON cratectl.go_checksum_legacy_incidents FOR INSERT TO CURRENT_USER WITH CHECK(true);

INSERT INTO cratectl.go_checksum_legacy_incidents(tenant,event_sequence,event_hash)
 SELECT e.tenant,e.sequence,e.hash FROM cratectl.events e
 WHERE e.payload::jsonb->>'kind'='proxy.retrieval.failed'
 AND e.payload::jsonb#>>'{data,failure}'='upstream_checksum_fork'
 AND NOT EXISTS (
  SELECT 1 FROM cratectl.go_checksum_failures f
  WHERE f.tenant=e.tenant AND f.change_sequence=e.sequence AND f.classification='fork'
  AND f.repository=(e.payload::jsonb#>>'{data,repository}')
  AND f.root_path=(e.payload::jsonb#>>'{data,path}')
  AND f.source_revision::text=(e.payload::jsonb#>>'{data,source_revision}')
  AND f.generation::text=(e.payload::jsonb#>>'{data,generation}')
  AND f.evidence_digest=(e.payload::jsonb#>>'{data,go_checksum_failure_digest}')
  AND EXISTS(SELECT 1 FROM cratectl.go_checksum_forks k WHERE k.tenant=f.tenant AND k.key_digest=f.key_digest)
 );

-- Validate retained original event bindings before removing owner policies.
DROP POLICY go_checksum_legacy_migration_owner ON cratectl.events;
DROP POLICY go_checksum_legacy_migration_owner ON cratectl.go_checksum_failures;
DROP POLICY go_checksum_legacy_migration_owner ON cratectl.go_checksum_forks;
DROP POLICY go_checksum_legacy_migration_owner ON cratectl.go_checksum_legacy_incidents;
