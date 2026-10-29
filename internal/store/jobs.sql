-- SPDX-License-Identifier: BUSL-1.1
ALTER TABLE cratectl_private.tokens DROP CONSTRAINT IF EXISTS tokens_role_check;
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='cratectl_private.tokens'::regclass AND conname='token_roles_v2') THEN
 ALTER TABLE cratectl_private.tokens ADD CONSTRAINT token_roles_v2 CHECK(role IN ('admin','writer','reader','worker'));
END IF; END $$;
-- Worker credentials cannot authenticate to the public artifact/management API.
CREATE OR REPLACE FUNCTION cratectl.authenticate(token_hash text)
 RETURNS TABLE(tenant text, actor text, role text)
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT t.tenant,t.actor,t.role FROM cratectl_private.tokens t
 WHERE t.hash=token_hash AND t.role<>'worker' AND NOT t.revoked AND t.expires_at>clock_timestamp()
 $$;
CREATE OR REPLACE FUNCTION cratectl.authenticate_worker(token_hash text)
 RETURNS TABLE(tenant text, actor text)
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT t.tenant,t.actor FROM cratectl_private.tokens t
 WHERE t.hash=token_hash AND t.role='worker' AND NOT t.revoked AND t.expires_at>clock_timestamp()
 $$;
REVOKE ALL ON FUNCTION cratectl.authenticate_worker(text) FROM PUBLIC;
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS task text NOT NULL DEFAULT 'event';
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS queue text NOT NULL DEFAULT 'events';
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}';
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS generation bigint NOT NULL DEFAULT 0;
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS lease_token text NOT NULL DEFAULT '';
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS lease_until timestamptz NOT NULL DEFAULT 'epoch';
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS worker text NOT NULL DEFAULT '';
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS cycle_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS last_error text NOT NULL DEFAULT '';
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE cratectl.jobs ADD COLUMN IF NOT EXISTS finished_at timestamptz;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='cratectl.jobs'::regclass AND contype='p' AND array_length(conkey,1)=2) THEN
 ALTER TABLE cratectl.jobs DROP CONSTRAINT jobs_pkey;
 ALTER TABLE cratectl.jobs ADD PRIMARY KEY(tenant,sequence,task);
END IF; END $$;
ALTER TABLE cratectl.jobs DROP CONSTRAINT IF EXISTS jobs_tenant_sequence_fkey;
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='cratectl.jobs'::regclass AND conname='jobs_event_fk') THEN
 ALTER TABLE cratectl.jobs ADD CONSTRAINT jobs_event_fk FOREIGN KEY(tenant,sequence) REFERENCES cratectl.events(tenant,sequence) DEFERRABLE INITIALLY DEFERRED;
END IF; END $$;
CREATE INDEX IF NOT EXISTS jobs_ready_idx ON cratectl.jobs(tenant,queue,available_at,sequence,task) WHERE state IN ('pending','retry','running','cancel_requested');
CREATE TABLE IF NOT EXISTS cratectl.queue_policies (
 tenant text NOT NULL REFERENCES cratectl.tenants(tenant), queue text NOT NULL,
 capacity integer NOT NULL DEFAULT 100000, max_running integer NOT NULL DEFAULT 2,
 max_attempts integer NOT NULL DEFAULT 5, retry_seconds integer NOT NULL DEFAULT 5,
 retry_max_seconds integer NOT NULL DEFAULT 300,
 PRIMARY KEY(tenant,queue), CHECK(queue IN ('events','integrity')),
 CHECK(capacity>0 AND max_running>0 AND max_attempts>0 AND retry_seconds>0 AND retry_max_seconds>=retry_seconds)
);
CREATE TABLE IF NOT EXISTS cratectl.event_projections (
 tenant text NOT NULL, sequence bigint NOT NULL, event_hash text NOT NULL,
 actor text NOT NULL, kind text NOT NULL, repository text NOT NULL DEFAULT '',
 path text NOT NULL DEFAULT '', digest text NOT NULL DEFAULT '',
 projected_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,sequence), FOREIGN KEY(tenant,sequence) REFERENCES cratectl.events(tenant,sequence)
);
CREATE TABLE IF NOT EXISTS cratectl.integrity_observations (
 tenant text NOT NULL, sequence bigint NOT NULL, task text NOT NULL, generation bigint NOT NULL,
 repository text NOT NULL, digest text NOT NULL, size bigint NOT NULL,
 status text NOT NULL CHECK(status IN ('verified','missing','corrupt','superseded','io_error','limit','timeout')),
 worker text NOT NULL, engine text NOT NULL DEFAULT 'sha256-v1',
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,sequence,task,generation),
 FOREIGN KEY(tenant,sequence,task) REFERENCES cratectl.jobs(tenant,sequence,task)
);
CREATE INDEX IF NOT EXISTS integrity_digest_idx ON cratectl.integrity_observations(tenant,repository,digest,observed_at DESC);

ALTER TABLE cratectl.event_projections ADD COLUMN IF NOT EXISTS position bigint NOT NULL DEFAULT 0;
UPDATE cratectl.event_projections SET position=sequence WHERE position=0;
CREATE UNIQUE INDEX IF NOT EXISTS event_projection_position_idx ON cratectl.event_projections(tenant,position);
