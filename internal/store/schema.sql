-- SPDX-License-Identifier: BUSL-1.1
CREATE SCHEMA IF NOT EXISTS cratectl;
CREATE SCHEMA IF NOT EXISTS cratectl_private;
REVOKE ALL ON SCHEMA cratectl_private FROM PUBLIC;
CREATE TABLE IF NOT EXISTS cratectl.tenants (tenant text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS cratectl_private.tokens (
 hash text PRIMARY KEY, tenant text NOT NULL REFERENCES cratectl.tenants(tenant),
 actor text NOT NULL, role text NOT NULL CHECK(role IN ('admin','writer','reader')),
 expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS cratectl.repositories (
 tenant text NOT NULL, name text NOT NULL, format text NOT NULL,
 mode text NOT NULL DEFAULT 'hosted' CHECK(mode='hosted'),
 require_review boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant,name),
 FOREIGN KEY(tenant) REFERENCES cratectl.tenants(tenant)
);
CREATE TABLE IF NOT EXISTS cratectl.artifacts (
 tenant text NOT NULL, repository text NOT NULL, path text NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'), size bigint NOT NULL CHECK(size>=0),
 media_type text NOT NULL, metadata jsonb NOT NULL DEFAULT '{}',
 decision text NOT NULL DEFAULT 'unassessed' CHECK(decision IN ('unassessed','allowed','denied')),
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant,repository,path),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
CREATE TABLE IF NOT EXISTS cratectl.events (
 tenant text NOT NULL, sequence bigint NOT NULL, payload text NOT NULL,
 previous_hash text NOT NULL, hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant,sequence)
);
CREATE TABLE IF NOT EXISTS cratectl.mutations (
 tenant text NOT NULL, actor text NOT NULL, key text NOT NULL, fingerprint text NOT NULL,
 response bytea NOT NULL, status integer NOT NULL, PRIMARY KEY(tenant,actor,key)
);
CREATE TABLE IF NOT EXISTS cratectl.jobs (
 tenant text NOT NULL, sequence bigint NOT NULL, kind text NOT NULL, state text NOT NULL DEFAULT 'pending',
 attempts integer NOT NULL DEFAULT 0, available_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant,sequence), FOREIGN KEY(tenant,sequence) REFERENCES cratectl.events(tenant,sequence)
);
CREATE OR REPLACE FUNCTION cratectl.authenticate(token_hash text)
 RETURNS TABLE(tenant text, actor text, role text)
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT t.tenant,t.actor,t.role FROM cratectl_private.tokens t
 WHERE t.hash=token_hash AND NOT t.revoked AND t.expires_at>now()
 $$;
REVOKE ALL ON FUNCTION cratectl.authenticate(text) FROM PUBLIC;
CREATE TABLE IF NOT EXISTS cratectl.uploads (
 tenant text NOT NULL, repository text NOT NULL, image text NOT NULL, id text NOT NULL,
 offset_bytes bigint NOT NULL DEFAULT 0, state text NOT NULL DEFAULT 'active',
 expires_at timestamptz NOT NULL DEFAULT now()+interval '30 minutes',
 PRIMARY KEY(tenant,id), FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
CREATE TABLE IF NOT EXISTS cratectl.tags (
 tenant text NOT NULL, repository text NOT NULL, image text NOT NULL, tag text NOT NULL,
 digest text NOT NULL, version bigint NOT NULL DEFAULT 1,
 PRIMARY KEY(tenant,repository,image,tag), FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
-- The initial development schema is upgraded in place; existing hosted rows
-- keep their access and policy. Production migration qualification remains open.
ALTER TABLE cratectl.repositories ADD COLUMN IF NOT EXISTS access text NOT NULL DEFAULT 'tenant';
ALTER TABLE cratectl.repositories ADD COLUMN IF NOT EXISTS settings jsonb NOT NULL DEFAULT '{}';
ALTER TABLE cratectl.repositories DROP CONSTRAINT IF EXISTS repositories_mode_check;
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='repository_modes_v2' AND conrelid='cratectl.repositories'::regclass) THEN
 ALTER TABLE cratectl.repositories ADD CONSTRAINT repository_modes_v2 CHECK(mode IN ('hosted','proxy','group'));
END IF; END $$;
CREATE TABLE IF NOT EXISTS cratectl.repository_grants (
 tenant text NOT NULL, repository text NOT NULL, actor text NOT NULL,
 can_read boolean NOT NULL, can_write boolean NOT NULL CHECK(NOT can_write OR can_read),
 PRIMARY KEY(tenant,repository,actor), FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
CREATE TABLE IF NOT EXISTS cratectl.retrievals (
 tenant text NOT NULL, repository text NOT NULL, path text NOT NULL,
 generation bigint NOT NULL, lease_token text NOT NULL, lease_until timestamptz NOT NULL,
 state text NOT NULL CHECK(state IN ('fetching','ready','negative','failed')),
 fresh_until timestamptz NOT NULL DEFAULT 'epoch', stale_until timestamptz NOT NULL DEFAULT 'epoch',
 etag text NOT NULL DEFAULT '', modified text NOT NULL DEFAULT '',
 last_status integer NOT NULL DEFAULT 0, last_error text NOT NULL DEFAULT '',
 PRIMARY KEY(tenant,repository,path), FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
ALTER TABLE cratectl.retrievals ADD COLUMN IF NOT EXISTS source_fresh_seconds integer NOT NULL DEFAULT 0;
ALTER TABLE cratectl.retrievals ADD COLUMN IF NOT EXISTS source_stale_seconds integer NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS cratectl.content_decisions (
 tenant text NOT NULL, repository text NOT NULL, digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),
 decision text NOT NULL CHECK(decision IN ('allowed','denied','unassessed')),
 version bigint NOT NULL DEFAULT 1, evidence_kind text NOT NULL DEFAULT 'manual',
 updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant,repository,digest),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
CREATE INDEX IF NOT EXISTS artifacts_digest_idx ON cratectl.artifacts(tenant,repository,digest);
-- Preserve legacy decisions conservatively. A conflicting denial wins; repeated
-- migration never overwrites a canonical decision made after this backfill.
INSERT INTO cratectl.content_decisions(tenant,repository,digest,decision)
 SELECT tenant,repository,digest,CASE WHEN bool_or(decision='denied') THEN 'denied' ELSE 'allowed' END
 FROM cratectl.artifacts WHERE decision IN ('allowed','denied') GROUP BY tenant,repository,digest
 ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS cratectl.npm_sources (
 tenant text NOT NULL, repository text NOT NULL, key text NOT NULL CHECK(key ~ '^[a-f0-9]{64}$'),
 package text NOT NULL, version text NOT NULL, tarball text NOT NULL, integrity text NOT NULL,
 metadata jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant,repository,key), FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
CREATE TABLE IF NOT EXISTS cratectl.native_sources (
 tenant text NOT NULL, repository text NOT NULL, key text NOT NULL CHECK(key ~ '^[a-f0-9]{64}$'),
 format text NOT NULL, package text NOT NULL, coordinate text NOT NULL, version text NOT NULL,
 url text NOT NULL, integrity text NOT NULL, metadata jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant,repository,key),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
-- Keep existing pinned npm URLs valid. The old immutable table is retained for
-- development migration evidence; new bindings use the common format store.
INSERT INTO cratectl.native_sources(tenant,repository,key,format,package,coordinate,version,url,integrity,metadata)
 SELECT tenant,repository,key,'npm',package,version,version,tarball,integrity,metadata FROM cratectl.npm_sources
 ON CONFLICT DO NOTHING;
CREATE INDEX IF NOT EXISTS artifacts_package_idx ON cratectl.artifacts(tenant,repository,(metadata->>'name'),path);
CREATE INDEX IF NOT EXISTS artifacts_oci_subject_idx ON cratectl.artifacts(tenant,repository,((metadata->'oci_subject')->>'digest'),path);
CREATE TABLE IF NOT EXISTS cratectl.python_yanks (
 tenant text NOT NULL, repository text NOT NULL, filename text NOT NULL,
 yanked boolean NOT NULL, reason text NOT NULL DEFAULT '', revision bigint NOT NULL DEFAULT 1,
 updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant,repository,filename),
 FOREIGN KEY(tenant,repository,filename) REFERENCES cratectl.artifacts(tenant,repository,path)
);
CREATE TABLE IF NOT EXISTS cratectl.npm_tags (
 tenant text NOT NULL, repository text NOT NULL, package text NOT NULL, tag text NOT NULL,
 version text NOT NULL, revision bigint NOT NULL DEFAULT 1, deleted boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant,repository,package,tag),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
-- Preserve the last native publication tag from the development schema. Deleted
-- tags keep tombstones so this idempotent backfill cannot resurrect them.
INSERT INTO cratectl.npm_tags(tenant,repository,package,tag,version)
 SELECT DISTINCT ON (a.tenant,a.repository,a.metadata->>'name',t.key)
 a.tenant,a.repository,a.metadata->>'name',t.key,t.value
 FROM cratectl.artifacts a JOIN cratectl.repositories r ON (r.tenant,r.name)=(a.tenant,a.repository)
 CROSS JOIN LATERAL jsonb_each_text(CASE WHEN jsonb_typeof(a.metadata->'dist_tags')='object' THEN a.metadata->'dist_tags' ELSE '{}'::jsonb END) t
 WHERE r.format='npm' AND a.metadata->>'name' IS NOT NULL
 ORDER BY a.tenant,a.repository,a.metadata->>'name',t.key,a.created_at DESC,a.path DESC
 ON CONFLICT DO NOTHING;
