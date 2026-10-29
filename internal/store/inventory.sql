-- SPDX-License-Identifier: BUSL-1.1
CREATE TABLE IF NOT EXISTS cratectl.inventory_entries (
 tenant text NOT NULL, sequence bigint NOT NULL, task text NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>0), area text NOT NULL,
 bucket text NOT NULL DEFAULT '', name_b64 text NOT NULL, display_name text NOT NULL,
 entry_type text NOT NULL, size bigint NOT NULL CHECK(size>=0), modified_ns bigint NOT NULL,
 file_identity text NOT NULL, expected_layout boolean NOT NULL, digest text NOT NULL DEFAULT '',
 artifact_references bigint NOT NULL DEFAULT 0, upload_parts bigint NOT NULL DEFAULT 0,
 upload_state text NOT NULL DEFAULT '', acknowledged_bytes bigint NOT NULL DEFAULT 0,
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,sequence,task,ordinal),
 UNIQUE(tenant,sequence,task,area,bucket,name_b64),
 FOREIGN KEY(tenant,sequence,task) REFERENCES cratectl.jobs(tenant,sequence,task) DEFERRABLE INITIALLY DEFERRED,
 CHECK(area IN ('root','sha256','cas','staged','uploads')),
 CHECK(entry_type IN ('file','directory','symlink','other','disappeared')),
 CHECK(length(name_b64)<=344 AND length(display_name)<=1024 AND (digest='' OR digest ~ '^[a-f0-9]{64}$'))
);
CREATE TABLE IF NOT EXISTS cratectl.inventory_observations (
 tenant text NOT NULL, sequence bigint NOT NULL, task text NOT NULL, ordinal bigint NOT NULL,
 generation bigint NOT NULL, pass bigint NOT NULL, status text NOT NULL,
 worker text NOT NULL, engine text NOT NULL DEFAULT 'sha256-v1',
 observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,sequence,task,generation),
 FOREIGN KEY(tenant,sequence,task,ordinal) REFERENCES cratectl.inventory_entries(tenant,sequence,task,ordinal),
 CHECK(status IN ('verified','missing','corrupt','io_error','limit','timeout','changed','unsupported'))
);
CREATE INDEX IF NOT EXISTS inventory_hash_idx ON cratectl.inventory_entries(tenant,sequence,task,ordinal) WHERE area='cas' AND expected_layout;
CREATE INDEX IF NOT EXISTS inventory_latest_idx ON cratectl.inventory_observations(tenant,sequence,task,pass,ordinal,generation DESC);
CREATE INDEX IF NOT EXISTS artifacts_inventory_digest_idx ON cratectl.artifacts(tenant,digest);
CREATE INDEX IF NOT EXISTS upload_parts_inventory_digest_idx ON cratectl.upload_parts(tenant,digest);
