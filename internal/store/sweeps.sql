-- SPDX-License-Identifier: BUSL-1.1
CREATE TABLE IF NOT EXISTS cratectl.sweep_items (
 tenant text NOT NULL, sequence bigint NOT NULL, task text NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>0), repository text NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'), size bigint NOT NULL CHECK(size>=0),
 path text NOT NULL, artifact_references bigint NOT NULL CHECK(artifact_references>=0),
 upload_parts bigint NOT NULL CHECK(upload_parts>=0), reference_conflict boolean NOT NULL,
 PRIMARY KEY(tenant,sequence,task,ordinal),
 UNIQUE(tenant,sequence,task,repository,digest,size),
 FOREIGN KEY(tenant,sequence,task) REFERENCES cratectl.jobs(tenant,sequence,task) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE cratectl.integrity_observations ADD COLUMN IF NOT EXISTS ordinal bigint NOT NULL DEFAULT 0;
ALTER TABLE cratectl.integrity_observations ADD COLUMN IF NOT EXISTS pass bigint NOT NULL DEFAULT 0;
ALTER TABLE cratectl.integrity_observations DROP CONSTRAINT IF EXISTS integrity_observations_status_check;
ALTER TABLE cratectl.integrity_observations ADD CONSTRAINT integrity_observations_status_check CHECK(status IN ('verified','missing','corrupt','superseded','io_error','limit','timeout','inconsistent'));
CREATE INDEX IF NOT EXISTS sweep_observation_latest_idx ON cratectl.integrity_observations(tenant,sequence,task,pass,ordinal,generation DESC);
