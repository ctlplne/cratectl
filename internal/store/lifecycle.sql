-- SPDX-License-Identifier: BUSL-1.1
-- Migration 3: retain bytes and references; lifecycle is independent of approval.
CREATE TABLE cratectl.artifact_lifecycle (
 tenant text NOT NULL, repository text NOT NULL, path text NOT NULL,
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),
 deleted boolean NOT NULL DEFAULT false, revision bigint NOT NULL CHECK(revision>0),
 hold_reason text NOT NULL DEFAULT '' CHECK(octet_length(hold_reason)<=1024),
 hold_until timestamptz, reason text NOT NULL CHECK(octet_length(reason)<=1024),
 actor text NOT NULL, changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 change_sequence bigint NOT NULL CHECK(change_sequence>0),
 PRIMARY KEY(tenant,repository,path),
 FOREIGN KEY(tenant,repository,path) REFERENCES cratectl.artifacts(tenant,repository,path)
);
CREATE TABLE cratectl.repository_lifecycle (
 tenant text NOT NULL, repository text NOT NULL,
 state text NOT NULL CHECK(state IN ('active','suspended','removed')),
 revision bigint NOT NULL CHECK(revision>0), reason text NOT NULL CHECK(octet_length(reason)<=1024),
 actor text NOT NULL, changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 change_sequence bigint NOT NULL CHECK(change_sequence>0),
 PRIMARY KEY(tenant,repository),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
