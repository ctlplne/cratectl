-- SPDX-License-Identifier: BUSL-1.1
-- Migration 10: independently revised bindings to immutable OCI references.
CREATE TABLE cratectl.artifact_hold_cases (
 tenant text NOT NULL, repository text NOT NULL, path text NOT NULL CHECK(octet_length(path)<=2048),
 case_id text NOT NULL CHECK(case_id ~ '^[a-z][a-z0-9-]{0,62}$' AND case_id<>'legacy'),
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),
 revision bigint NOT NULL CHECK(revision>0), released boolean NOT NULL DEFAULT false,
 hold_reason text NOT NULL CHECK(octet_length(hold_reason) BETWEEN 1 AND 1024),
 hold_until timestamptz, reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 1024),
 actor text NOT NULL, changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 created_sequence bigint NOT NULL CHECK(created_sequence>0),
 change_sequence bigint NOT NULL CHECK(change_sequence>=created_sequence),
 PRIMARY KEY(tenant,repository,path,case_id), UNIQUE(tenant,created_sequence),
 FOREIGN KEY(tenant,repository,path) REFERENCES cratectl.artifacts(tenant,repository,path)
);
CREATE INDEX hold_cases_active_reference ON cratectl.artifact_hold_cases(tenant,repository,path) WHERE NOT released;
CREATE INDEX hold_cases_history ON cratectl.events(tenant,
 ((payload::jsonb#>>'{data,case,repository}')),
 ((payload::jsonb#>>'{data,case,path}')),
 ((payload::jsonb#>>'{data,case,case_id}')),sequence)
 WHERE (payload::jsonb->>'kind')='artifact.hold_case.changed';
