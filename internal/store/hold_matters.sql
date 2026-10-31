-- SPDX-License-Identifier: BUSL-1.1
-- Migration 11: reviewed cross-reference preservation and independent release.
CREATE TABLE cratectl.hold_matters (
 tenant text NOT NULL, name text NOT NULL CHECK(name ~ '^[a-z][a-z0-9-]{0,62}$'),
 revision bigint NOT NULL CHECK(revision>0), state text NOT NULL CHECK(state IN ('open','closed')),
 title text NOT NULL CHECK(octet_length(title) BETWEEN 1 AND 256),
 reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 1024),
 actor text NOT NULL, created_sequence bigint NOT NULL CHECK(created_sequence>0),
 change_sequence bigint NOT NULL CHECK(change_sequence>=created_sequence),
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant,name),
 FOREIGN KEY(tenant) REFERENCES cratectl.tenants(tenant)
);
CREATE TABLE cratectl.hold_matter_members (
 tenant text NOT NULL, matter text NOT NULL, repository text NOT NULL,
 path text NOT NULL CHECK(octet_length(path)<=2048), digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),
 revision bigint NOT NULL CHECK(revision>0), released boolean NOT NULL DEFAULT false,
 hold_reason text NOT NULL CHECK(octet_length(hold_reason) BETWEEN 1 AND 1024), hold_until timestamptz,
 reason text NOT NULL CHECK(octet_length(reason) BETWEEN 1 AND 1024), actor text NOT NULL,
 created_sequence bigint NOT NULL CHECK(created_sequence>0), change_sequence bigint NOT NULL CHECK(change_sequence>=created_sequence),
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,matter,repository,path), UNIQUE(tenant,created_sequence),
 FOREIGN KEY(tenant,matter) REFERENCES cratectl.hold_matters(tenant,name),
 FOREIGN KEY(tenant,repository,path) REFERENCES cratectl.artifacts(tenant,repository,path)
);
CREATE INDEX hold_matter_active_reference ON cratectl.hold_matter_members(tenant,repository,path) WHERE NOT released;
CREATE TABLE cratectl.hold_matter_operations (
 tenant text NOT NULL, sequence bigint NOT NULL CHECK(sequence>0), matter text NOT NULL,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 state text NOT NULL CHECK(state IN ('awaiting_approval','approved','cancelled')),
 plan jsonb NOT NULL CHECK(octet_length(plan::text)<=16384),
 requester_actor text NOT NULL, requester_hash text NOT NULL CHECK(requester_hash<>''),
 approver_actor text NOT NULL DEFAULT '', approver_hash text NOT NULL DEFAULT '',
 approval_reason text NOT NULL DEFAULT '' CHECK(octet_length(approval_reason)<=1024),
 expires_at timestamptz NOT NULL, job_sequence bigint, job_task text,
 change_sequence bigint NOT NULL CHECK(change_sequence>=sequence),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,sequence), FOREIGN KEY(tenant,matter) REFERENCES cratectl.hold_matters(tenant,name),
 FOREIGN KEY(tenant,job_sequence,job_task) REFERENCES cratectl.jobs(tenant,sequence,task),
 CHECK((job_sequence IS NULL)=(job_task IS NULL)),
 CHECK((state='approved')=(job_sequence IS NOT NULL)),
 CHECK(approver_actor='' OR approver_actor<>requester_actor)
);
CREATE INDEX hold_matter_operations_page ON cratectl.hold_matter_operations(tenant,matter,sequence);
CREATE TABLE cratectl.hold_matter_targets (
 tenant text NOT NULL, operation bigint NOT NULL, ordinal bigint NOT NULL CHECK(ordinal>0),
 target jsonb NOT NULL CHECK(octet_length(target::text)<=8192),
 PRIMARY KEY(tenant,operation,ordinal), FOREIGN KEY(tenant,operation) REFERENCES cratectl.hold_matter_operations(tenant,sequence)
);
CREATE TABLE cratectl.hold_matter_outcomes (
 tenant text NOT NULL, operation bigint NOT NULL, ordinal bigint NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 outcome text NOT NULL CHECK(outcome IN ('held','released','already_released','changed')),
 member_revision bigint NOT NULL CHECK(member_revision>=0), lifecycle_revision bigint NOT NULL CHECK(lifecycle_revision>=0), effective_held boolean NOT NULL,
 worker text NOT NULL, event_sequence bigint NOT NULL CHECK(event_sequence>0), observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,operation,ordinal),
 FOREIGN KEY(tenant,operation,ordinal) REFERENCES cratectl.hold_matter_targets(tenant,operation,ordinal)
);
CREATE INDEX hold_matter_history ON cratectl.events(tenant,((payload::jsonb#>>'{data,matter_name}')),sequence)
 WHERE (payload::jsonb->>'kind') LIKE 'hold.matter.%';
