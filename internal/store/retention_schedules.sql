-- SPDX-License-Identifier: BUSL-1.1
CREATE TABLE cratectl.retention_schedules (
 tenant text NOT NULL, repository text NOT NULL, name text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), policy_revision bigint NOT NULL,
 source_revision bigint NOT NULL CHECK(source_revision>=0),
 configuration jsonb NOT NULL CHECK(octet_length(configuration::text)<=16384),
 enabled boolean NOT NULL, requester_hash text NOT NULL,
 configured_at timestamptz NOT NULL, next_due_at timestamptz NOT NULL,
 retry_at timestamptz NOT NULL, blocked boolean NOT NULL DEFAULT false,
 last_error text NOT NULL DEFAULT '', last_sequence bigint, last_task text,
 PRIMARY KEY(tenant,repository,name),
 FOREIGN KEY(tenant,repository,name,policy_revision) REFERENCES cratectl.retention_revisions(tenant,repository,name,revision),
 CHECK((last_sequence IS NULL)=(last_task IS NULL))
);
CREATE INDEX retention_schedules_due_idx ON cratectl.retention_schedules(tenant,retry_at,next_due_at,repository,name) WHERE enabled AND NOT blocked;
CREATE TABLE cratectl.retention_schedule_revisions (
 tenant text NOT NULL, repository text NOT NULL, name text NOT NULL,
 revision bigint NOT NULL, configuration jsonb NOT NULL CHECK(octet_length(configuration::text)<=16384),
 PRIMARY KEY(tenant,repository,name,revision),
 FOREIGN KEY(tenant,repository,name) REFERENCES cratectl.retention_schedules(tenant,repository,name)
);
CREATE TABLE cratectl.retention_schedule_runs (
 tenant text NOT NULL, repository text NOT NULL, name text NOT NULL,
 revision bigint NOT NULL, due_at timestamptz NOT NULL,
 admitted_at timestamptz NOT NULL, coalesced_intervals bigint NOT NULL CHECK(coalesced_intervals>=0),
 sequence bigint NOT NULL, task text NOT NULL,
 PRIMARY KEY(tenant,repository,name,revision,due_at), UNIQUE(tenant,sequence,task),
 FOREIGN KEY(tenant,repository,name,revision) REFERENCES cratectl.retention_schedule_revisions(tenant,repository,name,revision),
 FOREIGN KEY(tenant,sequence,task) REFERENCES cratectl.retention_runs(tenant,sequence,task)
);
CREATE INDEX retention_schedule_runs_page_idx ON cratectl.retention_schedule_runs(tenant,repository,name,sequence);
