-- SPDX-License-Identifier: BUSL-1.1
CREATE TABLE cratectl.integrity_schedules (
 tenant text NOT NULL REFERENCES cratectl.tenants(tenant), name text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), repository text NOT NULL DEFAULT '',
 interval_seconds bigint NOT NULL CHECK(interval_seconds BETWEEN 60 AND 31536000),
 sample_size integer NOT NULL CHECK(sample_size BETWEEN 1 AND 1000000),
 enabled boolean NOT NULL, reason text NOT NULL,
 requester_actor text NOT NULL, requester_hash text NOT NULL,
 configured_at timestamptz NOT NULL, next_due_at timestamptz NOT NULL,
 retry_at timestamptz NOT NULL, blocked boolean NOT NULL DEFAULT false,
 last_error text NOT NULL DEFAULT '',
 cursor_repository text NOT NULL DEFAULT '', cursor_digest text NOT NULL DEFAULT '',
 cursor_size bigint NOT NULL DEFAULT 0 CHECK(cursor_size>=0),
 last_sequence bigint, last_task text,
 PRIMARY KEY(tenant,name),
 CHECK((last_sequence IS NULL)=(last_task IS NULL))
);
CREATE INDEX integrity_schedules_due_idx ON cratectl.integrity_schedules(tenant,retry_at,next_due_at,name) WHERE enabled AND NOT blocked;
CREATE TABLE cratectl.integrity_schedule_revisions (
 tenant text NOT NULL, name text NOT NULL, revision bigint NOT NULL,
 configuration jsonb NOT NULL CHECK(octet_length(configuration::text)<=16384),
 PRIMARY KEY(tenant,name,revision),
 FOREIGN KEY(tenant,name) REFERENCES cratectl.integrity_schedules(tenant,name)
);
CREATE TABLE cratectl.integrity_schedule_runs (
 tenant text NOT NULL, name text NOT NULL, revision bigint NOT NULL,
 due_at timestamptz NOT NULL, admitted_at timestamptz NOT NULL,
 sequence bigint NOT NULL, task text NOT NULL,
 coalesced_intervals bigint NOT NULL CHECK(coalesced_intervals>=0),
 PRIMARY KEY(tenant,name,revision,due_at), UNIQUE(tenant,sequence,task),
 FOREIGN KEY(tenant,name,revision) REFERENCES cratectl.integrity_schedule_revisions(tenant,name,revision),
 FOREIGN KEY(tenant,sequence,task) REFERENCES cratectl.jobs(tenant,sequence,task)
);
CREATE INDEX integrity_schedule_runs_page_idx ON cratectl.integrity_schedule_runs(tenant,name,sequence);
