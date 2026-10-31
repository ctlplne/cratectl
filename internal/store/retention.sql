-- SPDX-License-Identifier: BUSL-1.1
CREATE TABLE cratectl.retention_policies (
 tenant text NOT NULL, repository text NOT NULL, name text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0), configuration jsonb NOT NULL,
 PRIMARY KEY(tenant,repository,name),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name),
 CHECK(octet_length(configuration::text)<=16384)
);
CREATE TABLE cratectl.retention_revisions (
 tenant text NOT NULL, repository text NOT NULL, name text NOT NULL,
 revision bigint NOT NULL, configuration jsonb NOT NULL,
 PRIMARY KEY(tenant,repository,name,revision),
 FOREIGN KEY(tenant,repository,name) REFERENCES cratectl.retention_policies(tenant,repository,name),
 CHECK(octet_length(configuration::text)<=16384)
);
CREATE TABLE cratectl.retention_runs (
 tenant text NOT NULL, sequence bigint NOT NULL, task text NOT NULL,
 repository text NOT NULL, name text NOT NULL, revision bigint NOT NULL,
 plan jsonb NOT NULL CHECK(octet_length(plan::text)<=16384),
 requester_actor text NOT NULL, requester_hash text NOT NULL,
 PRIMARY KEY(tenant,sequence,task),
 FOREIGN KEY(tenant,sequence,task) REFERENCES cratectl.jobs(tenant,sequence,task),
 FOREIGN KEY(tenant,repository,name,revision) REFERENCES cratectl.retention_revisions(tenant,repository,name,revision)
);
CREATE INDEX retention_runs_page_idx ON cratectl.retention_runs(tenant,repository,name,sequence);
CREATE TABLE cratectl.retention_items (
 tenant text NOT NULL, sequence bigint NOT NULL, task text NOT NULL,
 ordinal bigint NOT NULL CHECK(ordinal>0),
 target jsonb NOT NULL CHECK(octet_length(target::text)<=16384),
 PRIMARY KEY(tenant,sequence,task,ordinal),
 FOREIGN KEY(tenant,sequence,task) REFERENCES cratectl.retention_runs(tenant,sequence,task)
);
CREATE TABLE cratectl.retention_observations (
 tenant text NOT NULL, sequence bigint NOT NULL, task text NOT NULL,
 ordinal bigint NOT NULL, generation bigint NOT NULL CHECK(generation>0),
 status text NOT NULL CHECK(status IN ('retired','held','tagged','referenced','newest','young','unvalidated','changed','already_retired')),
 lifecycle_revision bigint NOT NULL CHECK(lifecycle_revision>=0),
 worker text NOT NULL, observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,sequence,task,ordinal),
 FOREIGN KEY(tenant,sequence,task,ordinal) REFERENCES cratectl.retention_items(tenant,sequence,task,ordinal)
);
