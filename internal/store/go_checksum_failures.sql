-- SPDX-License-Identifier: BUSL-1.1
-- Bounded original failure observations are control evidence, atomically durable
-- with the failed attempt and any authenticated tenant/key block. No external
-- blob reference or ordinary asynchronous work queue is required for fail-stop.
CREATE TABLE cratectl.go_checksum_failures (
 tenant text NOT NULL, repository text NOT NULL,
 root_path text NOT NULL CHECK(octet_length(root_path) BETWEEN 1 AND 2048),
 source_revision bigint NOT NULL CHECK(source_revision>=0),
 generation bigint NOT NULL CHECK(generation>0),
 key_digest text NOT NULL CHECK(key_digest ~ '^[a-f0-9]{64}$'),
 expected_checkpoint_revision bigint NOT NULL CHECK(expected_checkpoint_revision>=0),
 classification text NOT NULL CHECK(classification IN ('unverified','fork')),
 evidence bytea NOT NULL CHECK(octet_length(evidence) BETWEEN 1 AND 2097152),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$'),
 change_sequence bigint NOT NULL CHECK(change_sequence>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,repository,root_path,source_revision,generation),
 UNIQUE(tenant,repository,root_path,source_revision,generation,key_digest,classification),
 FOREIGN KEY(tenant,repository) REFERENCES cratectl.repositories(tenant,name)
);
CREATE TABLE cratectl.go_checksum_forks (
 tenant text NOT NULL, key_digest text NOT NULL,
 repository text NOT NULL, root_path text NOT NULL,
 source_revision bigint NOT NULL, generation bigint NOT NULL,
 classification text NOT NULL DEFAULT 'fork' CHECK(classification='fork'),
 change_sequence bigint NOT NULL CHECK(change_sequence>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,key_digest),
 FOREIGN KEY(tenant,repository,root_path,source_revision,generation,key_digest,classification)
 REFERENCES cratectl.go_checksum_failures(tenant,repository,root_path,source_revision,generation,key_digest,classification)
);
