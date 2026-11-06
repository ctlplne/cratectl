-- SPDX-License-Identifier: BUSL-1.1
-- One append-only trust timeline per tenant and exact canonical verifier key.
-- Repository source changes cannot reset it. Proofs remain repository scoped.
CREATE TABLE cratectl.go_checksum_checkpoint_revisions (
 tenant text NOT NULL REFERENCES cratectl.tenants(tenant),
 key_digest text NOT NULL CHECK(key_digest ~ '^[a-f0-9]{64}$'),
 revision bigint NOT NULL CHECK(revision>0),
 verifier_key text NOT NULL CHECK(octet_length(verifier_key) BETWEEN 1 AND 4096),
 authority text NOT NULL CHECK(octet_length(authority) BETWEEN 1 AND 255),
 checkpoint bytea NOT NULL CHECK(octet_length(checkpoint) BETWEEN 1 AND 16384),
 tree_size bigint NOT NULL CHECK(tree_size>=0),
 root_hash text NOT NULL CHECK(octet_length(root_hash)=44),
 change_sequence bigint NOT NULL CHECK(change_sequence>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,key_digest,revision)
);
CREATE TABLE cratectl.go_checksum_checkpoints (
 tenant text NOT NULL,
 key_digest text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 PRIMARY KEY(tenant,key_digest),
 FOREIGN KEY(tenant,key_digest,revision) REFERENCES cratectl.go_checksum_checkpoint_revisions(tenant,key_digest,revision)
);
CREATE FUNCTION cratectl.fence_go_checksum_checkpoint() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fence$
DECLARE previous_size bigint; next_size bigint;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 THEN RAISE EXCEPTION 'checksum timeline must start at revision one'; END IF;
 ELSE
  IF NEW.tenant<>OLD.tenant OR NEW.key_digest<>OLD.key_digest OR NEW.revision<>OLD.revision+1 THEN
   RAISE EXCEPTION 'checksum timeline revision must advance exactly once';
  END IF;
  SELECT tree_size INTO STRICT previous_size FROM cratectl.go_checksum_checkpoint_revisions WHERE tenant=OLD.tenant AND key_digest=OLD.key_digest AND revision=OLD.revision;
  SELECT tree_size INTO STRICT next_size FROM cratectl.go_checksum_checkpoint_revisions WHERE tenant=NEW.tenant AND key_digest=NEW.key_digest AND revision=NEW.revision;
  IF next_size<=previous_size THEN RAISE EXCEPTION 'checksum timeline cannot shrink or replace a root'; END IF;
 END IF;
 RETURN NEW;
END;
$fence$;
REVOKE ALL ON FUNCTION cratectl.fence_go_checksum_checkpoint() FROM PUBLIC;
CREATE TRIGGER go_checksum_checkpoint_fence BEFORE INSERT OR UPDATE ON cratectl.go_checksum_checkpoints
FOR EACH ROW EXECUTE FUNCTION cratectl.fence_go_checksum_checkpoint();
CREATE TABLE cratectl.go_module_checksum_receipts (
 tenant text NOT NULL, repository text NOT NULL, root_path text NOT NULL,
 source_revision bigint NOT NULL CHECK(source_revision>=0),
 validation_generation bigint NOT NULL CHECK(validation_generation>0),
 key_digest text NOT NULL, checkpoint_revision bigint NOT NULL,
 expected_checkpoint_revision bigint NOT NULL CHECK(expected_checkpoint_revision>=0),
 proof_path text NOT NULL, proof_digest text NOT NULL CHECK(proof_digest ~ '^[a-f0-9]{64}$'),
 proof_size bigint NOT NULL CHECK(proof_size BETWEEN 1 AND 2097152),
 module text NOT NULL CHECK(octet_length(module) BETWEEN 1 AND 512),
 version text NOT NULL CHECK(octet_length(version) BETWEEN 1 AND 128),
 zip_h1 text NOT NULL CHECK(octet_length(zip_h1)=47),
 mod_h1 text NOT NULL CHECK(octet_length(mod_h1)=47),
 zip_digest text NOT NULL CHECK(zip_digest ~ '^[a-f0-9]{64}$'),
 mod_digest text NOT NULL CHECK(mod_digest ~ '^[a-f0-9]{64}$'),
 info_digest text NOT NULL CHECK(info_digest ~ '^[a-f0-9]{64}$'),
 change_sequence bigint NOT NULL CHECK(change_sequence>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant,repository,root_path,source_revision,validation_generation),
 CHECK(proof_path='go-checksum/'||proof_digest AND proof_path<>root_path),
 FOREIGN KEY(tenant,key_digest,checkpoint_revision) REFERENCES cratectl.go_checksum_checkpoint_revisions(tenant,key_digest,revision),
 FOREIGN KEY(tenant,repository,root_path) REFERENCES cratectl.artifacts(tenant,repository,path),
 FOREIGN KEY(tenant,repository,proof_path) REFERENCES cratectl.artifacts(tenant,repository,path)
);
