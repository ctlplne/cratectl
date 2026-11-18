// SPDX-License-Identifier: BUSL-1.1
package store

import "strings"

// Owner IDs are assigned inside the tenant mutation fence. They are stable
// across crates and do not allocate numbers from a cross-tenant sequence.
const cargoOwnershipSchema = `
CREATE TABLE cratectl.cargo_owner_actors (
 tenant text NOT NULL REFERENCES cratectl.tenants(tenant),
 actor text NOT NULL CHECK (actor ~ '^[a-z][a-z0-9-]{0,62}$'),
 cargo_id bigint NOT NULL CHECK (cargo_id BETWEEN 1 AND 4294967295),
 PRIMARY KEY (tenant, actor),
 UNIQUE (tenant, cargo_id)
);
CREATE TABLE cratectl.cargo_crate_owners (
 tenant text NOT NULL,
 repository text NOT NULL,
 crate_key text NOT NULL CHECK (crate_key ~ '^[a-z][a-z0-9-]{0,63}$'),
 actor text NOT NULL,
 active boolean NOT NULL DEFAULT true,
 PRIMARY KEY (tenant, repository, crate_key, actor),
 FOREIGN KEY (tenant, repository) REFERENCES cratectl.repositories(tenant, name),
 FOREIGN KEY (tenant, actor) REFERENCES cratectl.cargo_owner_actors(tenant, actor)
);
CREATE INDEX cargo_crate_owners_active ON cratectl.cargo_crate_owners(tenant,repository,crate_key,actor) WHERE active;
ALTER TABLE cratectl.cargo_owner_actors ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.cargo_owner_actors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.cargo_owner_actors USING (tenant=current_setting('cratectl.tenant',true)) WITH CHECK (tenant=current_setting('cratectl.tenant',true));
GRANT SELECT,INSERT ON cratectl.cargo_owner_actors TO cratectl_app;
ALTER TABLE cratectl.cargo_crate_owners ENABLE ROW LEVEL SECURITY;
ALTER TABLE cratectl.cargo_crate_owners FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cratectl.cargo_crate_owners USING (tenant=current_setting('cratectl.tenant',true)) WITH CHECK (tenant=current_setting('cratectl.tenant',true));
GRANT SELECT,INSERT ON cratectl.cargo_crate_owners TO cratectl_app;
GRANT UPDATE(active) ON cratectl.cargo_crate_owners TO cratectl_app;
`

var cargoOwnershipSchemaStateBody = strings.Replace(frozenSchemaStateBody, migrationSafetySQL(), cargoOwnershipSafetySQL(), 1)

func cargoOwnershipSafetySQL() string {
	return `SELECT (` + goRequirementExportSafetySQL() + `) AND (` + migrationSafetySQLFor(schemaTablesV19) + `) AND
 has_table_privilege('cratectl_app','cratectl.cargo_owner_actors','SELECT') AND
 has_table_privilege('cratectl_app','cratectl.cargo_owner_actors','INSERT') AND
 NOT has_table_privilege('cratectl_app','cratectl.cargo_owner_actors','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND
 NOT has_any_column_privilege('cratectl_app','cratectl.cargo_owner_actors','UPDATE,REFERENCES') AND
 has_table_privilege('cratectl_app','cratectl.cargo_crate_owners','SELECT') AND
 has_table_privilege('cratectl_app','cratectl.cargo_crate_owners','INSERT') AND
 NOT has_table_privilege('cratectl_app','cratectl.cargo_crate_owners','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND
 NOT has_any_column_privilege('cratectl_app','cratectl.cargo_crate_owners','REFERENCES') AND
 has_column_privilege('cratectl_app','cratectl.cargo_crate_owners','active','UPDATE') AND
 NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid='cratectl.cargo_crate_owners'::regclass
 AND a.attnum>0 AND NOT a.attisdropped AND a.attname<>'active'
 AND has_column_privilege('cratectl_app',a.attrelid,a.attnum,'UPDATE'))`
}
