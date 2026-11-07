-- SPDX-License-Identifier: BUSL-1.1
-- Terminal manifests remain durable roots, but must not make idle lease
-- reconciliation scan the entire retained history.
CREATE INDEX artifact_exports_due ON cratectl.artifact_exports(tenant,expires_at,id)
 WHERE state IN ('open','acknowledged');
