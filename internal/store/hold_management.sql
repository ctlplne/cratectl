-- SPDX-License-Identifier: BUSL-1.1
-- Migration 9: index existing current state and immutable receipts; never
-- synthesize history, rewrite tenant data or change earlier migration bytes.
CREATE INDEX artifact_lifecycle_hold_page_idx ON cratectl.artifact_lifecycle
 (tenant, ((repository||E'\n'||path) COLLATE "C"));
CREATE INDEX artifact_lifecycle_hold_history_idx ON cratectl.events
 (tenant, ((payload::jsonb#>>'{data,current,repository}') COLLATE "C"),
 ((payload::jsonb#>>'{data,current,path}') COLLATE "C"), sequence)
 WHERE (payload::jsonb->>'kind')='artifact.lifecycle.changed'
 AND (payload::jsonb#>>'{data,action}') IN ('hold','release_hold');
