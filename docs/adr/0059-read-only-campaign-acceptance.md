# 0059: Accept exact-source CI campaigns on GitHub

Date: 2026-11-07. State: implementation and qualification in progress.

Move bounded campaign inspection from this ARM workspace to a manually
dispatched GitHub job. Inputs are one full source SHA and the explicit run-ID
inventory. Manual dispatch does not start/retry any test. The verifier compares
that inventory with a fresh API snapshot of same-repository/main runs, checks
every selected profile/job/required step and its original bounded safe reports,
then refreshes the snapshot before accepting. New or omitted runs, pending,
failed, canceled, skipped required stages and successful empty reports refuse
acceptance. Re-run attempts require separate review, not automatic acceptance.

Support the nine existing test workflows, including separately selected library,
focused-browser and strict-client lanes. A skipped ARM browser or documentation
runtime lane remains explicitly unselected. A failed strict SDK profile still
fails; private fixture bypasses cannot repair DEFECT0126. No whole product or
release readiness follows from a scoped campaign verdict.

Use contents/actions read permissions only, dispatch on main, checkout without
persisted credentials, verify owner commit identity and require the source to be
in the trusted main history. Compare the candidate's workflow/typed-validator
bytes with the verifier's reviewed versions before using those contracts. Read
candidate source data with Git; never execute code from downloaded artifacts.
No pull_request_target/workflow_run privilege path, publishing, comments or
external messages. CI authority does not grant customer/primary changes.

Only fixed GitHub API routes are requested with the ephemeral token. For the
documented artifact/log redirect, use a separate HTTPS request without the token,
with reviewed download-host constraints and no further redirect. Bound requests,
response bytes, total bytes/time, JSON nesting, archive members and expansion.
Verify actual archive bytes against the API artifact SHA256, require the exact
single JSON member, validate typed report identities/contracts, and output only
constructed fixed labels/counts/hashes/IDs. Raw logs and downloaded JSON stay
private on the disposable runner. Failures emit a fixed category, never raw
server/command content or token/redirect URLs.

Preserve source inventories, binary/tool identities, per-step outcomes and
artifact/log digests. Actual native PG/SDK/host claims still come from their
original jobs. Existing local acceptance remains authoritative until this job's
boundaries pass stand-ins and an actual complete multi-workflow campaign is
independently checked. Keep every original first failure and exact-source record.
Full450capabilities/41families/later GOAL4.1 scope remains unchanged.

Official contracts checked2026-11-07:

- [Workflow runs and exact-source filters](https://docs.github.com/en/rest/actions/workflow-runs).
- [Artifact digest and download redirect](https://docs.github.com/en/rest/actions/artifacts).
- [workflow_run privileges and untrusted-code warning](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run).

Manual dispatch avoids that completion-event privilege path and makes the
reviewable expected inventory explicit. Automatic triggering can be evaluated
later without weakening the same acceptance contract.
