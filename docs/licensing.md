# Licensing record — local engineering only

The approved sibling structure was inspected read-only at
`../ctlplne-probectl/probectl/LICENSE` on 2026-10-28: BUSL-1.1 core, MPL-2.0 client
trees, commercial code isolated under `ee/`, and four-year conversion per release.
cratectl will follow that tree structure. There is currently no commercial code.

The sibling Additional Use Grant refers to license-key functionality. cratectl's
goal explicitly prohibits core entitlement requirements, so that clause must
not be copied into cratectl as a new core runtime restriction. The exact cratectl
grant needs owner approval before distribution. Pending text does not block
engineering. No publication is authorized by this run.

Proposed parameters, not approved legal terms: certctl LLC as licensor; cratectl
core as Licensed Work; production permission for customer deployments and their
service providers; no core usage caps; MPL-2.0 conversion four years after each
release publication. Hosting/competitive-product restrictions require exact
owner-approved wording. Do not silently finalize a grant.

Core source uses the intended `BUSL-1.1` identifier; public protocol/SDK code,
when introduced under `pkg/`, `proto/` and `examples/`, uses MPL-2.0. Third-party
dependencies retain their own licenses. This record is an explicit distribution
hold, not a license check inside core. Shipping LICENSE text and notices remains
open under LEGAL.GRANT.

The npm semantic-version parser adds `github.com/Masterminds/semver/v3` v3.4.0
(MIT). Its upstream license is retained at
`third_party/licenses/Masterminds-semver-LICENSE.txt`; dependency/source and
binary notice inventory remains part of the distribution gate.

Python index/intake parsing adds `golang.org/x/net` v0.62.0 (BSD-3-Clause) and
`github.com/aquasecurity/go-pep440-version` v0.0.1 (Apache-2.0), with runtime
dependencies `github.com/aquasecurity/go-version` v0.0.1 (Apache-2.0) and
`golang.org/x/xerrors` (BSD-3-Clause). Their license texts are retained under
`third_party/licenses/`; no third-party license is replaced by the core identifier.
