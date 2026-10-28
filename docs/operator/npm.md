# npm repositories, publication and tags

Create a hosted repository with format `npm` through the management API or CLI.
Use its `/npm/REPOSITORY/` URL as the npm registry and scope the service token to
that path in a private npm configuration file. A reader token installs packages;
a writer or administrator token publishes and changes distribution tags.

Publish with ordinary `npm publish --ignore-scripts`. Publish a prerelease with
`--tag next`, then use `npm dist-tag add PACKAGE@VERSION stable` or
`npm dist-tag rm PACKAGE stable`. Tags change independently of immutable version
tarballs. `npm install PACKAGE@latest` and `npm install PACKAGE@next` resolve the
current pointer, while an exact version and lockfile retain their version/digest.
The registry never runs uploaded package scripts. Test consumers use
`--ignore-scripts` to avoid running fixture scripts as well.

Metadata at `/npm/REPOSITORY/PACKAGE` contains only versions currently permitted
by repository policy. `/PACKAGE/VERSION` or `/PACKAGE/TAG` returns one version.
Tag management uses the native `-/package/PACKAGE/dist-tags` routes. A denied
digest hides every alias of those bytes within the repository, including tags,
and blocks direct tarball reads. Repository inventory lets an administrator
inspect quarantined references and issue an explicit manual decision.

If metadata returns `metadata_budget_exceeded`, inspect the package's version,
tag and metadata volume, then size the server's `--native-version-budget`,
`--native-tag-budget` and `--native-metadata-bytes` for available memory and work.
The default budgets are 10000 versions, 128 active tags and 8 MiB metadata.
The registry returns no partial index. Retrying an unchanged oversized request
will not repair the condition.

Intake reads package metadata from the tarball's `package/package.json` and checks
that its name and semantic version match the published coordinate. Outer publish
metadata cannot replace the dependencies described by those bytes. The default
input budgets are 24 MiB for the encoded publish document
(`--npm-publish-bytes`), 64 MiB expanded archive bytes (`--npm-expanded-bytes`),
10000 archive entries (`--npm-file-budget`) and 1 MiB for package.json
(`--npm-package-json-bytes`). Expanded headers and padding also count. Operators
can size these budgets; package.json must fit the expanded-byte budget.

An `invalid_npm_archive` response means the archive needs to be regenerated or
its budgets inspected. It must contain one matching package.json, valid gzip/tar
data and unambiguous paths inside `package/`. Links must stay inside the archive,
resolve to members and avoid cycles or linked parent directories. Devices,
traversal paths and Windows drive/stream path interpretations are rejected.
These checks validate the container and coordinate; they do not assess whether
package code is safe. Unassessed content remains explicitly unassessed.

For an upstream, create an npm repository with mode `proxy`, an `upstream` URL,
explicit network CIDRs and an operator credential reference. Its cache settings
control freshness, negative caching and explicit stale use. A normal npm install
uses this repository's `/npm/REPOSITORY/` URL. Catalog and tarball requests use the
same governed retrieval machinery; exact source bindings survive restart and
metadata refresh. New reads still enforce current grants and digest decisions.

If tarballs live under a separate authority/base path, add it to
`settings.download_sources` with its own URL, CIDRs and credential reference.
Metadata cannot grant network access or forward another source's credentials.
Up to 16 explicit download sources are accepted. URL queries, embedded credentials
and cross-authority redirects are rejected. Private destinations also need the
server's operator network ceiling. See [proxy configuration](proxy-and-group.md).

Create a mode `group` npm repository with an ordered `members` list. It merges
versions, keeps the first source for each collision and uses that source's tags.
A denied or quarantined first-source version cannot fall through to another
member. Namespace owners can reserve `@private/` or an exact `package-name/` for
one member. Readers need access to each selected member; a missing grant fails
the group request. Group endpoints accept native reads; publish and tag mutations
go to the appropriate hosted member.

A review-required proxy initially hides unfetched versions. Request the
conventional `/npm/REPOSITORY/NAME/-/NAME-VERSION.tgz` path to perform quarantined
intake, inspect repository inventory and review its exact digest. For scoped
packages this development route repeats the full scoped name in the filename.
Approval makes that validated version visible. Each source descriptor needs its
own archive/metadata validation; approval is not inferred from an unvalidated URL.

An invalid integrity value, archive or dependency disagreement creates no tarball
reference. Its coordinate remains blocked in metadata and groups. After repairing
the upstream, an administrator can expire that exact cache path through the cache
API, or revalidate its retained pinned download URL. Active negative-cache entries
hide unavailable tarballs until their configured deadline. Use inventory metadata
and the cache API's last-error classification to distinguish these cases.

This is early hosted/proxy/group proof. Unpublish, ownership, package signatures,
cross-authority redirects, signed-query URLs, full npm/pnpm/Yarn compatibility,
lifecycle and the complete fault campaign remain required. There is no full
format or production-readiness verdict.
