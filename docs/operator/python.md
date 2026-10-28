# Python repositories and package metadata

A hosted `pypi` repository accepts ordinary twine uploads at
`/pypi/REPOSITORY/`. Configure pip with `/pypi/REPOSITORY/simple/`. A writer token
publishes; a reader token resolves and downloads permitted packages. Keep tokens
in a private client configuration or netrc, scoped to the registry. Do not put
credentials in index URLs or command arguments.

The registry checks the distribution filename and embedded Name/Version against
the upload. Requires-Python comes from those bytes. ZIP wheels and ZIP/tar.gz
source distributions are inspected without extraction or execution. Source
package code runs only if the consuming build client chooses to build it. A
successful structural/hash check is not a malware, vulnerability or license verdict.

Configure an upstream mode `proxy` with its simple-index URL, explicit network
CIDRs and optional tenant credential reference. If files use another base path
or authority, add a `download_sources` entry with its own CIDRs and credential
reference. Public PyPI normally uses `https://pypi.org/simple/` for metadata and
`https://files.pythonhosted.org/packages/` for files. Private destinations also
require the server's operator network ceiling. URL queries, embedded credentials
and cross-authority redirects remain rejected.

The default `python_index_format` is `auto`, preferring version 1 JSON with HTML
fallback. Use `html` or `json` to request that representation from an upstream.
Clients can request HTML or `application/vnd.pypi.simple.v1+json` from cratectl.
File links preserve wheel filenames and bind exact source URLs and hashes.
Metadata refresh never changes an already issued pinned URL's binding.

A mode `group` repository combines an ordered list of hosted/proxy members.
The first source owns each filename collision; denied or quarantined files cannot
fall through. Reserve an exact normalized project with a namespace owner such as
`"private-project/": "internal-python"`. Readers need grants to all selected
members. Publish and change yanks on a hosted member.

Metadata sidecars (`FILE.metadata`) contain the exact core metadata from the
validated parent archive. The parent's current authorization, digest policy and
stored-byte integrity govern both responses. A review-required proxy hides
unfetched files. A conventional `/pypi/REPOSITORY/files/FILENAME` read performs
durable quarantined intake; inspect inventory and manually review the exact
digest before it becomes a candidate.

Administrators can PUT `/api/v1/repositories/REPOSITORY/yanks` with an
Idempotency-Key and `{"filename":"FILE.whl","yanked":true,"reason":"reason"}`.
Set `yanked` false to restore ordinary resolution. A yank advises native selection;
an exact pip pin may still fetch it. Use a digest denial to block package and
sidecar reads. Cache inspection distinguishes origin, integrity, metadata and
transient failures; repair the origin then expire the affected cache path.

Defaults are a 64 MiB encoded upload/distribution budget (`--python-upload-bytes`),
256 MiB expanded archive budget (`--python-expanded-bytes`), 10000 entries
(`--python-file-budget`) and 1 MiB core metadata (`--python-metadata-bytes`).
The shared native index budgets cap file count and total metadata. Operators size
these safety controls for their infrastructure; no partial index is returned.

Legacy development references without archive validation fail closed. Re-upload
the same exact bytes through a writer to enrich them safely; an existing digest
decision remains attached to those bytes. This is not a production upgrade or
recovery qualification. Root indexes list authorized hosted/cached inventory.
Full upstream enumeration, hashless sources, all standards/clients, lifecycle,
attestations and the complete security/fault campaign remain open.
