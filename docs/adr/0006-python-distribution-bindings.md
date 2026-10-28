# Python distribution identity and governed indexes

Python publication now derives Name, Version, Requires-Python and core metadata
from the distribution bytes. Multipart identity fields and the filename must
agree. A wheel's root dist-info/METADATA or source archive's PKG-INFO is read with
bounded standard ZIP/tar/gzip parsers. The registry never extracts files, imports
a module or runs a build backend. Path traversal, ambiguous case/path duplicates,
escaping/cyclic links, special file types and configured resource excess fail
intake. Accepted bytes are durable before publication and its journal/outbox intent.

The new common `native_sources` table stores format-scoped immutable source
descriptors. Catalog publication and descriptor batches share the existing
retrieval generation/token fence and transaction. Legacy npm descriptors are copied
without changing their keys, preserving retained pinned URLs; the old immutable
table is retained. Runtime readers check repository format, grants and forced RLS.
The ordinary repository-digest decision path still governs cached bytes.

PyPI proxies accept modern simple JSON and HTML project indexes. The maintained
Go HTML tokenizer and Aqua Security PEP 440 parser handle their respective
grammars. Index file names must agree with normalized project coordinates. Links
must carry a supported strong hash and resolve to an approved metadata/download
source. Download credentials, destination CIDRs and the operator private-network
ceiling remain independently bound. Local filename-preserving URLs identify the
source descriptor, retaining old hash-locked requests across refresh and restart.

Index Requires-Python declarations and advertised core-metadata hashes are checked
against the fetched archive. The exact embedded metadata supplies `.metadata`
responses; a separate upstream metadata payload cannot substitute a dependency
graph. Parent-byte integrity and current parent/group policy are checked before
serving the sidecar. A missing scan remains unassessed. Review-required sources
hide unfetched or unapproved files; a conventional download can perform quarantined
intake for subsequent manual review.

Group file-name collisions belong to the first configured source, including
blocked coordinates. Missing files may be combined; a denial does not authorize
fallback to another same-name file. Namespace ownership reserves a normalized
project before source lookup. Group/member grants, source catalogs, yanks and
digest decisions are evaluated in one PostgreSQL view snapshot. Complete-index
budgets reject oversized results instead of truncating dependency candidates.

Hosted yanks are versioned, audited, idempotent mutable state separate from
immutable files. Yanked files stay downloadable under current policy so an exact
client pin can retain them; ordinary pip selection can avoid them. Policy denial
still hides and blocks the file and its metadata. Proxy refresh observes upstream
yank changes without rebinding previously issued source URLs.

Simple HTML and JSON reads support canonical project URLs, Requires-Python,
yanking, core-metadata aliases, ranges, HEAD and conditional reads. Source builds
occur only in explicitly owned test consumers. This does not qualify arbitrary
build backends or an execution service in the registry.

Open scope includes hashless upstream compatibility, signed-query/cross-authority
redirects, full upstream root enumeration, all legacy distribution forms, every
metadata/API revision, uv and other clients, attestations, dynamic source metadata,
complete malicious-parser/fault campaigns, lifecycle and production migration.
The root index currently reflects authorized hosted/cached inventory, not an
exhaustive upstream project mirror. This remains an implementing format row.

References observed 2026-10-28:

- [PyPA simple repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/)
- [PyPA core metadata](https://packaging.python.org/en/latest/specifications/core-metadata/)
- [PyPA file yanking](https://packaging.python.org/en/latest/specifications/file-yanking/)
- [Aqua Security PEP 440 parser](https://github.com/aquasecurity/go-pep440-version)
