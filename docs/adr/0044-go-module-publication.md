# Go module identity and atomic publication

Hosted and group adapters are implemented but unverified. They register native Go reads
and atomic bundle publication; local tests do not establish stock-client
compatibility. Both native hosted/group journeys and all proxy-retrieval work remain required.

Use the official `golang.org/x/mod` module/path/version and go.mod parsers,
pinned to v0.42.0 with normal Go checksum verification. Its BSD-3-Clause license
and dependency are deliberate; no new service or runtime fetch is introduced.
Reject alternate URL spellings, noncanonical versions and incompatible major
version suffixes. Native uppercase escaping is distinct from HTTP URL escaping.

The shared ZIP inspector bounds physical central-directory entries before the
standard library allocates them. It checks local/central header agreement,
contiguous byte ranges, CRC, exact expanded sizes and exact compressed-stream
consumption. It never extracts or executes files. NuGet keeps its existing
path/manifest rules and regression corpus through this same inspector; each
format selects only its own bounded metadata to buffer. ZIP64, split archives,
links and alternate Unicode path records remain unsupported admission cases.

The Go profile additionally checks the unescaped module@version ZIP prefix,
portable file paths, case-fold collisions including implicit parent directories,
and the exact root go.mod declaration. It requires a root go.mod. Legacy modules
without one need a separately implemented workflow. A caller supplies the stable
publication instant; retries must preserve it rather than synthesizing new info
bytes. Names and sizes are resource controls, not edition entitlements.

Publication stages/syncs the exact ZIP, root go.mod and version-info bytes, then inserts
all three references through the common tenant mutation transaction. It applies the
same current authority and digest review to the complete bundle and discovery.
Each read checks all three current references; partial approval cannot expose a
sibling. Publication cannot overwrite a version. Durable actor/coordinate replay
checks current write authority before its receipt. Go-specific lifecycle operations
remain unimplemented; ordinary repository admission stays enforced. Proxy/group intake, freshness, source fences
and checksum dependencies require separate implementation and native proof.

The stock Go client only applies GOAUTH/netrc credentials to HTTPS. Qualification
must use an owned trusted loopback TLS installation and private NETRC, not URL
credentials or an insecure TLS exception. Set one explicit GOPROXY with no direct
fallback, disable VCS, isolate project caches and state the checksum-database
policy. Download and inspect owned dependency-bearing fixtures without running
package code. Both actual Linux architectures and real PostgreSQL must pass;
local parser tests do not qualify this journey.

References observed 2026-11-04: the official [module protocol and authentication
reference](https://go.dev/ref/mod), [module identity library](https://pkg.go.dev/golang.org/x/mod/module)
and [module ZIP constraints](https://pkg.go.dev/golang.org/x/mod/zip). The reviewed
v0.42.0 source/checksum identities are retained in the development record.


The group extension reuses common source resolution and final source/group
revision admission. Native discovery queries hosted members in one repeatable-read
transaction with shared row/metadata budgets. First-source blocked coordinates
remain in the merge, preventing lower-source substitution. Stronger group review
covers the complete bundle. Namespace-owner selection uses escaped Go module
prefixes for both discovery and direct byte paths. Only hosted members are
implemented; native proxy intake remains rejected. No new schema or runtime
privilege is needed. The native v2 profile retains every v1 case and adds ordered
sources, stronger review, namespace pinning, source-grant denial, group read-only
publication and restart/revocation through the group. It requires nine stages,
24 publisher/reference/HTTP bindings and16 exact stock ZIP/mod cache bindings.
These are required observations, not a native pass claim.

The next proxy foundation validates independent upstream representations before
intake: bounded `.info` must name the exact canonical version, preserve optional
Time and tolerate opaque future fields without trusting them. Duplicate/case
aliases and ambiguous metadata fail. The `.mod` response must exactly equal the
validated ZIP root go.mod bytes. Original info bytes remain separate from parsed
identity. These validators have unit/race and short owned-input fuzz proof; they
are not connected to proxy routes. Atomic multi-object retrieval/cache receipts,
source/grant/lease fences, checksum authority and full native journeys remain
required before enabling Go proxy mode. Legacy module synthesis is separate.

The internal retrieval completion extension now accepts an already inspected and
staged three-object bundle under one canonical ZIP lease. Reference/cache-root
receipts, integrity jobs and ready event/outbox share the common transaction,
with current read authority, source epoch and live generation checked first.
All three representations remain immutable in this initial intake profile.
Three PostgreSQL regressions compile but have not executed; ordinary proxy
creation stays rejected. A complete network/cache/serving implementation must
use this foundation and prove its behavior with native clients before exposure.

Bounded upstream version advertisements now have a separate canonical parser:
whole-input byte/count checks, semantic order, no duplicate/pseudo/alias entries
and no partial valid prefix after a later failure. A line walk avoids allocating
one slice per physical line. Advertised names do not approve unknown bytes.
Persisted source/freshness catalogs and current first-source/bundle policy must
still be joined before these names can power a proxy/group response.
