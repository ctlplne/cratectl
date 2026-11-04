# Go module identity and atomic publication

The hosted adapter is implemented but unverified. It registers native Go reads
and atomic bundle publication; local tests do not establish stock-client
compatibility. Both native hosted journeys and all proxy/group work remain required.

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
