# 0073: Compare replacement and exclusion metadata with the native Go SDK

Status: qualification implementation; native execution pending. No production
resolver, database definition, trust grant or closed campaign contract changes.
The full owner-amended GOAL4.1 remains required.

The requirement export preserves the project's original `go.mod`, every examined
source `.mod`, the logical build list and its physical source coordinates. Those
identities differ when the project replaces a module with another module. Sorting
physical source inputs must not reorder logical selections or change root ordinals.

One additional integration function runs five explicit, independently specified
cases through real PostgreSQL, native publication and allowed policy decisions,
actual candidate CLI creation over trusted TLS, exact creation replay, external
OpenSSL checkpoint signing and original collection/replay:

| Case | Required comparison |
| --- | --- |
| Specific replacement | A version-specific replacement wins over an unpublished wildcard target. Logical `aa-original` selects physical `zz-fork` before logical `mm-leaf`, reversing physical source order. |
| Wildcard replacement | A wildcard replacement selects the same fixed fork. Both replacement cases ignore the dependency's own local replacement and exclusion directives. |
| Exclusion with another branch | The main exclusion removes the lower transitive edge; a separate legacy branch selects the explicitly required higher version. The excluded version is never published. |
| Excluded-only edge | Excluding the only transitive edge leaves the metadata build list without that dependency. It does not invent a version-catalog query. |
| Exclusion with a lower direct root | Removing the excluded transitive edge does not impose its version as a floor on the separately required lower direct root. |

After the owned TLS listener stops, the pinned Go1.27.3 SDK independently lists
logical modules and replacement identities, downloads exactly the physical
selections, compares original ZIP/mod h1 values and reads inert asset bytes.
Each signed collection is independently verified and assembled by the native CLI;
same-input replay returns the original receipt. Every CLI and SDK command records
its actual empty child network namespace under the ordinary job identity:31
commands across five cases. The SDK can edit its private consumer copy of the
project; the original collection and completion receipt must remain unchanged.
No package is compiled or executed.

The excluded-only case is deliberate metadata behavior, not a complete package
export. The pinned Go source `cmd/go/internal/modload/modfile.go`, `goModSummary`,
filters excluded dependency edges. Resolving an import can still need another
version and more inputs. A proposed additional minimum-version check would reject
valid metadata graphs and is not introduced. The project's direct excluded roots
remain an explicit refusal until a reviewed updated main file is supplied.

Local qualification is limited to pure graph/proof regressions, bounded SDK JSON
response and filesystem stand-ins, build/unit/race/lint, and tagged compile/vet.
Actual PostgreSQL, external signer, SDK and Linux namespace claims require the
original GitHub jobs. The new function is selected by existing full and Go-only
normal/race suites on both actual Linux architectures. It raises the inventory to
296 full PostgreSQL functions/118 named Go functions;66 fuzz targets remain.
No additional always-on job or weaker evidence compatibility exception is needed.

The existing20 closed campaign contracts stay byte-identical. The in-flight
12c6c49 profile retains its own original jobs and qualification boundary; these
later comparisons are never backdated into it. Unchanged optional browser,
library and strict checksum profiles count only if actually selected and passed.

Package imports, platform/build-tag closure, workspace/local immutable inputs,
automatic excluded-root resolution, source precedence and public/private checksum
authority, current destination scan/import/session/operator outcomes and every
remaining GOAL requirement stay open. `dependency_closure`, checksum authority,
current registry admission and broad readiness remain false.

References: [Go replacement directives](https://go.dev/ref/mod#go-mod-file-replace),
[exclusion directives](https://go.dev/ref/mod#go-mod-file-exclude),
[minimal version selection](https://go.dev/ref/mod#minimal-version-selection),
and the original pinned SDK source retained by the qualification setup.
