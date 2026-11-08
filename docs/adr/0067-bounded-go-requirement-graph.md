# 0067: Bound Go requirement selection before export planning

Status: bounded metadata resolver/signed caller qualified within scoped12c6;
replacement/exclusion comparisons pass both named78a Go jobs. Complete dependency
export remains required. Full GOAL4.1 scope is unchanged.

The existing common export accepts explicit coordinates. An operator should
eventually supply a project and receive its complete governed package/platform
selection, with every missing or denied dependency preventing completion. A list
of immediate requirements cannot establish that outcome.

`internal/gomodule/graph.go` adds a read-only, single-main-module requirement
resolver. It computes minimal version selection over examined requirements,
retaining constraints from reachable lower versions even when a higher version
is selected. It follows modern pruning and legacy unpruned subgraphs. A version
reached under both modes is expanded under both but loaded and accounted once.
Cycles terminate through bounded version/mode visitation.

The main module controls versioned replacements and exclusions. An exact-version
replacement precedes a wildcard replacement. Dependency-local replace/exclude
directives do not change main-module selection. Local filesystem replacements
are refused: server paths must never become implicit export inputs. An excluded
direct requirement is also refused until the caller supplies a reviewed updated
main go.mod. Automatic version queries, workspace resolution and immutable local
replacement inputs remain required work, with their own native qualification.

The result retains the original main go.mod digest, every examined logical/source
coordinate, original .mod size/digest, Go directive and requirements, including
unselected versions. It records the required Go-version floor and the main
toolchain suggestion without resolving or executing a toolchain. Modern pruning
can select modules whose .mod files were not read. This result is a module-metadata
build list, never a claim that package/platform closure, all permissions, physical
bytes, checksum authority, provenance or destination admission have been verified.

Default work budgets are 256 selected modules, 1,024 examined versions, 16,384
requirements and 32 MiB combined metadata. Each original go.mod is bounded to
1 MiB before parsing. Explicit caller limits have fixed safety ceilings. Reads
are serial; each loader must enforce the supplied byte budget and context on its
own I/O. Cancellation and budgets produce no partial result. Missing/denied input
errors propagate without fallback. No package or model code executes.

The actual eight-module PostgreSQL/TLS/signed-collection journey now derives its
selection from authorized original .mod bytes through this resolver. The final
common snapshot still checks all eight ZIP/mod/info representations and current
grants; the stock SDK independently downloads exactly that selected set and
checks its original bytes and h1 values. The whole12c6 campaign qualifies that
common/requirement caller scope. Later78a named118Go normal/race jobs on both Linux
hosts compare five replacement/exclusion cases with the actual pinned SDK after
signed collection/source shutdown in31 empty command networks. See ADR0073 and
evidence/2026-11-07/go-module-78a5983-native-checkpoint.json. Whole78a acceptance,
workspace/local immutable inputs and full package/platform closure remain separate.

Before exposing a complete automatic export, integrate the resolver with the
common source/authorization path and bounded CAS inspection. After all external
I/O, one final common read snapshot must revalidate every resolution input,
including unselected versions, and every selected root and routing revision.
Creation must repeat those guards under the existing mutation fence. Do not hold
a database transaction across external I/O. Retain immutable graph inputs in the
signed export proof, verify package imports and platform/build-tag selection,
qualify private/proxy/group precedence and authority, and implement current import,
scanner, server-session and operator outcomes. Existing manifests/receipts keep
`dependency_closure`, checksum authority and current destination admission false.

References: [Go minimal version selection](https://go.dev/ref/mod#minimal-version-selection),
[graph pruning](https://go.dev/ref/mod#graph-pruning),
[replace](https://go.dev/ref/mod#go-mod-file-replace),
[exclude](https://go.dev/ref/mod#go-mod-file-exclude), and the pinned Go1.27.3
`cmd/go/internal/modload` implementation. The algorithm is original project code;
the SDK is the intended independent native comparison, not a copied resolver.
