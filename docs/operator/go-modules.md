# Go modules

The named hosted and ordered-group profile is verified on both actual GitHub
Linux architectures at809e826:312stock Go1.27.3 checks and80named PostgreSQL
functions normally and under race. See the [native checkpoint](../../evidence/2026-11-07/go-module-809e826-native-checkpoint.json).
This is a scoped result; no full format or production verdict follows. Public
proxy creation/routing remain gated. The separate strict checksum-client profile
fails under DEFECT0126 on three native hosts; the312hosted/group profile uses
an explicit private-fixture GONOSUMDB bypass. Keep those claims separate.
Branch/revision queries, modules without root go.mod, full warm/offline caches,
lifecycle/GC, backup, migration and broader fault/scale/platform cases remain.
The new [historically authenticated offline preparation](../go-module-offline.md)
command passes ARM development checks but requires fresh native qualification.

Create a `go` repository in hosted mode using the console or repository API.
Its endpoint is `https://REGISTRY/go/REPOSITORY/`. A version is one immutable
bundle: the original module ZIP, its exact root go.mod, and version/time JSON.
The server verifies and syncs all three objects before publishing their references
and journal/outbox in one transaction. It never builds or executes uploaded code.

Go has a download protocol rather than a standard package-push command. Publish
a portable Go module ZIP with cratectl and a private writer configuration:

```sh
cratectl --config /private/path/writer.json --method PUT \
  --path '/go/REPOSITORY/ESCAPED_MODULE/@v/VERSION.zip' \
  --upload-file MODULE.zip --go-module-time COMMIT_TIME_RFC3339
```

The CLI validates a canonical Go ZIP route, PUT, upload-file and matching
timestamp before sending the request. The named native hosted/group profile includes real publication and consumption;
its exact-source candidate evidence is linked above.

Use a stable RFC3339 version creation time. A pseudo-version must carry that
same timestamp. Retain it on retries. Identical retries return the original
receipt; changing ZIP or info bytes at an existing version returns conflict.
An optional `--idempotency-key` binds the receipt to the authenticated actor and
exact repository/bundle; omitting it derives a stable actor-scoped coordinate
key. Current write authority is checked before replaying a receipt.

Latest discovery returns403when this module has retained versions but current
review/policy leaves none readable. It keeps404for an absent module and never
returns blocked version metadata. Continue to configure one explicit proxy.
The named native profile exercises empty/denied discovery; broader client and
fallback behavior remains subject to separate qualification.

The ZIP must contain paths beginning `MODULE@VERSION/`, using the original
unescaped module name. Its root go.mod must declare that exact module. URLs use
Go's uppercase convention: `example.org/Owned/app` becomes
`example.org/!owned/app`. Versions must be canonical and match their module's
major-version suffix. Branch aliases and revision queries remain unsupported.

Save credentials in a private NETRC file readable only by its owner. Bind its
machine name to the registry authority, including an explicitly configured port,
without a scheme or path. For `https://localhost:38443`, use
`machine localhost:38443`. The pinned Go client matches that authority exactly;
a hostname-only entry does not authorize this port. NETRC binds
a whole host; use a custom GOAUTH helper if credentials must be scoped to URL
prefixes. Keep credentials out of GOPROXY URLs and shell command arguments.
Trust the operator CA and use normal HTTPS verification:

```sh
export NETRC=/private/path/registry.netrc
export SSL_CERT_FILE=/private/path/ca.crt
export GOAUTH=netrc
export GOPROXY=https://REGISTRY/go/REPOSITORY/
export GOPRIVATE=YOUR_PRIVATE_MODULE_PREFIX
export GONOPROXY=none
export GONOSUMDB=YOUR_PRIVATE_MODULE_PREFIX
export GOVCS='*:off'
go mod download MODULE@VERSION
```

One explicit proxy and disabled VCS avoid an implicit source fallback.
GONOPROXY keeps private modules on this configured registry. GONOSUMDB prevents
private names from reaching the public checksum service; it does not provide a
private checksum database. The Go client still computes module sums. Public
checksum mirroring, imported trust and disconnected checksum behavior need
separate implementation and qualification.

A repository requiring review needs current approval for all three bundle
representations. Denial or missing approval of any one blocks native reads and
discovery of that version. Inspect the exact digests in the administrative
inventory before making decisions. Archive validation does not establish a clean
security scan. A cached client copy remains under the client's control; server
revocation governs new requests. Ordinary policy cannot erase downloaded files.

Groups provide one read endpoint over existing hosted Go sources. Create a
`go` repository in group mode with ordered `settings.members`. Publish through
a hosted member, then point GOPROXY at the group. Readers need authority on the
group and each consulted source. Discovery checks every source it consults; a
missing source grant stops the complete index instead of silently omitting it.

For a given version, the first source owns that coordinate. A denied, unreviewed,
retired or incomplete first-source version cannot be replaced by a lower copy.
Only a wholly absent coordinate permits normal ordered fallback. A group can
require stronger review than its sources; all three ZIP/mod/info representations
must meet that review before serving any sibling. Namespace owners in
`settings.namespace_owners` pin an escaped native module prefix ending in `/`
to one member, including when the pinned member lacks the requested version.
Complete version discovery and latest selection apply the same first-source and
review rules. Oversized views fail rather than returning truncated indexes.

These group rules have local unit/race and four integration-test compilations;
actual stock-client/PostgreSQL/browser and broader source/configuration races
remain unverified. Proxy repositories and richer source recovery remain required.

Defaults admit 64MiB compressed ZIP, 256MiB expanded bytes, 4MiB central directory,
10,000 entries and 1MiB root go.mod. Operators can configure ZIP/expanded/directory/
entry budgets through `--go-module-upload-bytes`, `--go-module-expanded-bytes`,
`--go-module-directory-bytes` and `--go-module-file-budget`. These are resource
budgets. ZIP64, split archives, links and alternate path records are rejected.

Protocol and authentication: [official Go module reference](https://go.dev/ref/mod).
The [architecture record](../adr/0044-go-module-publication.md) explains admission
and the separate proxy/group requirements.
