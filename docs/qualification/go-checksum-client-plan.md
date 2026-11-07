# Qualify stock Go checksum verification and failed client state

Status: open investigation. The exact5567d24 GitHub workflow reproduces the
mandatory ZIP trust-state failure on actual Linux amd64, Linux arm64 and macOS
arm64. Original safe summaries and owner-encrypted observations are retained in
[the three-host checkpoint](../../evidence/2026-11-07/go-checksum-client-5567d24-native-reproduction.json). All21 inner records were
authenticated/decrypted locally; six other controls pass per host. The dedicated
three-job profile remains failed. The pinned native Go 1.27.3 probe passes a signed cold download and two warm/fresh-consumer controls against
owned TLS response stand-ins. It rejects altered go.mod, invalid signature and
unavailable authority controls without recording sums. The altered ZIP control
fails a stronger trust-state requirement: the first command returns nonzero,
but its failed consumer retains the altered ZIP sum, and a controlled retry
returns zero and physically extracts the known altered inert file.

See [first retained observation](../../evidence/2026-11-07/go-checksum-client-negative-control-first.json).
Original diagnostic records and probe copies remain private with exact hashes.
No package code is compiled or executed. No cratectl registry, real database,
customer system or public package service participates in this probe. It does
not change the separately qualified source-14 internal admission/review tests.

The [Go module reference](https://go.dev/ref/mod#checksum-database) describes
explicit checksum database keys/URLs and the effect of GONOSUMDB. These controls
supply the public verifier key separately, use an explicit owned TLS URL, leave
GONOSUMDB/GOPRIVATE empty and disable VCS/public package fallback. Original public
lookup/tile signatures and exact mod/ZIP h1 are checked by the stock client.

The local command source matches [official Go 1.27.3 fetch.go](https://github.com/golang/go/blob/go1.27.3/src/cmd/go/internal/modfetch/fetch.go)
byte-for-byte. Its used-sum bookkeeping before verification and later sum-file
rewrite suggest an explanation for the observed failed-cache transition. This
is an inference, not a maintainer-confirmed root cause. The failure observations
are independently reproduced on the three named hosts; broader SDK versions and
platforms remain unqualified.
No external report or message has been sent.

## Required native evidence

The dedicated `go-checksum-client.yml` workflow runs the same seven controls on
actual Linux amd64, Linux arm64 and macOS arm64 with the exact repository toolchain
pin. It uses only loopback port 38443, owner-private temporary state, original
public signed fixtures and inert resource files. No package scripts, builds,
models, database or primary changes occur. Individual client commands have a
60-second limit and bounded output; the entire native job has a 15-minute limit.

Keep all seven controls: verified cold download, verified warm cache, a fresh
consumer sharing a verified client cache, and rejection/trust-state checks for
changed ZIP, changed go.mod, invalid signature and unavailable authority. The
ZIP assertion is not removed or replaced with an expected-success retry. The
probe remains failed whenever untrusted state is retained. A single controlled
retry inspects the inert asset solely to explain that failure.

Safe summaries contain fixed control identifiers/outcomes, source/platform and
binary/fixture/script digests, plus bounded boolean observations. They contain no
raw Go output, private paths, credential values or source response bodies.
Failure observations are sealed to the existing owner-held diagnostic recipient;
the private key never visits GitHub. No plaintext artifact fallback is allowed.
The exporter has separate owned unit controls for complete-only success, strict
outcome/size bounds and private payload exclusion. Those stand-in exporter tests
do not establish encryption or actual native client behavior by themselves;
standard diagnostic crypto and actual runner evidence remain separate.

Accept every actually selected native job, original safe artifact and encrypted
failure metadata at its exact source. Preserve platform failures/skips as such;
no retry, case removal, checksum bypass or poisoned-cache reuse becomes a pass.
The current local result cannot establish Linux behavior. Public Go proxy
creation/routing, checksum-on stock proxy/group and full disconnected/cache/
install/export/backup/GC/conditional-refresh outcomes remain open. All 450
artifact capabilities, 41 families and later GOAL stages remain under section 4.1.
