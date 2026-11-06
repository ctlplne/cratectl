# Public Go checksum timeline fixture

`go-checksum-timeline-public.json` contains a public verifier key, signed empty,
one-record and two-record heads, original lookup/hash-tile responses, and a
same-key conflicting log. It covers consistent growth, concurrent admission,
missing consistency tiles, older lookups and authenticated forks.

The original inert ZIP contents are `go.mod` and `assets/inert.txt`, with the
module, versions and payload recorded in the JSON. Tests inspect the real staged
ZIP and compare both h1 values. No package contents execute.

A temporary exporter inside `internal/crypto` used the pinned standard sumdb test
server and an ephemeral random signing key, entirely in memory. Only the public
fixture was written. The exporter was deleted; no private signing key or signing
service is part of the application or fixture. No external log was contacted.

Owned fixture and documentation: SPDX-License-Identifier: BUSL-1.1.
