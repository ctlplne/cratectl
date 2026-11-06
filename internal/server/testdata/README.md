# Owned checksum authority fixture

`go-checksum-public.json` contains only a public verifier key, signed empty/one-
record checkpoints, original lookup/hash-tile responses and content h1 values
for `goOriginBytes`. It was generated with the pinned x/mod test server inside
the crypto test boundary. The temporary generator and private signing key are
not part of the application or this fixture. No external service was contacted.

Server tests independently inspect the actual inert ZIP, fetch these original
responses through the configured loopback authority, replay the proof offline
and verify the durably staged bytes. Fixture hashes and publisher signatures are
verification inputs; they do not constitute production trust or package approval.

Owned fixture and documentation: SPDX-License-Identifier: BUSL-1.1.
