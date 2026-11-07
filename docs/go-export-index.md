# Verify several historical export manifests together

`cratectl go-export-index-verify` authenticates a selected list of export
manifests through one complete signed journal. It is implemented; actual native
qualification is pending. This preflight checks what each original export
claimed before you collect its package bytes. Full multi-artifact collection,
dependency/proof closure and current-policy import remain unfinished.

Select each original export ID, exact repository/module/version and creation
event sequence yourself. Obtain the canonical manifest through the normal
current-authorized export route. Keep it in a private regular file. Select the
journal tenant/terminal checkpoint and trusted public key through your
independent trust channel; a key stored beside the files cannot authenticate
itself. Use your existing external signing tool as described in
[journal export](journal-export.md). No signing private key is accepted here.

Create a private index with compact JSON in this exact field order and a final
newline. Replace the example identities/sequences/paths with your selected
originals; both example IDs below are placeholders:

```json
{"profile":"cratectl.go.export.index.v1","entries":[{"repository":"hosted","module":"go.cratectl.invalid/Owned/first","version":"v1.0.0","export_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","event_sequence":7,"manifest_file":"/private/path/first-manifest.json"},{"repository":"other-hosted","module":"go.cratectl.invalid/Owned/second","version":"v1.2.0","export_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","event_sequence":11,"manifest_file":"/private/path/second-manifest.json"}]}
```

Store it as `/private/path/export-index.json` with mode0600 under a private
parent. All manifest paths must be absolute and clean. Unknown/duplicate JSON
fields, aliases, missing values, noncanonical formatting and duplicate
coordinates/export IDs/event sequences refuse the whole index. Entry order is
the returned binding order; it need not match journal order.

```sh
cratectl go-export-index-verify \
  --index-file /private/path/export-index.json \
  --journal-file /private/path/journal.jsonl \
  --journal-tenant "$CRATECTL_TRUSTED_TENANT" \
  --journal-through "$CRATECTL_TRUSTED_JOURNAL_SEQUENCE" \
  --journal-through-hash "$CRATECTL_TRUSTED_JOURNAL_HASH" \
  --checkpoint-file /private/path/checkpoint.json \
  --checkpoint-signature-file /private/path/checkpoint.sig \
  --checkpoint-key-file /private/path/independently-trusted-public.pem
```

The index selects all events. Supplying `--journal-event-sequence` is rejected.
The command verifies the complete signed range and EOF before it binds any
manifest. If even the last manifest fails, no binding receipt is printed.
It makes no registry request, opens no package file and writes no output file;
redirect successful JSON into a new private receipt if you want to retain it.

The receipt includes index/event/manifest hashes, the complete journal and
signature observations, per-export declared package sizes and their sum. It
omits private paths and historical policy bodies. Declared size does not prove
package content: `artifact_bytes_verified`, `dependency_closure`,
`consistent_server_snapshot`, `checksum_authority_verified` and
`current_registry_admission` are all false. Continue verifying exact original
ZIP/mod/info through the existing [offline workflow](go-module-offline.md).
That workflow currently prepares one version per private output, not a complete
multi-module proxy. A valid old source decision never grants destination access
or scan approval, and a historical signature does not establish latest history.

Limits:256KiB index,256members,32KiB per manifest,4MiB retained selected original
payloads. `--max-artifact-bytes` bounds the sum of declared representation sizes
(default1GiB, positive through64GiB); repeated content is counted separately.
Existing `--journal-max-bytes` and page/frame bounds still apply.
`--journal-timeout` defaults to5minutes and accepts a positive duration through
1hour. Linux/macOS private regular-file semantics are implemented; Windows ACL
and broader provider/fault/scale qualification remain required.
