# Private GitHub failure diagnostics

The native OCI workflow normally publishes only reviewed summary fields.
Some client failures contain paths or credentials and cannot safely be printed
verbatim. If a fixed diagnostic marker does not identify the failure, the job
encrypts a bounded diagnostic payload for local inspection.

The payload contains a bounded failure message, commands that unexpectedly
failed and the owned registry log. For an assertion after a command returned,
it instead retains the last observation, explicitly marked `observation_only`
with its actual exit code. Cleanup cannot replace that observation. Token,
credential and database configuration files and all other command logs remain
excluded. A maximum of four reports, two selected commands per report, 8 MiB per log and 16 MiB of
combined raw logs applies. The serialized payload is limited to 24 MiB.
Special files, symlinks, extra hardlinks and paths outside the owned private
directory are rejected. This is diagnostic collection, not a test pass.

OpenSSL encrypts the payload as standard CMS using AES-256-GCM, with an
RSA-OAEP/SHA-256 recipient. The public recipient certificate is
`docs/qualification/ci-diagnostics-recipient.pem`. Its SHA-256 DER fingerprint is
`BFA04B5681B6C9092984D101EA101A45038CAE7AE0149F9DD19C606CED1D756F`.
The matching key is retained only at the ignored local path
`.private/ci-diagnostics/recipient-20261102-key.pem`, with mode0600 under the
mode0700 private directory. The CI workflow has no private key or decryption
secret. Do not commit or upload that key.
The real CMS regression suite requires OpenSSL 3 or later. The macOS source job
selects the native Homebrew `openssl@3` binary and prints its version; Linux
uses the observed runner OpenSSL. An unsupported CLI fails with a fixed
family/version diagnostic. No crypto test is skipped.

On a failed job, GitHub retains `encrypted-native-diagnostics-amd64` or
`encrypted-native-diagnostics-arm64` for seven days. Each artifact contains
only the `.cms` ciphertext and a fixed metadata JSON file with source/run/
platform identity, certificate/ciphertext hashes and record count. Encryption
failure has no plaintext fallback. An installation failure that produced no
native report records that absence explicitly; it never becomes client proof.

Download the artifact into `.cache/` and verify its GitHub run, commit,
architecture, metadata hashes and recipient certificate before decrypting:

```sh
python3 scripts/ci_native_diagnostics.py \
  --decrypt .cache/native-diagnostic-download/ci-native-diagnostics.cms \
  --key .private/ci-diagnostics/recipient-20261102-key.pem \
  --output .private/ci-diagnostics/new-run.json
```

Decryption captures OpenSSL output privately and writes a new mode0600 file
only after successful decryption. Existing files and symlink parents cannot
be overwritten. Inspect the decoded base64 log bytes locally; retain only
reviewed, credential-free findings in public evidence. Delete no original
failure record when a repair passes.

The envelope protects confidentiality and detects modification of the GCM
ciphertext. It does not sign a report or prove a test result: anyone holding
the public certificate can encrypt a message. The actual GitHub run/source
and independently checked bytes remain the authority for qualification.
Protect the private key as retained local state. To rotate recipients, create
a new local private key and public certificate, test both directions with the
actual OpenSSL versions, commit only the public certificate, and retain old
keys while their diagnostic artifacts are needed.


The hosted Go workflow also seals failed command streams and registry output.
Each command writes a new private mode0600 log while it runs, bounded to8MiB
and120seconds. A timeout keeps its partial stream with unknown exit status;
normal expected Go denials require exit1. A later cleanup command cannot replace
the selected failure/last observation. Only exact generated run/candidate paths
are collected. NETRC, token and runtime/client configuration files are excluded.
Raw logs have no plaintext upload fallback. The owner-held recipient and all CMS
size/authentication limits remain unchanged. PostgreSQL-step/bootstrap failures
before a Go campaign report still require their separate job observations; a
missing private record is never reconstructed as an encrypted diagnostic pass.
