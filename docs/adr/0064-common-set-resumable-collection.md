# 0064: Collect every common-set member before completion

Date: 2026-11-07. State: implemented; actual native qualification pending.

Build on ADR0063's single durable common selection. The CLI verifies the complete
journal under an independently chosen external signer/head before reading client
configuration or contacting the source. Fetch the exact current-generation common
manifest and bind its original creation event, set identity and canonical object.
Capture and reverify the original statement/signature/key; bind the complete
journal and every original ZIP/mod/info identity before creating output.

Use a new owner-private flat collection directory. Its immutable binding covers
the source authority, exact set ID, journal attribution, five original proof
members and three representations per ordered root. Keep client tokens/config
outside that directory. Retain 8–773 members, with a 780-entry enumeration ceiling
including metadata/recovery names and 512 KiB metadata publication ceiling. The
single-version profile retains its original twelve-entry and 64 KiB limits.
Unknown members, competing pending receipts and a different immutable selection
refuse recovery. No package scripts, extraction, VCS fallback or model loading run.

Reuse the hardened owner-private regular-file checks, directory lock, bounded
streaming hashes, synced checkpoints and exact pending-prefix/two-name link
publication. Follow each range's exact size, digest, generation and Content-Range.
Retain uncertain private bytes after interruption; explicit renewal and --resume
select the next generation. Rehash retained files. Never automatically retry a
mutation, truncate corrupt bytes, overwrite a final binding or rewrite a previous
completion receipt. A renewed replay returns the original completion bytes.

Before completion, hash and inspect every selected ZIP/mod/info through the same
bounded native representation parser. Keep only three representation files open
at once. A missing or corrupt late member leaves no new success receipt or stdout.
One final current whole-set manifest HEAD checks every source grant/policy/epoch/
item identity; repeated whole-set checks for all 768 objects would add quadratic
SQL work. Check current parent identity/generation again, sync the directory and
publish the complete receipt using the existing durable link protocol.

The result states bytes_verified=true only after those package/proof checks.
Current admission, checksum authority, dependency closure and delivery remain
false. This is an exact collection of explicitly selected original roots, not an
automatically selected dependency closure or a current destination approval.
The flat directory is retained input for the complete private native file proxy
and current-policy import, both still required by the full export plan.

Bound network requests to 16,384, individual chunks to 64 KiB–8 MiB, combined
retained member bytes to a caller budget through 65 GiB, and HTTP/copy/inspection
time to one hour at most. The separate journal byte/time limits apply before
collection. Use larger chunks for a selection that would exceed the request cap.
The existing verified source-serving path still has its own deadline and current
authority checks. Large-volume throughput and resource tuning remain unqualified.

Local ARM build/unit/race/lint and tagged normal/race compilation/vet pass.
Five added meaningful unit functions cover maximum metadata without widening
legacy limits, prefix/link recovery and refusal, original-generation receipt
replay, actual inert archive/representation consistency and late corruption, and
missing independent proof before configuration/output. The existing CLI suite
passes under race with owned stand-ins. An initial unprivileged attempt could
not bind an existing loopback stand-in; the authorized replay passes unchanged.

Extend the existing native PG/CAS/TLS/CLI/OpenSSL collector journey with separate
common-set barriers: kill at its second range, retain an exact synced prefix,
explicitly renew/resume, verify all eleven original members, preserve the original
receipt after another renewal, deny a late root after the first was collected,
recover explicitly after current approval, and refuse a corrupt retained late
member without rewriting the previous receipt. The original single-export
barriers/assertions remain independent. These new controls are compiled, not run
locally. Both actual Linux architectures must pass normal/race and stock profiles.

Latest accepted source `1664c7c` qualifies only ADR0062's common metadata preview:
26 native jobs, 19 unchanged safe summaries, 72 reports, 277 PostgreSQL/99 named
Go functions normally/race on both Linux hosts, 60 fuzz targets on three hosts,
and the original clients/browser/upgrades/portability. New schema17/common-set/
collector code remains outside that result. The new combined runtime source
requires 283 PostgreSQL/105 named Go/61 fuzz and 16 historical native binaries/
21 upgrade reports per Linux host. Shared schema/evidence edits also select two
NuGet-library and three focused-browser jobs: inspect all actual selected runs.

Keep all fourteen export cases, seven environments, 450 capabilities, 41 families
and later GOAL4.1 scope. Full file proxy, dependency/authority/permission/provenance
closure, current destination scanner/import, console progress, safe physical GC,
providers/platforms/backup/HA/scale/soak and broad readiness remain incomplete.
The stopped primary stays schema 11 with `5483878b` qualified binaries and ten receipts.
