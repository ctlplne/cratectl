# 0058: Select several original events from one verified journal pass

Date: 2026-11-07. State: implemented; local development checks pass, native
qualification pending.

Complete artifact bundles need several original publication/export events, not
repeated scans of a potentially large journal. Add a bounded selection operation
to the existing complete-range verifier. It retains at most256distinct requested
events and at most64MiB of original selected payload bytes. The caller chooses a
smaller budget; the CLI defaults to4MiB. Existing input/page/time limits remain.
Reject duplicate, out-of-range or excessive selectors before reading input.

Return selected original events only after every page, link, exact terminal
anchor and EOF verify. A later corrupt/truncated/trailing record or read error
returns neither partial selections nor a success receipt. Preserve caller order.
Keep the existing one-event API compatible by delegating to this operation.
The generic crypto operation still needs independently authenticated anchors.

`journal-verify --select-event SEQUENCE` may repeat this flag. Selection through
the CLI additionally requires the complete external checkpoint/signature and an
independently selected public key. Its output includes sequence, original event
hash/link, payload byte length and payload SHA256, never original payload text.
It does not supply latest-history, package approval, closure or delivery trust.
An adjacent public key or a self-declared checkpoint is not its own authority.

Test full-range and late-failure behavior, ordering, exact count/byte bounds,
duplicates, outside selections, read/context failures, input mutation and
compatibility of the original selector. Fuzz the new selection boundary. Use
public signed fixtures for local CLI units; require actual external OpenSSL,
candidate CLI and real source journal in the native Go workflow. Local units
and bounded fuzz are distinct from actual native and stock-client qualification.

This supports the full dependency/authority/permission/provenance export work;
it does not itself implement a multi-artifact bundle or dependency closure.
All450capabilities/41families/later GOAL4.1 scope and current readiness gates
remain. No schema, primary, credentials, signer service or customer change.
