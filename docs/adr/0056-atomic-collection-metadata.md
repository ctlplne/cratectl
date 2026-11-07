# 0056: Publish collection metadata only after complete durable writes

Date: 2026-11-07. State: implemented; native qualification pending.

DEFECT0132 is an owned filesystem unit failure at812bd58. A disposable child
with a128-byte kernel file limit returns a binding-write error but leaves128bytes
under the final `bindings.json` name. Its parent limit is unchanged. This directly
reproduces the binding writer; the original receipt writer has the same pattern
by source inspection, not by an independent original receipt fault campaign.
Retain the first failure and distinguish it from real collector/socket evidence.

Bindings now stage under `.bindings.pending`. Completion stages under
`receipt.GENERATION.pending`, recording the original completion intent even if
serving is later renewed. Validate and sync the complete canonical JSON before
an exclusive hard link publishes its final name. Sync that directory before
removing the pending alias, then sync again. No final filename is replaced.
Payload/proof files never precede a complete immutable binding.

Explicit resume may append only an exact pending JSON prefix. It revalidates all
collected bytes and current server access before finishing a pending completion.
A pending generation must be canonical, positive and no newer than the current
serving generation. After renewal, it preserves the original completion's
generation and bytes. A completed record never becomes an editable checkpoint.
Corrupt prefixes, corrupt completed metadata, multiple pending completions,
future generations, unbound payloads and unrelated links fail intact.

A crash after publication can leave two names for one inode. Recovery allows
exactly that final/pending pair, both owner-private, regular, same inode and
exactly two links. Verify the complete expected bytes before removing the owned
pending alias. Any third link or unrelated alias refuses recovery. Normal package
and proof members still require one link. Bound metadata to64KiB and the directory
to12members; a completed bundle still has its original ten members. Require atomic
local hard-link publication, directory sync and the existing OS lock. Unsupported
filesystems fail explicitly; no replace/rename fallback weakens the contract.

Local regressions use child kernel file limits for both binding and receipt writes,
plus declared partial-prefix/post-link states, renewal, corrupt/future/multiple
intent and unrelated-hardlink cases. They execute no registry, signer or SDK.
The existing native socket/process-kill test additionally resumes a declared
partial completion after another real server renewal and recovers both metadata
link pairs. This supplements its actual collector kill; it is not a real power-loss,
arbitrary filesystem/provider, registry death or broad storage-fault campaign.

All original signed bindings, eight data/proof members, current authorization,
false destination/checksum/closure/remote-ack fields and scope remain. No schema,
primary, credential, signer custody or customer change. Native274PG/96Go normal/
race,56fuzz/19main151browser and every existing selected profile still require
exact-source GitHub acceptance. Windows and full closure/import/GC/backup/scale
and all450capabilities/41families/later GOAL4.1 scope remain required.
