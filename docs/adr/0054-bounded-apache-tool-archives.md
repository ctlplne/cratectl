# 0054: Bound and cache the pinned Ant/Ivy tool archives

Date: 2026-11-07. State: implemented; native replay pending.

DEFECT0131 stops the source470ca74 ARM Ant/Ivy installer before any stock Ivy
journey runs. Its only host times out after 268,903 ms. The original job log
cannot identify which of its two sequential archive requests failed. Preserve
the failed job, empty summary, skipped client stage and diagnostic artifact
identities; a later passing repository or client job does not erase that result.

Reuse the existing bounded public-archive fetcher for exactly Ivy 2.6.0 and
Ant 1.10.18. Keep their original SHA-512 pins, archive names, 64-MiB per-archive
ceiling and extracted tool paths. Existing ORAS/Helm/Gitleaks SHA-256 contracts
remain unchanged. Apache archive selection is an explicit SHA-512-only allowlist,
not a general download URL or implicit dependency-version update.

Each request disables curl configuration, permits HTTPS redirects only (at most
five), limits connection setup to 15 seconds and transfer time to 180 seconds,
and runs under the existing 195-second process/output bound and independent
kernel file-size limit. A bounded transport/HTTP failure may fetch the same
archive from its exact official Apache archive path. Completed digest mismatch,
corrupt cache, local write/size/output failure, unsafe path and invalid inputs
fail immediately without another source or overwriting retained cache bytes.
Only a fully verified, synced regular file is published into the cache.

The [official Ivy archive directory](https://archive.apache.org/dist/ant/ivy/2.6.0/)
lists the original binary archive and its SHA-512 file. The [official Ant archive
checksum](https://archive.apache.org/dist/ant/binaries/apache-ant-1.10.18-bin.tar.gz.sha512)
matches the existing repository pin. The tool will still verify actual bytes
against the unchanged pins; directory metadata is not native download proof.
No package/tool download or execution is needed on the development machine.

The two existing native Ivy jobs cache only the two public compressed archives.
Use the existing immutable cache action, OS/architecture plus installer/fetcher/
pin-source identity, no restore prefix, five-minute cache-step budget and
two-minute segment bound. Verify every restored archive again, then retain the
original SHA-512 check, extraction and all original stock-client cases. Never
cache credentials, extracted tools, consumer caches, databases or diagnostics.
A successful cache step is not a passed Ivy journey. Cache saving depends on
job success; cold/save and later exact-key restore need actual GitHub evidence.

Sixteen local fetch tests retain the eleven original cases and add SHA-512
verification/cache revalidation, bounded primary failure with exact fallback,
completed mismatch/corrupt-cache refusal, source/version/algorithm rejection
and a real child kernel limit without fallback. These use owned inert curl
stand-ins and execute no Ant/Ivy tool or package payload. Full ARM lint and
workflow/shell syntax are development gates. Native Ant/Ivy archive fetch,
cache action and original client journey remain unverified on the new source
until both actual GitHub architectures run. No source16 migration, product
permission, client assertion, primary, sibling or release behavior changes.
