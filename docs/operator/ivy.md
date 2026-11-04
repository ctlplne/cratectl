# Ant and Ivy client qualification

The initial release profile passes on both native Linux architectures at
`708214f`: 228 checks, all seven original stages, twelve exact JAR/POM
publisher/reference/HTTP identities and all three SHA-2 consumers. The
[named JVM checkpoint](../../evidence/2026-11-04/jvm-708214f-checkpoint.json)
retains exact source, tool and fixture identities. Original Ant-selection and
checksum-spelling failures remain retained. Broader Ivy/JVM compatibility is
unfinished. The owner resumed execution on2026-11-04. The previous
[halt record](../../evidence/2026-11-04/owner-halt-708214f.json) remains historical.
It targets Apache Ant 1.10.18, Ivy 2.6.0 and the pinned Java 21 runtime on
actual Linux x86 and ARM GitHub runners, using real PostgreSQL and the common
Maven repository endpoint. The [JVM plan](../qualification/jvm-client-plan.json)
retains exact distribution checksums and the unfinished client requirements.

Ivy uses different resolvers for reading and publishing. `ibiblio` with
`m2compatible="true"` reads ordinary Maven POMs and their dependencies. It does
not publish. A URL resolver publishes artifacts using HTTP PUT; an Ant build
can generate a POM with `ivy:makepom` and publish the JAR/POM pair with
`ivy:publish publishivy="false"`. The latter setting avoids uploading an Ivy
descriptor as though it were a Maven POM. A POM conversion must preserve the
dependency meaning required by the application; not every Ivy configuration
has a direct Maven equivalent.

Use the normal HTTPS endpoint `https://REGISTRY/r/REPOSITORY/`, the JVM's trust
configuration and credentials bound to the registry hostname and `cratectl`
realm. Keep a writer credential separate from the reader credential. Supply
credentials through private settings or a secret provider, without putting
them in command arguments, source files or build logs. Restricted repositories
also require an actor grant; a reader role cannot gain write authority through
a grant. Review-required repositories need current exact-digest decisions for
both the POM and package bytes.

The owned native test fixture contains only resources in its published JARs.
Its build XML runs bundled Ant/Ivy tasks; it never loads package code. Fresh
consumers must use one configured cratectl source and isolated artifact and
resolution caches. The profile requires six publications with twelve exact
publisher/reference/HTTP byte bindings, two tenant identities, review denial,
two versions, transitive dependencies, restricted writers/readers, checksum
proxying, group resolution and a version range. It then requires current
cached-content denial, an actual registry restart and credential revocation.
Native client failure and a same-credential HTTP denial are checked together;
an error log is not assumed to expose an HTTP status number.

Run `python3 scripts/conformance.py ivy --require-clean-build` only in an owned
isolated qualification environment with explicit database configuration and
matching candidate binaries. The dedicated GitHub jobs install hash-verified
official Ant/Ivy distributions, then export only reviewed stage codes, counts
and identity digests. Missing representations or partial stages cannot yield
a passing summary. Local Python checks qualify configuration and evidence
contracts only.

Snapshots, classifiers, parent POMs, richer configurations, exclusions and
conflicts, production TLS/private trust, interruptions, lifecycle, migration,
scale and other clients/platforms remain required. The initial release profile
does not establish complete Maven or JVM compatibility.

Official contracts: [Maven-compatible consumption](https://ant.apache.org/ivy/history/2.6.0/resolver/ibiblio.html),
[HTTP publication](https://ant.apache.org/ivy/history/2.6.0/resolver/url.html),
[POM conversion](https://ant.apache.org/ivy/history/2.6.0/use/makepom.html),
[publication task](https://ant.apache.org/ivy/history/2.6.0/use/publish.html)
and [credential scope](https://ant.apache.org/ivy/history/2.6.0/settings/credentials.html).


The qualification launcher uses the explicit pinned Java executable and Ant
bootstrap JAR, with an explicit Ant home, no user library and no inherited
classpath. It removes Java/Ant options that could replace the runtime or inject
classes. The downloaded Ant shell can select libraries through system
configuration or an inherited Ant home; a hash of a downloaded JAR alone does
not prove which library that shell loaded. Safe evidence binds the bootstrap
hash and the actual observed Ant version. A separate read-only legacy version
observation diagnoses the old path without treating a host-provided version
as the qualified client. The same exact pinned version assertion remains
mandatory, alongside every original release-profile case.


On a failed native job, the bounded command observation and owned registry log
can be sealed to the existing owner-held diagnostic recipient. Only CMS
ciphertext and fixed metadata are uploaded, with seven-day retention; no
credential/config file or plaintext fallback is included. Decryption and
inspection stay in private local state. Safe public summaries still contain
only the reviewed counts, stages, versions and hashes. This keeps detailed
client errors available without publishing raw runner logs.


The fixture now uses Ivy's documented `SHA-256` name. Its exact `.SHA-256`,
`.SHA-384` and `.SHA-512` URLs must return checksums of the authorized parent
JAR/POM; all three remain denied before review and after reader revocation.
Fresh native consumers separately select each stronger algorithm and compare
the complete exact transitive JAR set. Safe evidence requires the three client
observations in order, in addition to the original seven stages and twelve
publisher/reference/HTTP identities. SHA-1/MD5 compatibility checks remain;
no checksum or original client case is removed to obtain a pass.


The next `maven-metadata-v2` profile is implemented but awaits native replay.
It retains all original release cases, then publishes an owned parent POM with
a property-backed managed dependency, two conflicting versions and bridges,
optional/test dependencies and a separate classified resource-only JAR. All28
representations need publisher, retained-reference and independent HTTP digests.
Fresh consumers must obtain the real parent; an unassessed parent must fail.
A denied classified JAR must fail while default-artifact consumption still
works. Explicit optional/test configurations must return exact additional sets.
Maven and Ivy exclusion controls must differ from their nonexcluded controls;
latest-revision conflict resolution must return only the selected version.
Cached-parent policy, registry restart and reader revocation remain mandatory.
The initial release pass does not qualify these new cases.

Fixture design follows Apache's [Maven publication contract](https://cwiki.apache.org/confluence/spaces/ANT/pages/115528605/Publishing%2BMaven%2BArtifacts%2BWith%2BAnt%2BAnd%2BIvy),
[artifact selection](https://ant.apache.org/ivy/history/2.6.0/ivyfile/dependency-artifact.html)
and [conflict managers](https://ant.apache.org/ivy/history/2.6.0/ivyfile/conflict.html).
Only the owned build files execute; resolved packages remain inert.
