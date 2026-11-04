# Ant and Ivy client qualification

The Ant/Ivy profile is implemented but has no native compatibility result yet.
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
