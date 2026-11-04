# Gradle client development and qualification

Gradle uses the ordinary Maven repository endpoint,
`https://REGISTRY/r/REPOSITORY/`. A JAR contains the package payload. Its POM
describes Maven dependencies; Gradle Module Metadata describes Gradle variants
and dependencies. Both metadata files and the exact JAR remain governed by the
common repository authorization, digest decisions and storage path.

The first Gradle 9.8.2/JDK 21 profile passes 123 checks on native Linux x86
at `7ea5ee7`. ARM stops during Java setup before any client journey. The
[exact checkpoint](../../evidence/2026-11-03/github-7ea5ee7-checkpoint.json) retains
that failure. The strengthened profile below awaits native replay. Use the
[Maven guide](maven.md) for the currently named Maven scope and limits.

Configure a normal Gradle Maven repository with a reader credential supplied by
your private secret provider:

```groovy
import org.gradle.authentication.http.BasicAuthentication

repositories {
    maven {
        url = uri('https://REGISTRY/r/REPOSITORY/')
        credentials {
            username = 'token'
            password = providers.environmentVariable('CRATECTL_READER_TOKEN').get()
        }
        authentication { basic(BasicAuthentication) }
    }
}
```

Trust the operator's CA using the JVM's normal trust configuration. Publishing
uses Gradle's bundled `maven-publish` plugin and an independently scoped writer
credential. Restricted repositories need a matching actor grant; a reader role
cannot acquire write authority through a grant. Review-required repositories
need exact-digest decisions for the metadata and payload required by consumers.

The new native GitHub lane publishes owned resource-only JARs with a real
nonadministrator writer, POMs and Gradle Module Metadata. Fresh consumers use
only the configured cratectl endpoint. They must resolve the exact transitive
set through module metadata, Maven-only metadata, proxy/group repositories and
version ranges. Separate cases cover review, a colliding tenant, denied cached
content, real registry restart, two snapshot publications and writer/reader
credential revocation. A fresh cache proves current service behavior; downloaded
copies remain outside the server's control.

Run `python3 scripts/conformance.py gradle --require-clean-build` only in an
owned isolated qualification environment with the explicit database profile and
matching candidate binaries. GitHub installs the hash-pinned Gradle distribution
and pinned JDK on actual Linux x86 and ARM runners. The existing `all` profile
retains its baseline-format campaign; alternative Docker/Podman and Gradle
clients have separate mandatory lanes and separate evidence. No absent lane is
counted as passing. Unknown profiles and flags fail before database access.

Client commands have a two-minute deadline, an 8 MiB private output limit, two
Gradle workers and an owned process group that is stopped on completion or
failure. A timeout leaves a publication outcome unconfirmed. Raw client output,
credentials and private paths stay on the disposable runner. Safe summaries
contain reviewed stage codes, exact source/tool hashes and all 24 owned
JAR/POM/module digests. The `publication-wire-v2` profile separately binds each
publisher file to the retained path, digest and size, then compares raw HTTP
bytes. Snapshot metadata must use the same timestamp/build as its JAR; a
second snapshot must preserve the first timestamped publication. Tenant B uses
its own inventory and credentials. Partial stages or missing readbacks cannot
produce a passing summary. The original x86 result predates these checks.

Ivy and SBT, other Gradle/JDK/platform versions, richer variant/plugin/build
graphs, production TLS, interruptions, every lifecycle/migration/scale case and
full format/readiness requirements remain open.

Primary references reviewed 2026-11-03: [Gradle repository authentication](https://docs.gradle.org/current/userguide/supported_repository_protocols.html),
[dependency verification](https://docs.gradle.org/current/userguide/dependency_verification.html)
and [distribution checksum](https://services.gradle.org/distributions/gradle-9.8.2-bin.zip.sha256).
