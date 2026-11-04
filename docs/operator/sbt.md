# SBT client qualification

SBT 1.13.0 and 2.0.11 each pass on both native Linux architectures at
`d4056d9`: 161 checks, all seven release-profile stages and twelve exact
publisher/reference/HTTP identities. The [SBT checkpoint](../../evidence/2026-11-04/sbt-d4056d9-checkpoint.json)
retains actual client/bootstrap/source identities and both original failures.
An Ivy or Gradle pass does not qualify either SBT version. The [JVM plan](../qualification/jvm-client-plan.json)
and [runtime pins](../qualification/jvm-clients.json) retain exact versions,
official distribution digests and unfinished work.

For an ordinary Maven-style repository, configure one explicit package read
source, a publication destination and a private credential file:

```scala
externalResolvers := Vector("cratectl" at "https://registry.example/r/releases/")
csrResolvers := externalResolvers.value
includePluginResolvers := false
publishTo := Some("cratectl" at "https://registry.example/r/releases/")
credentials += Credentials(Path.userHome / ".sbt" / "cratectl.credentials")
```

This example uses the SBT 1.x task syntax. In SBT 2, wrap the right-hand sides
of both resolver tasks with `Def.uncached(...)`. Keep SBT's launcher and owned
`project/plugins.sbt` build compiler on explicit tool repositories, with no
registry credentials. Do not set a global repository override to the package
endpoint: the build compiler needs its own Scala libraries before these root
settings load. The CI journey checks both resolver tasks against the exact
package URL before every package command, including expected failures.

The credential properties use `realm=cratectl`, the registry's exact `host`,
`user=token` and a scoped token as `password`. Restrict that file to its owner.
A writer needs the repository's explicit write grant; a reader must be unable
to publish. A group repository can be the read source while `publishTo` names
the intended hosted member. The isolated CI fixture permits HTTP only on its
owned loopback endpoint.

The qualification separates official SBT/tool bootstrap from project packages.
Tool-only cache inventories are bounded and must not contain fixture
coordinates. Each project command receives fresh copied cache bytes, its own
Ivy cache, one explicit cratectl resolver and private credentials. Empty private mirror configurations and disabled
Maven settings prevent inherited mirror substitution. No Maven
Central, local package or preseeded fixture may substitute for an observed
registry resolution. Exact pinned Java invokes the launcher JAR directly;
shell/thin-client wrappers and inherited JVM/repository injection are excluded.

The follow-up run loads the root project and verifies its resolvers, then exposes
another tool boundary: `autoScalaLibrary=false` still permits automatic Scala
compiler/doc/repl modules in the package graph. The owned resource-only package
fixture now uses `managedScalaInstance := false`, SBT's Java-only mode, and checks
that effective dependencies equal the declared owned modules. The separately
bootstrapped build compiler keeps its normal settings. Native packaging and
publication tasks remain required; all four repaired native release profiles now pass.

A Scala source project needs its approved compiler/library dependencies through
the configured governed source, such as a proxy/group. The Java-only resource
fixture does not qualify a compiled Scala application or supply its toolchain.

Stock SBT publishes owned resource-only JARs and generated POMs. Fresh
consumers copy resolved bytes for independent comparison; uploaded classes,
package scripts and models never execute. All twelve producer, retained-path
and HTTP identities must match. Seven stages require actual client identity,
scoped publication, two releases and a dependency, review denial, tenant
collisions, fresh reader publication denial without partial references,
proxy/group/range, current cached policy, registry restart and writer/reader
revocation. Each SBT series and architecture must pass independently.

SBT 2 uses virtual file references and cached tasks. Its owned fixture converts
through the file converter and marks the proof-copy task uncached; SBT 1 uses
its File API. Their command sequences remain separate. These version-specific fixture rules are bound to the exact native checkpoint.
The initial release proof does not qualify every SBT workflow.

Run `python3 scripts/conformance.py sbt1 --require-clean-build` or `sbt2` only
in an owned isolated environment with explicit database configuration and exact
candidate binaries. Native jobs have a five-minute cold tool bootstrap,
two-minute project commands and a 60-minute job budget. Only reviewed counts,
stages and hashes are public. Unexpected failures may retain bounded owner-only
encrypted diagnostics; raw credentials and reports stay private.

The initial release profile does not complete SBT or JVM parity. Snapshots,
classifiers, parent POMs/BOMs, richer configurations/conflicts, interruptions,
upstream outages, lifecycle, migration, scale, production TLS/private trust and
independent hosts/platforms remain required.

Official contracts: [publication and credentials](https://www.scala-sbt.org/2.x/docs/en/reference/sbt-publish.html),
[dependency/resolver behavior](https://www.scala-sbt.org/2.x/docs/en/reference/sbt-update.html),
[1.x command sequences](https://www.scala-sbt.org/1.x/docs/Running.html), and
[2.x API/command migration](https://www.scala-sbt.org/2.x/docs/en/changes/migrating-from-sbt-1.x.html).
