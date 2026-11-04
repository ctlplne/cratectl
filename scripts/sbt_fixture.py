# SPDX-License-Identifier: BUSL-1.1
"""Owned SBT build rules and tool-only cache isolation, never package code."""
import hashlib
import json
import os
from pathlib import Path
import shutil

GROUP = 'dev.cratectl.sbtproof'
MAX_SEED_FILES = 20000
MAX_SEED_BYTES = 768 << 20
CONFIG_FILES = {'scala-cli.json':b'{}\n','mirror.properties':b'','extra-mirrors.properties':b''}
TOOL_REPOSITORY = 'https://repo.maven.apache.org/maven2/'
RESOLVER_MARKER = 'CRATECTL_RESOLVERS_OK'


def meta_definition(series):
    """Only the owned build compiler may resolve official tool dependencies."""
    if series not in ('sbt1','sbt2'):raise ValueError('Unknown owned SBT series')
    resolvers='Vector("cratectl-tools" at "' + TOOL_REPOSITORY + '")'
    effective='externalResolvers.value'
    if series=='sbt2':
        resolvers='Def.uncached(' + resolvers + ')'
        effective='Def.uncached(' + effective + ')'
    return '\n'.join([
        '// SPDX-License-Identifier: BUSL-1.1',
        'externalResolvers := ' + resolvers,
        'csrResolvers := ' + effective,
        'includePluginResolvers := false',
        'credentials := Nil',
        'csrCacheDirectory := new java.io.File(sys.props("cratectl.cache"))',
    ]) + '\n'


def checked_task(task):
    return 'verifyResolvers;' + task


def require_resolver_observation(output):
    # Check this even for expected client failures: a compiler/resolver failure
    # before project loading must never qualify an authorization denial.
    if RESOLVER_MARKER not in output.splitlines():
        raise ValueError('Native SBT did not verify its sole package resolver')


def configure_runtime(root):
    config=Path(root)/'config';config.mkdir(mode=0o700)
    for name,body in CONFIG_FILES.items():
        path=config/name;path.write_bytes(body);path.chmod(0o600)


def check_runtime_config(root):
    config=Path(root)/'config'
    if config.is_symlink() or not config.is_dir():
        raise ValueError('Owned SBT resolver configuration changed')
    for name,body in CONFIG_FILES.items():
        path=config/name
        if path.is_symlink() or not path.is_file() or path.stat().st_size!=len(body) or path.read_bytes()!=body:
            raise ValueError('Owned SBT resolver configuration changed')


def build_definition(series, bootstrap=False):
    if series not in ('sbt1','sbt2'):
        raise ValueError('Unknown owned SBT series')
    virtual = series == 'sbt2'
    jar = 'new java.io.File(baseDirectory.value, "publication/" + name.value + "-" + version.value + ".jar")'
    pom = 'new java.io.File(baseDirectory.value, "publication/" + name.value + "-" + version.value + ".pom")'
    if virtual:
        jar = 'fileConverter.value.toVirtualFile((' + jar + ').toPath)'
        pom = 'fileConverter.value.toVirtualFile((' + pom + ').toPath)'
    repository = '("cratectl" at sys.props("cratectl.repository")).withAllowInsecureProtocol(true)'
    resolvers = 'Vector(' + repository + ')'
    effective = 'externalResolvers.value'
    if virtual:
        resolvers = 'Def.uncached(' + resolvers + ')'
        effective = 'Def.uncached(' + effective + ')'
    lines = [
        '// SPDX-License-Identifier: BUSL-1.1',
        '// Owned qualification rules. No resolved class or package script runs.',
        'organization := sys.props("cratectl.group")',
        'name := sys.props("cratectl.artifact")',
        'version := sys.props("cratectl.version")',
        'crossPaths := false',
        'autoScalaLibrary := false',
        'Compile / unmanagedSourceDirectories := Nil',
        'Test / unmanagedSourceDirectories := Nil',
        'Compile / unmanagedResourceDirectories := Seq(new java.io.File(baseDirectory.value, "resources"))',
        'Compile / packageSrc / publishArtifact := false',
        'Compile / packageDoc / publishArtifact := false',
        'publishMavenStyle := true',
        'publishTo := Some(("cratectl-publisher" at sys.props("cratectl.publication")).withAllowInsecureProtocol(true))',
        'externalResolvers := ' + resolvers,
        'csrResolvers := ' + effective,
        'includePluginResolvers := false',
        'csrCacheDirectory := new java.io.File(sys.props("cratectl.cache"))',
        'Compile / packageBin / artifactPath := ' + jar,
        'makePom / artifactPath := ' + pom,
    ]
    if not bootstrap:
        lines += [
            'val verifyResolvers = taskKey[Unit]("Require the sole owned package source before every journey command")',
            'verifyResolvers := ' + ('Def.uncached {' if virtual else '{'),
            '  val expected = sys.props("cratectl.repository").stripSuffix("/")',
            '  val configured = externalResolvers.value',
            '  val effective = csrResolvers.value',
            '  def owned(rs: Seq[sbt.librarymanagement.Resolver]): Boolean = rs.size == 1 && rs.forall {',
            '    case r: sbt.librarymanagement.MavenRepository => r.root.stripSuffix("/") == expected',
            '    case _ => false',
            '  }',
            '  require(owned(configured) && owned(effective), "Unexpected package resolver")',
            '  println("' + RESOLVER_MARKER + '")',
            '}',
            'credentials += Credentials(new java.io.File(sys.props("cratectl.credentials")))',
            'libraryDependencies ++= sys.props.get("cratectl.dependencyVersion").filter(_.nonEmpty).map { v =>',
            '  sys.props("cratectl.group") % sys.props("cratectl.dependencyArtifact") % v',
            '}.toVector',
            'val verifyOwned = taskKey[Unit]("Copy only resolved inert bytes for independent verification")',
            'verifyOwned := ' + ('Def.uncached {' if virtual else '{'),
        ]
        if virtual:
            lines += ['  val converter = fileConverter.value',
                      '  val files = (Compile / dependencyClasspath).value.map(a => converter.toPath(a.data).toFile)']
        else:
            lines += ['  val files = (Compile / dependencyClasspath).value.map(_.data)']
        lines += [
            '  require(files.size <= 16, "Owned dependency set exceeds its budget")',
            '  val proof = new java.io.File(baseDirectory.value, "proof")',
            '  IO.createDirectory(proof)',
            '  files.foreach { input =>',
            '    require(input.isFile && input.getName.endsWith(".jar") && input.length <= 1048576, "Unexpected owned dependency representation")',
            '    val output = new java.io.File(proof, input.getName)',
            '    require(!output.exists, "Duplicate owned artifact filename")',
            '    IO.copyFile(input, output)',
            '  }',
            '}',
        ]
    return '\n'.join(lines) + '\n'


def invocation(jdk, launcher, root, cache, repositories, environment, properties, task, series='sbt2'):
    """Use the pinned Java/JAR directly, with no ambient server/plugin injection."""
    if series not in ('sbt1','sbt2'):raise ValueError('Unknown owned SBT command series')
    clean = {k:v for k,v in environment.items() if not k.startswith('COURSIER_') and k not in {
        'JAVA_OPTS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','JAVACMD',
        'CLASSPATH','CLASSPATH_OVERRIDE','SBT_OPTS','SBT_CREDENTIALS',
        'COURSIER_CREDENTIALS','COURSIER_REPOSITORIES','SBT_BOOT_DIRECTORY',
        'COURSIER_CONFIG_DIR','COURSIER_MIRRORS','COURSIER_EXTRA_MIRRORS','COURSIER_MAVEN_SETTINGS',
        'SCALA_CLI_CONFIG','CS_MAVEN_HOME'}}
    config=root/'config'
    clean.update(JAVA_HOME=str(jdk), COURSIER_CACHE=str(cache),
                 COURSIER_CONFIG_DIR=str(config),SCALA_CLI_CONFIG=str(config/'scala-cli.json'),
                 COURSIER_MIRRORS=str(config/'mirror.properties'),COURSIER_EXTRA_MIRRORS=str(config/'extra-mirrors.properties'),
                 COURSIER_MAVEN_SETTINGS='false')
    argv = [jdk/'bin/java','-Xmx768m','-XX:MaxMetaspaceSize=384m','-XX:ActiveProcessorCount=2',
            '-Dsbt.server.autostart=false','-Dsbt.server.forcestart=false','-Dsbt.supershell=false',
            '-Dsbt.color=false','-Dsbt.log.noformat=true','-Dsbt.ci=true','-Dsbt.task.cpus=2',
            '-Dsbt.global.base='+str(root/'global'),'-Dsbt.boot.directory='+str(root/'boot'),
            '-Dsbt.coursier.home='+str(cache),
            '-Dsbt.ivy.home='+str(cache/'ivy-home'),'-Dsbt.override.build.repos=false',
            '-Dsbt.repository.config='+str(repositories),'-Dcoursier.maven-settings=false',
            '-Dcoursier.parallel-download-count=4',
            '-Dcoursier.config-dir='+str(config),'-Dscala-cli.config='+str(config/'scala-cli.json'),
            '-Dcoursier.mirrors='+str(config/'mirror.properties'),'-Dcoursier.mirrors.extra='+str(config/'extra-mirrors.properties')]
    argv += ['-D'+key+'='+str(value) for key,value in sorted(properties.items())]
    commands=task.split(';')+['exit'] if series=='sbt1' else [task+';exit']
    return argv + ['-jar',launcher,*commands], clean


def seed_manifest(root):
    """Freeze a bounded regular-file tool cache with no project fixture coords."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Bootstrap cache must be an owned regular directory')
    rows = []; total = 0; entries = 0
    for folder, directories, files in os.walk(root,followlinks=False):
        directories.sort(); files.sort()
        for name in directories + files:
            path = Path(folder)/name; relative = path.relative_to(root).as_posix(); entries += 1
            if entries>50000 or len(relative)>2048 or path.is_symlink() or 'sbtproof' in relative.lower() or any(c in relative for c in '\r\n\x00'):
                raise ValueError('Bootstrap cache contains unsafe paths or project coordinates')
        for name in files:
            path = Path(folder)/name
            if not path.is_file(): raise ValueError('Bootstrap cache contains a nonregular entry')
            before = path.stat(); total += before.st_size
            if len(rows)>=MAX_SEED_FILES or total>MAX_SEED_BYTES or before.st_size>128<<20:
                raise ValueError('Bootstrap cache exceeds its file/byte budget')
            with path.open('rb') as source: digest = hashlib.file_digest(source,'sha256').hexdigest()
            after = path.stat()
            if (before.st_size,before.st_mtime_ns,before.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino):
                raise ValueError('Bootstrap cache changed during inspection')
            rows.append((path.relative_to(root).as_posix(),before.st_size,digest))
    encoded=json.dumps(sorted(rows),separators=(',',':')).encode()
    return {'files':len(rows),'bytes':total,'sha256':hashlib.sha256(encoded).hexdigest()}


def copy_seed(source, destination, expected):
    if seed_manifest(source)!=expected:
        raise ValueError('Tool seed changed before project cache creation')
    shutil.copytree(source,destination,symlinks=False)
    if seed_manifest(destination)!=expected:
        raise ValueError('Fresh project cache differs from its tool-only seed')
