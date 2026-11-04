#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from bounded_client import run_owned_client
from sbt_fixture import TOOL_REPOSITORY,RESOLVER_MARKER,build_definition,checked_task,check_runtime_config,configure_runtime,copy_seed,invocation,meta_definition,require_resolver_observation,seed_manifest


class SbtFixture(unittest.TestCase):
    def test_version_specific_file_apis_and_uncached_copy_preserve_real_graph(self):
        one=build_definition('sbt1');two=build_definition('sbt2')
        for build in [one,two]:
            self.assertIn('Vector(("cratectl" at',build)
            self.assertIn('sys.props("cratectl.publication")',build)
            self.assertIn('sys.props("cratectl.repository")',build)
            self.assertIn('csrCacheDirectory := new java.io.File(sys.props("cratectl.cache"))',build)
            self.assertIn('autoScalaLibrary := false',build)
            self.assertIn('crossPaths := false',build)
            self.assertIn('Compile / unmanagedSourceDirectories := Nil',build)
            self.assertIn('Compile / dependencyClasspath',build)
            self.assertIn('Duplicate owned artifact filename',build)
            self.assertNotIn('publishLocal',build)
            self.assertNotIn('addSbtPlugin',build)
            self.assertNotIn('.run',build)
        self.assertNotIn('Def.uncached',one)
        self.assertNotIn('toVirtualFile',one)
        self.assertIn('verifyOwned := Def.uncached {',two)
        self.assertIn('converter.toPath(a.data).toFile',two)
        self.assertIn('fileConverter.value.toVirtualFile(',two)
        bootstrap=build_definition('sbt2',bootstrap=True)
        self.assertNotIn('credentials +=',bootstrap)
        self.assertNotIn('libraryDependencies',bootstrap)
        self.assertNotIn('verifyOwned',bootstrap)

    def test_ambient_jvm_server_and_repository_settings_do_not_replace_owned_launch(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-sbt-launch-') as temporary:
            root=Path(temporary);jdk=root/'jdk';(jdk/'bin').mkdir(parents=True)
            java=jdk/'bin/java';java.write_text('#!'+sys.executable+'\nimport json,os,sys\nprint(json.dumps({"argv":sys.argv[1:],"env":{k:v for k,v in os.environ.items() if k in ["JAVA_HOME","JAVA_TOOL_OPTIONS","SBT_OPTS","COURSIER_CACHE","COURSIER_REPOSITORIES","COURSIER_CREDENTIALS"]}}))\n');java.chmod(0o700)
            environment=dict(os.environ,JAVA_HOME='/foreign',JAVA_TOOL_OPTIONS='-javaagent:/foreign',SBT_OPTS='foreign',COURSIER_REPOSITORIES='foreign',COURSIER_CREDENTIALS='foreign',COURSIER_CACHE_SERVER='https://foreign',COURSIER_CHECKSUMS='none')
            argv,environment=invocation(jdk,root/'sbt-launch.jar',root,root/'cache',root/'repositories',environment,{'cratectl.artifact':'owned'},'show sbtVersion')
            code,output=run_owned_client(argv,root,environment)
            self.assertEqual(code,0);data=json.loads(output)
            self.assertEqual(data['env'],{'JAVA_HOME':str(jdk),'COURSIER_CACHE':str(root/'cache')})
            self.assertEqual(data['argv'][-3:],['-jar',str(root/'sbt-launch.jar'),'show sbtVersion;exit'])
            self.assertIn('-Dsbt.server.autostart=false',data['argv'])
            self.assertIn('-Dsbt.override.build.repos=false',data['argv'])
            self.assertIn('-Dsbt.ivy.home='+str(root/'cache/ivy-home'),data['argv'])
            self.assertIn('-Dcoursier.maven-settings=false',data['argv'])
            self.assertIn('-Dscala-cli.config='+str(root/'config/scala-cli.json'),data['argv'])
            self.assertIn('-Dcoursier.parallel-download-count=4',data['argv'])
            self.assertIn('-Dsbt.coursier.home='+str(root/'cache'),data['argv'])
            self.assertNotIn('COURSIER_CACHE_SERVER',environment)
            self.assertNotIn('COURSIER_CHECKSUMS',environment)

    def test_build_compiler_and_package_resolution_are_separate_even_on_denial(self):
        for series in ['sbt1','sbt2']:
            meta=meta_definition(series)
            self.assertIn(TOOL_REPOSITORY,meta)
            self.assertIn('credentials := Nil',meta)
            self.assertNotIn('cratectl.credentials',meta)
            self.assertNotIn('cratectl.repository',meta)
            build=build_definition(series)
            self.assertNotIn(TOOL_REPOSITORY,build)
            effective='Def.uncached(externalResolvers.value)' if series=='sbt2' else 'externalResolvers.value'
            self.assertIn('csrResolvers := '+effective,build)
            self.assertIn('csrResolvers := '+effective,meta)
            self.assertIn('includePluginResolvers := false',build)
            self.assertIn('owned(configured) && owned(effective)',build)
            self.assertIn('rs.size == 1',build)
            self.assertIn('case _ => false',build)
            root=Path('/owned')
            args,_=invocation(root/'jdk',root/'launcher',root,root/'cache',root/'repositories',{}, {},checked_task('publish'),series)
            if series=='sbt1':self.assertEqual(args[-3:],['verifyResolvers','publish','exit'])
            else:self.assertEqual(args[-1],'verifyResolvers;publish;exit')
        require_resolver_observation('[info] loading project\n'+RESOLVER_MARKER+'\n[error] forbidden')
        for output in ['[error] compilation failed','[error] Error downloading Scala\n403','[info] '+RESOLVER_MARKER,'prefix'+RESOLVER_MARKER]:
            with self.assertRaises(ValueError):require_resolver_observation(output)

    def test_seed_rejects_preseeded_fixture_symlinks_and_limits(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-sbt-seed-') as temporary:
            root=Path(temporary);source=root/'source';source.mkdir();(source/'official.jar').write_bytes(b'owned-tool-standin')
            digest=seed_manifest(source);self.assertEqual(digest['files'],1);self.assertEqual(digest['bytes'],18)
            target=root/'fresh';copy_seed(source,target,digest)
            self.assertEqual(seed_manifest(target),digest)
            self.assertNotEqual((target/'official.jar').stat().st_ino,(source/'official.jar').stat().st_ino)
            (target/'official.jar').write_bytes(b'changed');self.assertEqual(seed_manifest(source),digest)
            with self.assertRaises(FileExistsError):copy_seed(source,target,digest)
            with patch('sbt_fixture.MAX_SEED_BYTES',1),self.assertRaises(ValueError):seed_manifest(source)
            with patch('sbt_fixture.MAX_SEED_FILES',0),self.assertRaises(ValueError):seed_manifest(source)
            fixture=source/'dev.cratectl.sbtproof';fixture.mkdir()
            with self.assertRaises(ValueError):seed_manifest(source)
            fixture.rmdir();link=source/'escape';link.symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):seed_manifest(source)
            link.unlink();(source/'official.jar').write_bytes(b'mutated')
            with self.assertRaises(ValueError):copy_seed(source,root/'other',digest)

    def test_each_cli_series_uses_its_documented_command_sequence(self):
        root=Path('/owned')
        args=(root/'jdk',root/'launcher',root,root/'cache',root/'repositories',{}, {},'packageBin;makePom;show sbtVersion')
        one,_=invocation(*args,series='sbt1');two,_=invocation(*args,series='sbt2')
        self.assertEqual(one[-6:],['-jar',root/'launcher','packageBin','makePom','show sbtVersion','exit'])
        self.assertEqual(two[-3:],['-jar',root/'launcher','packageBin;makePom;show sbtVersion;exit'])
        with self.assertRaises(ValueError):invocation(*args,series='unknown')

    def test_private_mirror_configuration_is_empty_immutable_and_not_replaced(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-sbt-config-') as temporary:
            root=Path(temporary);configure_runtime(root);check_runtime_config(root)
            self.assertEqual((root/'config').stat().st_mode&0o777,0o700)
            with self.assertRaises(FileExistsError):configure_runtime(root)
            path=root/'config/scala-cli.json';self.assertEqual(path.stat().st_mode&0o777,0o600)
            path.write_text('{"repositories.mirrors":["foreign"]}')
            with self.assertRaises(ValueError):check_runtime_config(root)
            path.unlink();path.symlink_to(root/'config/mirror.properties')
            with self.assertRaises(ValueError):check_runtime_config(root)


if __name__=='__main__':unittest.main()
