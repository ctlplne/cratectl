#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""The owned build must keep read/write credentials scoped and packages inert."""
from pathlib import Path
import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as XML

from conformance_ivy import ant_invocation, descriptor, GROUP, changing_settings, cached_snapshot_bytes
from ivy_metadata_fixture import MODULES, MAVEN, consumer_descriptor, filename, pom, publisher_descriptor
from ci.ivy_evidence import METADATA_REPRESENTATIONS
from bounded_client import run_owned_client

ROOT = Path(__file__).resolve().parents[1]


class IvyFixture(unittest.TestCase):
    def test_changing_consumer_retains_one_source_and_never_clears_its_cache(self):
        data=(ROOT/'scripts/fixtures/ivy-client/ivysettings.xml').read_bytes()
        original=XML.fromstring(data);changed=XML.fromstring(changing_settings(data))
        reader=changed.find('resolvers/ibiblio')
        for name,value in {'checkmodified':'true','changingPattern':'.*-SNAPSHOT','changingMatcher':'regexp'}.items():
            self.assertEqual(reader.attrib.pop(name),value)
        self.assertEqual(XML.tostring(changed),XML.tostring(original))
        with self.assertRaises(ValueError):changing_settings(b'<ivysettings><resolvers/></ivysettings>')
        module=XML.fromstring(descriptor('consumer','1.0.0',('ivy-app','1.1-SNAPSHOT'),publish=False,changing=True))
        self.assertEqual(module.find('dependencies/dependency').get('changing'),'true')
        module=XML.fromstring(descriptor('ivy-app','1.1-SNAPSHOT',('ivy-dep','1.0.0'),description='snapshot_first'))
        self.assertEqual(module.find('info/description').text,'snapshot_first')
        ns={'ivy':'antlib:org.apache.ivy.ant'}
        build=XML.parse(ROOT/'scripts/fixtures/ivy-client/build.xml').getroot()
        target=build.find("target[@name='consume-changing']")
        self.assertEqual(target.find('ivy:resolve',ns).get('refresh'),'true')
        self.assertEqual(target.find('ivy:retrieve',ns).get('overwriteMode'),'always')
        self.assertFalse({n.tag.split('}')[-1]for n in target.iter()} & {'delete','cleancache','exec','java','script'})

    def test_actual_cache_reader_observes_original_bytes_and_rejects_links_or_unbounded_files(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-ivy-cache-',dir=ROOT/'.cache') as temporary:
            cache=Path(temporary)/'cache';cache.mkdir()
            paths={'app_jar':'ivy-app/jars/ivy-app-1.1-SNAPSHOT.jar','app_pom':'ivy-app/ivy-1.1-SNAPSHOT.xml.original',
                   'dependency_jar':'ivy-dep/jars/ivy-dep-1.0.0.jar','dependency_pom':'ivy-dep/ivy-1.0.0.xml.original'}
            expected={k:('owned first '+k).encode()for k in paths}
            for name,relative in paths.items():
                path=cache/GROUP/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(expected[name])
            self.assertEqual(cached_snapshot_bytes(cache),expected)
            for name in ['app_jar','app_pom']:
                expected[name]=('owned updated '+name).encode();(cache/GROUP/paths[name]).write_bytes(expected[name])
            self.assertEqual(cached_snapshot_bytes(cache),expected)
            target=cache/GROUP/paths['app_pom'];target.write_bytes(b'x'*((1<<20)+1))
            with self.assertRaises(ValueError):cached_snapshot_bytes(cache)
            target.unlink();target.mkdir()
            with self.assertRaises(ValueError):cached_snapshot_bytes(cache)
            target.rmdir();outside=Path(temporary)/'outside';outside.write_bytes(b'private stand-in')
            target.symlink_to(outside)
            with self.assertRaises(ValueError):cached_snapshot_bytes(cache)
            target.unlink();target.write_bytes(expected['app_pom'])
            module=cache/GROUP/'ivy-app';module.rename(cache/GROUP/'saved-module');module.symlink_to(cache/GROUP/'saved-module',target_is_directory=True)
            with self.assertRaises(ValueError):cached_snapshot_bytes(cache)
            self.assertEqual(outside.read_bytes(),b'private stand-in')

    def test_conflicting_host_environment_cannot_replace_owned_ant_or_java(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-ant-launcher-',dir=ROOT/'.cache') as temporary:
            directory=Path(temporary);jdk=directory/'jdk';(jdk/'bin').mkdir(parents=True)
            java=jdk/'bin/java'
            java.write_text('#!'+sys.executable+'\nimport json,os,sys\nprint(json.dumps({"argv":sys.argv[1:],"environment":{k:v for k,v in os.environ.items() if k in ["ANT_HOME","JAVA_HOME","CLASSPATH","JAVA_TOOL_OPTIONS","ANT_ARGS","JAVACMD"]}}))\n')
            java.chmod(0o700)
            ant=directory/'owned-ant';ivy=directory/'owned-ivy.jar'
            poisoned=dict(os.environ,ANT_HOME='/foreign/ant',JAVA_HOME='/foreign/jdk',JAVACMD='/foreign/java',
                          CLASSPATH='/foreign/classes',CLASSPATH_OVERRIDE='true',ANT_ARGS='-lib /foreign/plugins',
                          ANT_OPTS='-javaagent:/foreign/agent',JAVA_TOOL_OPTIONS='-javaagent:/foreign/agent',
                          JDK_JAVA_OPTIONS='-javaagent:/foreign/agent',_JAVA_OPTIONS='-javaagent:/foreign/agent')
            argv,environment=ant_invocation(ant,ivy,jdk,poisoned)
            code,output=run_owned_client(argv+['-version'],directory,environment)
            self.assertEqual(code,0)
            observed=json.loads(output)
            self.assertEqual(observed['environment'],{'ANT_HOME':str(ant),'JAVA_HOME':str(jdk)})
            self.assertEqual(observed['argv'],['-Xmx512m','-XX:MaxMetaspaceSize=384m','-XX:ActiveProcessorCount=2',
                             '-Dant.home='+str(ant),'-classpath',str(ant/'lib/ant-launcher.jar'),
                             'org.apache.tools.ant.launch.Launcher','-nouserlib','-noclasspath','-lib',str(ivy),'-noinput','-version'])

    def test_published_descriptor_preserves_exact_transitive_coordinates(self):
        root = XML.fromstring(descriptor('ivy-app','2.0.0',('ivy-dep','1.0.0')))
        self.assertEqual(root.find('info').attrib,{'organisation':GROUP,'module':'ivy-app','revision':'2.0.0','status':'release'})
        self.assertEqual([a.attrib for a in root.findall('publications/artifact')],
                         [{'name':'ivy-app','type':ext,'ext':ext,'conf':'default'} for ext in ['jar','pom']])
        self.assertEqual(root.find('dependencies/dependency').attrib,{'org':GROUP,'name':'ivy-dep','rev':'1.0.0','conf':'default->default'})
        root = XML.fromstring(descriptor('consumer','1.0.0',('ivy-app','[1.0,4.0)'),publish=False))
        self.assertIsNone(root.find('publications'))
        self.assertEqual(root.find('dependencies/dependency').get('rev'),'[1.0,4.0)')

    def test_build_uses_separate_maven_read_and_write_paths_without_package_execution(self):
        root = XML.parse(ROOT/'scripts/fixtures/ivy-client/build.xml').getroot()
        tasks = {n.tag.split('}')[-1] for n in root.iter()}
        self.assertFalse(tasks & {'exec','java','javac','script','taskdef','get','import','subant','ant'})
        ns = {'ivy':'antlib:org.apache.ivy.ant'}
        publish = root.find('.//ivy:publish',ns)
        self.assertEqual(publish.get('publishivy'),'false')
        self.assertEqual(publish.get('haltonmissing'),'true')
        self.assertEqual(root.find('.//ivy:makepom',ns).get('artifactPackaging'),'jar')
        self.assertEqual(root.find("target[@name='publish']").get('depends'),'prepare')
        prepare=root.find("target[@name='prepare']")
        self.assertIsNotNone(prepare.find('ivy:resolve',ns))
        self.assertIsNotNone(prepare.find('ivy:makepom',ns))
        self.assertIsNone(prepare.find('ivy:publish',ns))
        self.assertEqual(root.find("property[@name='checksumAlgorithms']").get('value'),'SHA-256,sha1,md5')
        settings = XML.parse(ROOT/'scripts/fixtures/ivy-client/ivysettings.xml').getroot()
        self.assertEqual(settings.find('credentials').get('passwd'),'${registry.password}')
        self.assertEqual(settings.find('resolvers/ibiblio').get('root'),'${repositoryURL}')
        for resolver in settings.find('resolvers'):
            self.assertEqual(resolver.get('checksums'),'${checksumAlgorithms}')
        self.assertTrue(settings.find('resolvers/url/artifact').get('pattern').startswith('${publicationURL}'))
        self.assertEqual(len(settings.findall('resolvers/ibiblio')),1)
        self.assertEqual(settings.find('resolvers/url/artifact').get('pattern'),
                         '${publicationURL}[organisation]/[module]/[revision]/[artifact]-[revision](-[classifier]).[ext]')
        prepared = root.find("target[@name='publish-prepared']")
        self.assertIsNotNone(prepared.find('ivy:resolve',ns))
        self.assertEqual(prepared.find('ivy:publish',ns).get('artifactspattern'),'build/[artifact]-[revision](-[classifier]).[ext]')
        self.assertIsNone(prepared.find('ivy:makepom',ns))

    def test_real_parent_is_required_for_managed_version_and_child_exclusion_is_explicit(self):
        ns={'p':'http://maven.apache.org/POM/4.0.0'}
        parent=XML.fromstring(pom('parent'));child=XML.fromstring(pom('metadata_app'))
        self.assertEqual(parent.find('p:packaging',ns).text,'pom')
        self.assertEqual(parent.find('p:properties/p:owned.dependency.version',ns).text,'1.0.0')
        self.assertEqual(parent.find('p:dependencyManagement/p:dependencies/p:dependency/p:version',ns).text,'${owned.dependency.version}')
        self.assertEqual(child.find('p:parent/p:artifactId',ns).text,'ivy-parent')
        self.assertIsNone(child.find('p:parent/p:relativePath',ns).text)
        deps={d.find('p:artifactId',ns).text:d for d in child.findall('p:dependencies/p:dependency',ns)}
        self.assertIsNone(deps['ivy-dep'].find('p:version',ns))
        self.assertEqual(deps['ivy-bridge-two'].find('p:exclusions/p:exclusion/p:artifactId',ns).text,'ivy-choice')
        self.assertEqual(deps['ivy-optional'].find('p:optional',ns).text,'true')
        self.assertEqual(deps['ivy-test'].find('p:scope',ns).text,'test')
        for label,version in [('bridge_1','1.0.0'),('bridge_2','2.0.0')]:
            self.assertEqual(XML.fromstring(pom(label)).find('p:dependencies/p:dependency/p:version',ns).text,version)

    def test_classified_bytes_and_mandatory_graph_are_not_collapsed_to_default_artifact(self):
        self.assertEqual({name:v[2] for name,v in MODULES.items()},METADATA_REPRESENTATIONS)
        self.assertEqual(sum(len(v[2]) for v in MODULES.values()),16)
        root=XML.fromstring(publisher_descriptor(*MODULES['metadata_app']))
        self.assertIsNone(root.find('dependencies'))
        self.assertEqual([a.get('{'+MAVEN+'}classifier') for a in root.findall('publications/artifact')],[None,None,'tests'])
        self.assertEqual(filename('ivy-metadata-app','1.0.0','tests_jar'),'ivy-metadata-app-1.0.0-tests.jar')
        consumer=XML.fromstring(consumer_descriptor([('ivy-metadata-app','1.0.0')],classifier=True))
        self.assertEqual(consumer.find('dependencies/dependency/artifact').get('{'+MAVEN+'}classifier'),'tests')
        consumer=XML.fromstring(consumer_descriptor([('ivy-bridge-one','1.0.0'),('ivy-bridge-two','1.0.0')],exclude=True))
        self.assertEqual(consumer.find("dependencies/dependency[@name='ivy-bridge-two']/exclude").get('module'),'ivy-choice')
        self.assertIsNone(consumer.find("dependencies/dependency[@name='ivy-bridge-one']/exclude"))
        self.assertEqual(consumer.find('dependencies/conflict').get('manager'),'latest-revision')
        consumer=XML.fromstring(consumer_descriptor([('ivy-metadata-app','1.0.0')],mapping='default->default,optional'))
        self.assertEqual(consumer.find('dependencies/dependency').get('conf'),'default->default,optional')


if __name__ == '__main__':unittest.main()
