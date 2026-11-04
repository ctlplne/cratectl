#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""The owned build must keep read/write credentials scoped and packages inert."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as XML

from conformance_ivy import descriptor, GROUP

ROOT = Path(__file__).resolve().parents[1]


class IvyFixture(unittest.TestCase):
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
        settings = XML.parse(ROOT/'scripts/fixtures/ivy-client/ivysettings.xml').getroot()
        self.assertEqual(settings.find('credentials').get('passwd'),'${registry.password}')
        self.assertEqual(settings.find('resolvers/ibiblio').get('root'),'${repositoryURL}')
        self.assertTrue(settings.find('resolvers/url/artifact').get('pattern').startswith('${publicationURL}'))
        self.assertEqual(len(settings.findall('resolvers/ibiblio')),1)


if __name__ == '__main__':unittest.main()
