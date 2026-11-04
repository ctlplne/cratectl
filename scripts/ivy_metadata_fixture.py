# SPDX-License-Identifier: BUSL-1.1
"""Owned inert Maven metadata graph for native Ivy qualification, never code."""
import xml.etree.ElementTree as XML

GROUP = 'dev.cratectl.ivyproof'
MAVEN = 'http://ant.apache.org/ivy/maven'
XML.register_namespace('m', MAVEN)

# The publisher descriptor deliberately has no dependencies: it describes the
# exact prepared upload, not a fake successful client resolution of its POM.
# Consumers subsequently interpret the real parent/management/scope graph.
MODULES = {
    'parent': ('ivy-parent', '1.0.0', ('pom',)),
    'choice_1': ('ivy-choice', '1.0.0', ('jar', 'pom')),
    'choice_2': ('ivy-choice', '2.0.0', ('jar', 'pom')),
    'bridge_1': ('ivy-bridge-one', '1.0.0', ('jar', 'pom')),
    'bridge_2': ('ivy-bridge-two', '1.0.0', ('jar', 'pom')),
    'optional_dependency': ('ivy-optional', '1.0.0', ('jar', 'pom')),
    'test_dependency': ('ivy-test', '1.0.0', ('jar', 'pom')),
    'metadata_app': ('ivy-metadata-app', '1.0.0', ('jar', 'pom', 'tests_jar')),
}


def xml(root):
    return XML.tostring(root, encoding='utf-8', xml_declaration=True)


def filename(artifact, version, representation):
    return artifact + '-' + version + ('-tests.jar' if representation == 'tests_jar' else '.' + representation)


def publisher_descriptor(artifact, version, representations):
    root = XML.Element('ivy-module', version='2.0')
    XML.SubElement(root, 'info', organisation=GROUP, module=artifact, revision=version, status='release')
    XML.SubElement(XML.SubElement(root, 'configurations'), 'conf', name='default', visibility='public')
    publications = XML.SubElement(root, 'publications')
    for representation in representations:
        ext = 'jar' if representation == 'tests_jar' else representation
        attributes = {'name':artifact, 'type':ext, 'ext':ext, 'conf':'default'}
        if representation == 'tests_jar': attributes['{' + MAVEN + '}classifier'] = 'tests'
        XML.SubElement(publications, 'artifact', attributes)
    return xml(root)


def pom(label):
    artifact, version, _ = MODULES[label]
    root = XML.Element('project', xmlns='http://maven.apache.org/POM/4.0.0')
    def element(parent, name, text):
        XML.SubElement(parent, name).text = text
    def dependency(parent, artifact, version=None, scope=None, optional=False, exclude=None):
        node = XML.SubElement(parent, 'dependency')
        element(node, 'groupId', GROUP); element(node, 'artifactId', artifact)
        if version is not None: element(node, 'version', version)
        if scope: element(node, 'scope', scope)
        if optional: element(node, 'optional', 'true')
        if exclude:
            exclusion = XML.SubElement(XML.SubElement(node, 'exclusions'), 'exclusion')
            element(exclusion, 'groupId', GROUP); element(exclusion, 'artifactId', exclude)
    element(root, 'modelVersion', '4.0.0')
    if label == 'metadata_app':
        parent = XML.SubElement(root, 'parent')
        element(parent, 'groupId', GROUP); element(parent, 'artifactId', 'ivy-parent'); element(parent, 'version', '1.0.0')
        element(parent, 'relativePath', '')
    element(root, 'groupId', GROUP); element(root, 'artifactId', artifact); element(root, 'version', version)
    element(root, 'packaging', 'pom' if label == 'parent' else 'jar')
    if label == 'parent':
        element(XML.SubElement(root, 'properties'), 'owned.dependency.version', '1.0.0')
        managed = XML.SubElement(XML.SubElement(root, 'dependencyManagement'), 'dependencies')
        dependency(managed, 'ivy-dep', '${owned.dependency.version}')
    elif label.startswith('bridge_'):
        dependency(XML.SubElement(root, 'dependencies'), 'ivy-choice', '1.0.0' if label == 'bridge_1' else '2.0.0')
    elif label == 'metadata_app':
        dependencies = XML.SubElement(root, 'dependencies')
        dependency(dependencies, 'ivy-dep')  # Requires the actual remote parent.
        dependency(dependencies, 'ivy-bridge-two', '1.0.0', exclude='ivy-choice')
        dependency(dependencies, 'ivy-optional', '1.0.0', optional=True)
        dependency(dependencies, 'ivy-test', '1.0.0', scope='test')
    return xml(root)


def consumer_descriptor(dependencies, mapping='default->default', classifier=False, exclude=False):
    root = XML.fromstring(publisher_descriptor('metadata-consumer', '1.0.0', ()))
    root.remove(root.find('publications'))
    nodes = XML.SubElement(root, 'dependencies')
    for artifact, version in dependencies:
        node = XML.SubElement(nodes, 'dependency', org=GROUP, name=artifact, rev=version, conf=mapping)
        if classifier:
            XML.SubElement(node, 'artifact', {'name':artifact, 'type':'jar', 'ext':'jar', '{' + MAVEN + '}classifier':'tests'})
        if exclude and artifact == 'ivy-bridge-two':
            XML.SubElement(node, 'exclude', org=GROUP, module='ivy-choice')
    XML.SubElement(nodes, 'conflict', org=GROUP, module='ivy-choice', manager='latest-revision')
    return xml(root)
