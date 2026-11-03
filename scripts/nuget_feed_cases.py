# SPDX-License-Identifier: BUSL-1.1
"""Deterministic owned metadata for actual SDK-versus-HTTP observations.

Packages contain only a Nuspec and an inert text file. These declarations never
install, resolve or run packages. Range preference remains distinct from bounds.
"""
import base64
import io
import zipfile


def cases(extended=False):
    bodies = [
        ('none', ''), ('empty', '<dependencies/>'),
        ('legacy', '<dependencies><dependency id="Owned.A" version="[1,2)"/><dependency id="Owned.Any"/><dependency id="Owned.Empty" version=""/></dependencies>'),
        ('group-precedence', '<dependencies><dependency id="ignored/invalid" version="invalid"/><group targetFramework="net10.0"><dependency id="Owned.A" version="1.2*"/></group><group targetFramework="netstandard2.0"/></dependencies>'),
        ('empty-group-precedence', '<dependencies><dependency id="ignored/invalid" version="invalid"/><group/></dependencies>'),
        ('split-containers', '<dependencies><dependency id="Owned.A" version="1"/></dependencies><dependencies><dependency id="Owned.B" version="[2,3)"/></dependencies>'),
        ('duplicate-groups', '<dependencies><group targetFramework="net10.0"/><group targetFramework="net10.0"><dependency id="Owned.A" version="1.0+Owned"/></group></dependencies>'),
        ('duplicate-items', '<dependencies><group><dependency id="Owned.A" version="1"/><dependency id="owned.a" version="1.0.0"/><dependency id="Owned.A" version="2"/></group></dependencies>'),
        ('signed-zero-ties', '<dependencies><group><dependency id="Owned.A" version="1.0--0"/><dependency id="Owned.A" version="1.0-0"/></group></dependencies>'),
        ('case-sensitive-nodes', '<Dependencies><dependency id="ignored/invalid"/></Dependencies><dependencies><Group><dependency id="ignored/invalid"/></Group><dependency id="Owned.A" version="1"/></dependencies>'),
        ('foreign-nodes', '<dependencies xmlns="urn:foreign"><dependency id="ignored/invalid"/></dependencies><dependencies><x:dependency xmlns:x="urn:foreign" id="ignored/invalid"/><dependency id="Owned.A" version="1"/></dependencies>'),
        ('nested-nodes', '<dependencies><group><wrapper><dependency id="ignored/invalid"/></wrapper><dependency id="Owned.A" version="[1.0-rc.1+Owned,2.0+Upper)"/></group></dependencies>'),
        ('all-stable', '<dependencies><dependency id="Owned.A" version="*"/></dependencies>'),
        ('all-prerelease', '<dependencies><dependency id="Owned.A" version="*-*"/></dependencies>'),
        ('floating-major', '<dependencies><dependency id="Owned.A" version="1.*"/></dependencies>'),
        ('floating-legacy-floor', '<dependencies><dependency id="Owned.A" version="1.2*"/></dependencies>'),
        ('floating-prerelease', '<dependencies><dependency id="Owned.A" version="1.2.3-rc.*"/></dependencies>'),
        ('floating-combined', '<dependencies><dependency id="Owned.A" version="1.2.*-*"/></dependencies>'),
        ('license-acceptance', '<requireLicenseAcceptance>TrUe</requireLicenseAcceptance>'),
        ('license-whitespace', '<requireLicenseAcceptance> true </requireLicenseAcceptance>'),
        ('unicode-dependency', '<dependencies><group><dependency id="_Owned.Ünicode" version="[1.0--0,1.0-0]"/></group></dependencies>'),
    ]
    frameworks = ['net10.0', 'net8.0', 'netstandard2.0', '.NETStandard2.0', '.NETFramework4.7.2',
                  '.NETCoreApp3.1', 'portable-net45+win8+wp8', 'win8', 'wp8', 'uap10.0', 'monotouch',
                  'monoandroid10.0', 'tizen6.0', 'xamarinios10.0', 'net8.0-windows10.0.19041.0',
                  'net9.0-android35.0', 'any', 'agnostic', 'native', 'unsupported', ' ']
    for index, framework in enumerate(frameworks):
        bodies.append(('framework-' + str(index), '<dependencies><group targetFramework="' + framework + '"><dependency id="Owned.A" version="[1.0.0.1,2)"/></group></dependencies>'))
    output = []
    for index, (label, body) in enumerate(bodies):
        identity = 'Cratectl.Metadata.Case' + str(index)
        xml = ('<?xml version="1.0" encoding="utf-8"?><package><metadata><id>' + identity + '</id><version>1.0.0+Owned</version><authors>cratectl owned fixture</authors><description>Inert HTTP metadata comparison</description>' + body + '</metadata></package>').encode()
        output.append({'index': index, 'label': label, 'id': identity, 'nuspec': base64.b64encode(xml).decode('ascii'), 'omit_float_comparison': label == 'all-stable'})
    for encoding in ['utf-16le', 'utf-16be']:
        index = len(output)
        identity = 'Cratectl.Metadata.Case' + str(index)
        xml = '<?xml version="1.0" encoding="utf-16"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>' + identity + '</id><version>1.0.0+Owned</version><authors>cratectl owned fixture</authors><description>Inert original UTF16 bytes</description><dependencies><group targetFramework="net10.0"><dependency id="Owned.A" version="[1,2)"/></group></dependencies></metadata></package>'
        raw = (b'\xff\xfe' if encoding.endswith('le') else b'\xfe\xff') + xml.encode(encoding)
        output.append({'index': index, 'label': encoding, 'id': identity, 'nuspec': base64.b64encode(raw).decode('ascii'), 'omit_float_comparison': False})
    if extended:
        extra = [
            ('flags-order-case', 'Owned.A', 'owned.a', '1', '1.0.0', 'runtime,Build,runtime', 'BUILD,RUNTIME'),
            ('flags-empty-token', 'Owned.A', 'Owned.A', '1', '1', '', ' '),
            ('flags-supplementary', 'Owned.A', 'Owned.A', '1', '1', '\U00010d70', '\U00010d50'),
            ('id-micro-sign', 'Owned.µ', 'Owned.Μ', '1', '1', '', ''),
            ('id-kelvin-sign', 'Owned.K', 'Owned.K', '1', '1', '', ''),
            ('id-long-s', 'Owned.ſ', 'Owned.S', '1', '1', '', ''),
            ('id-dotless-i', 'Owned.ı', 'Owned.I', '1', '1', '', ''),
            ('id-ascii-i', 'Owned.I', 'owned.i', '1', '1', '', ''),
            ('range-build-metadata', 'Owned.A', 'Owned.A', '1.0+First', '1.0+Second', '', ''),
            ('range-floating-interval', 'Owned.A', 'Owned.A', '1.*', '[1.0.0, )', '', ''),
            ('flags-greek-sigma', 'Owned.A', 'Owned.A', '1', '1', 'Σ', 'ς'),
            ('flags-distinct', 'Owned.A', 'Owned.A', '1', '1', 'build', 'runtime'),
        ]
        for label, left, right, lo, hi, include_left, include_right in extra:
            index = len(output)
            identity = 'Cratectl.Metadata.Case' + str(index)
            body = '<dependencies><group><dependency id="' + left + '" version="' + lo + '" include="' + include_left + '"/><dependency id="' + right + '" version="' + hi + '" include="' + include_right + '"/></group></dependencies>'
            raw = ('<package><metadata><id>' + identity + '</id><version>1.0.0+Owned</version><authors>cratectl owned fixture</authors><description>Inert dependency set comparison</description>' + body + '</metadata></package>').encode()
            output.append({'index': index, 'label': label, 'id': identity, 'nuspec': base64.b64encode(raw).decode('ascii'), 'omit_float_comparison': False})
    return output


def archive(case):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=False) as package:
        for name, value in [(case['id'] + '.nuspec', base64.b64decode(case['nuspec'])), ('content/owned.txt', b'Owned inert metadata fixture; never executed.\n')]:
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            package.writestr(info, value)
    return out.getvalue()


def difference_paths(original, observed, prefix=''):
    """Describe owned observation differences without exporting their values."""
    if type(original) is not type(observed):
        return [prefix + '._type']
    if isinstance(original, dict):
        paths = []
        for key in sorted(set(original) | set(observed)):
            path = prefix + '.' + key if prefix else key
            if key not in original or key not in observed:
                paths.append(path + '._type')
            else:
                paths.extend(difference_paths(original[key], observed[key], path))
        return paths
    if isinstance(original, list):
        paths = [prefix + '._length'] if len(original) != len(observed) else []
        for index, (left, right) in enumerate(zip(original, observed)):
            paths.extend(difference_paths(left, right, prefix + '[' + str(index) + ']'))
        return paths
    return [prefix] if original != observed else []
