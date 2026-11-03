#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Compare Go ID, version identity/precedence, Nuspec and archive contracts with SDK libraries.

This is a native library contract test, not package-feed or stock-client proof.
The owned C# fixture has no package references and clears package sources.
No downloaded package, project, package script, application or model executes.
"""
import datetime
import base64
import hashlib
import itertools
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def version_cases():
    cores = ['0', '1', '1.0', '1.00.01', '1.0.0.0', '1.0.0.1', '2147483647', '2147483648', '1.2.3.4.5', '1.', '1..0', '1 . 2 . 3', '１.0', '-1', '', 'v1.0']
    releases = ['', '-alpha', '-Alpha.1', '-0', '-00', '-0a', '-a-b', '-1.01', '-α', '-']
    metadata = ['', '+build', '+build.00', '+bad+bad', '+', '+b-c', '+a_b']
    values = [core + release + build for core, release, build in itertools.product(cores, releases, metadata)]
    values += ['\t1.0\r\n', '\u00851.0\u0085', '1.0\x00', '[1.0,2.0)', '1.*', '1 2', '1. \n 2', '1-9999999999999999999999', '1+0000']
    return list(dict.fromkeys(values))


def nuspec_cases():
    template = '<package{namespace}><metadata><id>{identity}</id><version>{version}</version><authors>Owned fixture</authors><description>Opaque metadata only</description><dependencies><group targetFramework="net10.0"><dependency id="Cratectl.Dependency" version="[1.0,2.0)" /></group></dependencies></metadata></package>'
    plain = template.format(namespace='', identity='Cratectl.Foundation', version='1')
    namespaced = template.format(namespace=' xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"', identity='Cratectl.Foundation', version='01.02.3.0-Alpha.1+owned')
    declaration = '<?xml version="1.0" encoding="utf-16"?>' + namespaced
    values = [plain.encode(), namespaced.encode(), b'\xef\xbb\xbf' + namespaced.encode(),
              b'\xff\xfe' + declaration.encode('utf-16le'), b'\xfe\xff' + declaration.encode('utf-16be'),
              declaration.encode('utf-16le'), declaration.encode('utf-16be'),
              template.format(namespace='', identity='_Cratectl.Ünicode', version='0-0a').encode(),
              template.format(namespace='', identity='Cratectl.&#x45;xample', version='1.0').encode(),
              template.format(namespace='', identity='<![CDATA[Cratectl.CData]]>', version='<![CDATA[1.0]]>').encode(),
              template.format(namespace='', identity='  Cratectl.Trimmed  ', version=' 1.00.0 ').encode()]
    return [base64.b64encode(value).decode('ascii') for value in values]


def archive_cases():
    values = []
    documents = nuspec_cases()
    for compression in [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED]:
        for index in [0, 3]:
            output = io.BytesIO()
            manifest = 'Cratectl.Manifest.nuspec' if compression == zipfile.ZIP_STORED else 'Declared.NUSPEC'
            with zipfile.ZipFile(output, 'w', compression=compression) as archive:
                files = [(manifest, base64.b64decode(documents[index])),
                         ('[Content_Types].xml', b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="nuspec" ContentType="application/octet" /></Types>'),
                         ('_rels/.rels', ('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/' + manifest + '" Id="owned" /></Relationships>').encode()),
                         ('lib/net10.0/_._', b''),
                         ('content/\u00fc.txt', b'owned opaque UTF8 path payload\n')]
                for name, body in files:
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type = compression
                    info.external_attr = 0o100600 << 16
                    archive.writestr(info, body)
            values.append(base64.b64encode(output.getvalue()).decode('ascii'))
    return values


def id_cases():
    # Cover every non-surrogate BMP scalar inside the legacy word grammar,
    # plus whole-coordinate limits, transport guards and supplementary cases.
    values = ['Cratectl.' + chr(code) + '.Case' for code in range(0x10000) if not 0xd800 <= code <= 0xdfff]
    values += ['', '_', 'Cratectl.Library', 'Cratectl.İD', 'Cratectl.ID', 'Cratectl.ıD', 'Cratectl.É', 'Cratectl.E\u0301',
               'Cratectl\n', 'Cratectl\r', 'Cratectl\x00', ' Cratectl', 'Cratectl ', 'Cratectl..Other', '.Cratectl', 'Cratectl-', 'Cratectl/Other', 'Cratectl%2eOther',
               'A' * 100, 'A' * 101, 'Ü' * 100, 'Ü' * 101, '𐐀' * 50, '𐐀' * 51,
               'Cratectl.𐐀', 'Cratectl.𐐨', 'Cratectl.𞤀', 'Cratectl.𞤢']
    return list(dict.fromkeys(values))


def comparison_cases():
    values = ['0', '0.0.0', '1', '01.00.0', '1.0.0.0', '1.0.0.1', '1.0.0.2', '2', '9', '10',
              '2147483647', '2147483647.2147483647.2147483647.2147483647']
    values += ['1.0.0-' + label for label in ['0', '1', '2', '10', '2147483647', '2147483648', '10000000000',
               '-1', '-0', '-00', '-01', '-2147483648', '-2147483649', '-', 'alpha', 'ALPHA', 'alpha.0',
               'alpha.1', 'alpha.2', 'alpha.10', 'alpha10', 'alpha2', 'rc.2', 'rc.10', 'rc.2147483648',
               'rc.10000000000', 'a-b', 'a.0.b', 'a.' + '1' * 128, 'a' * 970]]
    values += ['1.0.0+owned', '1.0.0+OTHER', '1.0.0-ALPHA+owned', '1 . 0 . 0', '', 'v1', '2147483648',
               '1.2.3.4.5', '1.0.0-01', '1.0.0-alpha..1', '1.0.0-a_1', '1.0.0+', '1.0.0-a+meta.7']
    return [json.dumps(pair, separators=(',', ':')) for pair in itertools.product(values, repeat=2)]


def main():
    os.chdir(ROOT)
    os.umask(0o077)
    run = uuid.uuid4().hex[:10]
    work = ROOT / '.cache/nuget-version-contract' / run
    logs = ROOT / '.private/nuget-version-contract' / run
    work.mkdir(parents=True)
    logs.mkdir(parents=True, mode=0o700)
    candidate = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all']).strip())
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    report = {'candidate': candidate, 'run_id': os.environ.get('GITHUB_RUN_ID'), 'status': 'failed', 'phase': 'preflight', 'source_dirty': dirty, 'checks': [], 'limits': ['Native transport-profile ID/flat-key, version-key/precedence, Nuspec identity and owned ZIP archive identity/manifest-byte contracts only. ID reference acceptance and transport-profile exclusions are reported separately. An ordering tie is not permission to merge coordinate identities. No durable publication, full package/signature, ZIP64/split/exotic archive, feed, dependency-resolution, publish/consume, tenant, policy, symbol, Chocolatey/PowerShell or release-readiness qualification.']}
    environment = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_NOLOGO='1', DOTNET_GENERATE_ASPNET_CERTIFICATE='false', DOTNET_CLI_HOME=str(work / 'dotnet-home'), NUGET_PACKAGES=str(work / 'packages'), MSBuildEnableWorkloadResolver='false', GOTOOLCHAIN='local', GOCACHE=str(ROOT / '.cache/go-build'), GOMODCACHE=str(ROOT / '.cache/go-mod'))
    number = 0

    def command(arguments, label, data=None):
        nonlocal number
        number += 1
        completed = subprocess.run([str(v) for v in arguments], input=data, cwd=ROOT, env=environment, capture_output=True, timeout=180)
        (logs / (str(number) + '.log')).write_bytes(completed.stdout + completed.stderr)
        if completed.returncode or len(completed.stdout) + len(completed.stderr) > 8 << 20:
            codes = sorted(set(re.findall(rb'\b(?:CS[0-9]{4}|NETSDK[0-9]{4}|NU[0-9]{4}|MSB[0-9]{4})\b', completed.stdout + completed.stderr)))[:10]
            if codes:
                print('Reference fixture error codes: ' + ','.join(v.decode('ascii') for v in codes), flush=True)
            raise ValueError(label)
        return completed.stdout

    def check(label, condition):
        if not condition:
            raise ValueError(label)
        report['checks'].append(label)
        print('PASS: ' + label, flush=True)

    try:
        check('clean exact source on native GitHub Linux', not dirty and platform.system() == 'Linux' and arch in ('amd64', 'arm64') and os.environ.get('GITHUB_SHA') == candidate)
        dotnet = shutil.which('dotnet')
        check('actual dotnet SDK is installed', dotnet is not None)
        sdk = command([dotnet, '--version'], 'dotnet SDK version observation').decode().strip()
        check('dotnet SDK version has a bounded public identity', re.fullmatch(r'[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,5}(?:-[A-Za-z0-9.-]{1,60})?', sdk) is not None)
        report.update(sdk_version=sdk, runner_os='Linux', runner_arch=arch)
        fixture = ROOT / 'scripts/fixtures/nuget-versions'
        report['phase'] = 'build'
        properties = ['-p:TargetFramework=net' + sdk.split('.')[0] + '.0', '-p:BaseIntermediateOutputPath=' + str(work / 'obj') + '/', '-p:NuGetAudit=false']
        command([dotnet, 'restore', fixture / 'Oracle.csproj', '--configfile', fixture / 'NuGet.Config', *properties], 'resolve installed SDK references with all remote package sources cleared')
        command([dotnet, 'build', fixture / 'Oracle.csproj', '--no-restore', '--configuration', 'Release', '--output', work / 'managed', *properties], 'build owned reference fixture without remote package sources')
        go = ROOT / '.cache/go/bin/go'
        executable = go if go.exists() else 'go'
        command([executable, 'build', '-trimpath', '-o', work / 'go-oracle', './scripts/fixtures/nuget-versions'], 'build exact native Go version fixture')
        cases = version_cases()
        inputs = json.dumps(cases).encode()
        report['phase'] = 'compare'
        native = json.loads(command([work / 'go-oracle'], 'run owned native Go contract', inputs))
        reference = json.loads(command([dotnet, work / 'managed/Oracle.dll'], 'run actual SDK NuGet.Versioning contract', inputs))
        check('both reference processes use the actual native Linux architecture', native['os'] == reference['os'] == 'linux' and native['architecture'] == arch and reference['architecture'] == {'amd64': 'x64', 'arm64': 'arm64'}[arch])
        check('Go contract embeds this clean source', native['build'] == {'vcs.revision': candidate, 'vcs.modified': 'false'})
        report['go_build_identity'] = native['build']
        check('reference library has a bounded public version', re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}', reference['version']) is not None)
        check('both libraries produced one result per synthetic case', len(native['rows']) == len(reference['rows']) == len(cases))
        report.update(cases=len(cases), fixture_sha256=hashlib.sha256(inputs).hexdigest(), nuget_library_version=reference['version'], library_sha256=hashlib.sha256((work / 'managed/NuGet.Versioning.dll').read_bytes()).hexdigest(), go_oracle_sha256=hashlib.sha256((work / 'go-oracle').read_bytes()).hexdigest())
        mismatches = [index for index, (actual, expected) in enumerate(zip(native['rows'], reference['rows'])) if actual != expected]
        report['mismatch_indexes'] = mismatches
        (logs / 'comparison.json').write_text(json.dumps({'inputs': cases, 'go': native, 'reference': reference}, indent=2))
        check('all synthetic version identities agree with actual NuGet.Versioning', not mismatches)
        report['phase'] = 'nuspec_compare'
        documents = nuspec_cases()
        encoded = json.dumps(documents).encode()
        actual = json.loads(command([work / 'go-oracle', '--nuspec'], 'read owned Nuspec fixtures with Go', encoded))
        expected = json.loads(command([dotnet, work / 'managed/Oracle.dll', 'nuspec'], 'read owned Nuspec fixtures with actual NuGet.Packaging', encoded))
        check('Nuspec reference processes use this clean native source', actual['os'] == expected['os'] == 'linux' and actual['architecture'] == arch and expected['architecture'] == {'amd64': 'x64', 'arm64': 'arm64'}[arch] and actual['build'] == native['build'])
        check('Nuspec reference library and case count are observed', re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){3}', expected['version']) is not None and len(actual['rows']) == len(expected['rows']) == len(documents))
        report.update(nuspec_cases=len(documents), nuspec_fixture_sha256=hashlib.sha256(encoded).hexdigest(), packaging_library_version=expected['version'], packaging_library_sha256=hashlib.sha256((work / 'managed/NuGet.Packaging.dll').read_bytes()).hexdigest())
        errors = [index for index, (a, b) in enumerate(zip(actual['rows'], expected['rows'])) if a != b or not a['valid']]
        report['nuspec_mismatch_indexes'] = errors
        # These are owned synthetic inputs, not user data. Retain bounded
        # mismatches so a failed reference comparison remains diagnosable.
        report['nuspec_mismatches'] = [{'index': index, 'go': actual['rows'][index], 'reference': expected['rows'][index]} for index in errors[:16]]
        check('all owned Nuspec identities agree with actual SDK reader', not errors)
        report['phase'] = 'archive_compare'
        packages = archive_cases()
        encoded = json.dumps(packages).encode()
        actual = json.loads(command([work / 'go-oracle', '--archive'], 'inspect owned package archives with Go', encoded))
        expected = json.loads(command([dotnet, work / 'managed/Oracle.dll', 'archive'], 'read owned archives with actual NuGet.Packaging', encoded))
        check('archive reference processes use this clean native source', actual['os'] == expected['os'] == 'linux' and actual['architecture'] == arch and expected['architecture'] == {'amd64': 'x64', 'arm64': 'arm64'}[arch] and actual['build'] == native['build'])
        check('archive reference library and case count are observed', expected['version'] == report['packaging_library_version'] and len(actual['rows']) == len(expected['rows']) == len(packages))
        report.update(archive_cases=len(packages), archive_fixture_sha256=hashlib.sha256(encoded).hexdigest())
        errors = [index for index, (a, b) in enumerate(zip(actual['rows'], expected['rows'])) if a != b or not a['valid']]
        report['archive_mismatch_indexes'] = errors
        report['archive_mismatches'] = [{'index': index, 'go': actual['rows'][index], 'reference': expected['rows'][index]} for index in errors[:16]]
        check('all owned archive identities and exact Nuspec bytes agree with actual SDK reader', not errors)
        report['phase'] = 'id_compare'
        identifiers = id_cases()
        encoded = json.dumps(identifiers).encode()
        check('owned identifier corpus stays within the input and case budgets', len(encoded) <= 2 << 20 and len(identifiers) <= 65536)
        report.update(id_cases=len(identifiers), id_fixture_sha256=hashlib.sha256(encoded).hexdigest())
        actual = json.loads(command([work / 'go-oracle', '--id'], 'derive owned NuGet ID keys with Go', encoded))
        expected = json.loads(command([dotnet, work / 'managed/Oracle.dll', 'id'], 'validate IDs and derive invariant keys with actual SDK', encoded))
        check('ID reference processes use this clean native source', actual['os'] == expected['os'] == 'linux' and actual['architecture'] == arch and expected['architecture'] == {'amd64': 'x64', 'arm64': 'arm64'}[arch] and actual['build'] == native['build'])
        check('ID reference library and case count are observed', expected['version'] == report['packaging_library_version'] and len(actual['rows']) == len(expected['rows']) == len(identifiers))
        projected = [{'valid': row['valid'], 'key': row['key']} for row in expected['rows']]
        report.update(id_cases=len(identifiers), id_fixture_sha256=hashlib.sha256(encoded).hexdigest(), id_go_unicode_version=actual['go_unicode_version'], id_reference_runtime=expected['runtime'], id_reference_accepted=sum(row['reference_valid'] for row in expected['rows']), id_transport_rejected_reference_accepted_indexes=[index for index, row in enumerate(expected['rows']) if row['transport_rejected']])
        report['id_go_rows_sha256'] = hashlib.sha256(json.dumps(actual['rows'], sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        report['id_go_profile'] = actual['id_profile']
        report['id_reference_profile_rows_sha256'] = hashlib.sha256(json.dumps(projected, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        errors = [index for index, (a, b) in enumerate(zip(actual['rows'], projected)) if a != b]
        report['id_mismatch_indexes'] = errors
        report['id_mismatches'] = [{'index': index, 'input': identifiers[index], 'go': actual['rows'][index], 'reference': expected['rows'][index]} for index in errors[:64]]
        check('all owned ID validity and invariant lookup keys agree within the explicit transport profile', not errors)
        report['phase'] = 'version_comparison'
        pairs = comparison_cases()
        encoded = json.dumps(pairs).encode()
        check('owned comparison corpus stays within input and case budgets', len(encoded) <= 2 << 20 and len(pairs) <= 4096)
        actual = json.loads(command([work / 'go-oracle', '--compare'], 'compare owned versions with Go', encoded))
        expected = json.loads(command([dotnet, work / 'managed/Oracle.dll', 'compare'], 'compare owned versions with actual NuGet.Versioning', encoded))
        check('comparison references use this clean native source', actual['os'] == expected['os'] == 'linux' and actual['architecture'] == arch and expected['architecture'] == {'amd64': 'x64', 'arm64': 'arm64'}[arch] and actual['build'] == native['build'])
        check('comparison library and case count are observed', expected['version'] == report['nuget_library_version'] and len(actual['rows']) == len(expected['rows']) == len(pairs))
        errors = [index for index, (a, b) in enumerate(zip(actual['rows'], expected['rows'])) if a != b]
        report.update(comparison_cases=len(pairs), comparison_fixture_sha256=hashlib.sha256(encoded).hexdigest(), comparison_mismatch_indexes=errors,
                      comparison_mismatches=[{'index': index, 'input': json.loads(pairs[index]), 'go': actual['rows'][index], 'reference': expected['rows'][index]} for index in errors[:64]])
        check('all owned version precedence and invalid-input results agree with the actual SDK', not errors)
        report.update(status='passed', phase='complete')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['failure_type'] = type(error).__name__
        print('FAIL: NuGet library contract at phase=' + report['phase'] + '; private diagnostics retained', flush=True)
    finally:
        folder = ROOT / 'evidence' / datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        folder.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(report, indent=2).encode() + b'\n'
        (folder / ('nuget-version-contract-' + run + '.json')).write_bytes(encoded)
        (ROOT / '.cache/nuget-version-summary.json').write_bytes(encoded)
    if report['status'] != 'passed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
