# SPDX-License-Identifier: BUSL-1.1
"""Closed public observations from actual native Windows qualification only."""
import re

SOURCES = {
    'go.mod', 'go.sum', 'cmd/cratectl/main.go', 'cmd/cratectl/npm.go',
    'internal/configfile/config.go', 'internal/configfile/config_test.go',
    'internal/configfile/read_unix.go', 'internal/configfile/read_other.go',
    'internal/configfile/private_acl.go', 'internal/configfile/private_acl_test.go',
    'internal/configfile/read_windows.go', 'internal/configfile/read_windows_test.go',
    'internal/configfile/write.go', 'internal/configfile/write_other.go',
    'internal/configfile/write_windows.go', 'internal/configfile/write_test.go',
    'scripts/ci/windowscli/main.go', 'scripts/ci/windowscli/events.go', 'scripts/ci/windowscli/events_test.go',
    'scripts/ci/windowscli/process.go', 'scripts/ci/windowscli/process_windows.go',
    'scripts/ci/windowscli/process_other.go', 'scripts/ci/windowscli/process_windows_test.go',
}
TESTS = {
    'configuration': sorted([
        'TestPrivateWindowsACLRejectsBroadComplexUnprotectedAndUnboundedMetadata',
        'TestPrivateWindowsACLRestrictsEveryEffectiveGrantToOwnerAndOSAdministrators',
        'TestReadBytesRejectsOverflowingSentinelBudget',
        'TestWindowsConfigurationHandleDeniesConcurrentWriteAndRename',
        'TestWindowsConfigurationRejectsActualReparsePoint',
        'TestWindowsNativeCLIUsesPrivateConfigurationAndRefusesBroadCredentialsBeforeHTTP',
        'TestWindowsPrivateConfigurationRejectsBroadInheritedAndNullACLs',
        'TestWindowsPrivateConfigurationRejectsHardLinkAliasesAndAlternateStreams',
        'TestWindowsPrivateConfigurationUsesActualProtectedOwnerACL',
        'TestWriteNewPrivateKeepsExactBytesAndRefusesConcurrentOverwrite',
    ]),
    'driver': sorted([
        'TestWindowsEventsEnforceExactTopLevelCoverageAndOrder',
        'TestWindowsEventsRejectSkippedFailedMalformedAndUnboundedInput',
        'TestWindowsOwnedProcessBoundsOutput',
        'TestWindowsOwnedProcessCapturesExactOutput',
        'TestWindowsOwnedProcessTimeoutKillsOwnedDescendant',
    ]),
}
FIELDS = {'schema', 'profile', 'candidate', 'run_id', 'runner_os', 'runner_arch', 'status', 'go_version',
          'binary_sha256', 'build_identity', 'source_sha256', 'tests', 'events_sha256', 'managed_commands',
          'all_owned_jobs_empty', 'management_response_standin', 'windows_server_qualified',
          'offline_collection_qualified', 'goal_complete', 'broad_readiness'}


def hashes(value, keys):
    return (isinstance(value, dict) and set(value) == set(keys)
            and all(isinstance(h, str) and re.fullmatch('[a-f0-9]{64}', h) for h in value.values()))


def safe_windows_cli_contract(value):
    if (not isinstance(value, dict) or set(value) != FIELDS
            or type(value['schema']) is not int or value['schema'] != 1
            or value['profile'] != 'cratectl.windows.private-configuration.v1'
            or value['status'] != 'passed' or value['go_version'] != '1.27.4'
            or value['runner_os'] != 'Windows' or value['runner_arch'] not in ('X64', 'ARM64')
            or not isinstance(value['candidate'], str) or not re.fullmatch('[a-f0-9]{40}', value['candidate'])
            or not isinstance(value['run_id'], str) or not re.fullmatch('[1-9][0-9]{0,19}', value['run_id'])):
        raise ValueError('Unexpected native Windows fields or identity')
    if (type(value['managed_commands']) is not int or value['managed_commands'] != 5
            or value['all_owned_jobs_empty'] is not True or value['management_response_standin'] is not True
            or any(value[key] is not False for key in ('windows_server_qualified', 'offline_collection_qualified',
                                                       'goal_complete', 'broad_readiness'))):
        raise ValueError('Incomplete owned-job controls or unsupported Windows scope')
    if (not hashes(value['binary_sha256'], ('cli', 'driver', 'go'))
            or not hashes(value['source_sha256'], SOURCES)
            or not hashes(value['events_sha256'], TESTS)
            or value['tests'] != TESTS):
        raise ValueError('Incomplete Windows byte or native test inventory')
    identity = {'GOOS': 'windows', 'GOARCH': {'X64': 'amd64', 'ARM64': 'arm64'}[value['runner_arch']],
                'vcs.revision': value['candidate'], 'vcs.modified': 'false'}
    if value['build_identity'] != {'cli': identity, 'driver': identity}:
        raise ValueError('Windows binaries differ from the clean native candidate')
    return {key: value[key] for key in sorted(FIELDS)}
