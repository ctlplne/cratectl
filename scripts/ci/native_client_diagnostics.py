# SPDX-License-Identifier: BUSL-1.1
"""Recognize fixed error markers without copying native-client output."""
import re

# These identifiers describe observed text, not a diagnosis of the root cause.
# Never return matched text, paths, URLs, usernames, or credential values.
MARKERS = {
    'credential_file': (b'credential file is not accessible',),
    'credential_read': (b'get credentials:', b'reading json file'),
    'credential_write': (b'writing auth file', b'error storing credentials'),
    'credential_rejected': (b'invalid username/password', b'authentication required', b'unauthorized'),
    'credential_helper': (b'credential helper', b'docker-credential-'),
    'permission_denied': (b'permission denied',),
    'missing_file': (b'no such file or directory',),
    'executable_missing': (b'executable file not found', b'command not found'),
    'sudo_password': (b'a password is required', b'a terminal is required'),
    'sudo_policy': (b'not allowed to execute', b'not in the sudoers'),
    'tls_http_mismatch': (b'http response to https',),
    'tls_certificate': (b'x509:', b'tls handshake'),
    'connection_refused': (b'connection refused',),
    'connection_timeout': (b'i/o timeout', b'context deadline exceeded'),
    'connection_dns': (b'no such host',),
    'registry_ping': (b'pinging container registry',),
    'registry_status': (b'invalid status code from registry', b'failed with status:', b'unexpected status'),
    'registry_auth_scheme': (b'unsupported auth', b'unsupported authentication', b'no supported www-authenticate'),
    'registry_token': (b'unable to retrieve auth token',),
    'manifest_missing': (b'manifest unknown',),
    'blob_missing': (b'blob unknown',),
    'platform_missing': (b'no matching manifest', b'no image found in manifest list'),
    'client_flag': (b'unknown flag:', b'unknown shorthand flag:'),
    'storage_driver': (b'graph driver', b'graphdriver', b'storage driver', b'vfs driver'),
    'storage_mount': (b'mount_program', b'error creating overlay mount'),
    'storage_database': (b'database configuration mismatch', b'database static dir', b'database storage'),
    'runtime_missing': (b'no valid executable', b'default oci runtime', b'oci runtime not found'),
    'runtime_setup': (b'oci runtime error', b'cannot re-exec process'),
    'user_namespace': (b'cannot clone:', b'creating user namespace', b'newuidmap', b'newgidmap'),
    'network_setup': (b'netavark', b'cni network', b'network backend'),
    'invalid_reference': (b'invalid reference format',),
    'json_parse': (b'invalid character', b'unexpected end of json input'),
}
CODES = frozenset(MARKERS)


def safe_client_diagnostics(output):
    """Bound both input and output; preserve only known literal marker IDs."""
    if not isinstance(output, bytes) or len(output) > 8 << 20:
        raise ValueError('native client diagnostics require bounded bytes')
    # A few error headers suffice. Do not classify echoed source/body content
    # in later lines as the first error (the browser classifier had that bug).
    error = re.search(rb'(?mi)^(?:error:|fatal:|sudo:)', output)
    start = error.start() if error else 0
    # Slice before splitting so many tiny log lines cannot multiply memory.
    lines = [line for line in output[start:start + 16384].splitlines() if line.strip()]
    header = b'\n'.join(lines[:4]).lower()
    return sorted(code for code, markers in MARKERS.items() if any(marker in header for marker in markers))
