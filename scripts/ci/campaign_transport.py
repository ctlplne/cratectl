#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Bounded read-only GitHub evidence transfer; downloaded bytes are never code."""
import hashlib
import io
import json
import re
import stat
import time
from urllib import error, parse, request
import zipfile
import zlib

REPOSITORY = 'ctlplne/cratectl'
JSON_BYTES = 2 << 20
LOG_BYTES = 32 << 20
TOTAL_BYTES = 256 << 20


class EvidenceError(ValueError):
    """Messages are fixed categories, safe to print without response content."""


def require(condition, category):
    if not condition:
        raise EvidenceError(category)


def strict_json(raw):
    require(isinstance(raw, bytes) and len(raw) <= JSON_BYTES, 'json_byte_limit')
    depth = 0
    quoted = escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            require(depth <= 64, 'json_depth_limit')
        elif char in (93, 125):
            depth -= 1
            require(depth >= 0, 'invalid_json')

    def object_pairs(pairs):
        require(len(pairs) <= 2048, 'json_field_limit')
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate_json_field')
            result[key] = value
        return result

    def constant(_):
        raise EvidenceError('invalid_json_number')

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=object_pairs,
                          parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError('invalid_json') from None


def artifact_json(raw, digest, member):
    require(isinstance(raw, bytes) and len(raw) <= JSON_BYTES, 'archive_byte_limit')
    require(isinstance(digest, str) and re.fullmatch('sha256:[a-f0-9]{64}', digest), 'artifact_digest_missing')
    require('sha256:' + hashlib.sha256(raw).hexdigest() == digest, 'artifact_digest_mismatch')
    require(raw.startswith(b'PK\x03\x04') and len(raw) >= 22 and raw[-22:-18] == b'PK\x05\x06', 'archive_framing')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            items = archive.infolist()
            require(len(items) == 1 and not archive.comment, 'archive_inventory')
            item = items[0]
            mode = (item.external_attr >> 16) & 0o170000
            require(item.filename == member and not item.is_dir() and mode in (0, stat.S_IFREG), 'archive_member')
            require(not item.flag_bits & 1 and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'archive_encoding')
            require(0 < item.file_size <= JSON_BYTES and item.compress_size <= JSON_BYTES, 'archive_expansion_limit')
            with archive.open(item) as source:
                body = source.read(JSON_BYTES + 1)
            require(len(body) == item.file_size, 'archive_expansion_limit')
            return strict_json(body), hashlib.sha256(body).hexdigest()
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, zlib.error):
        raise EvidenceError('invalid_archive') from None


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubEvidenceClient:
    def __init__(self, token, opener=None, clock=time.monotonic):
        require(isinstance(token, str) and 0 < len(token) <= 4096 and '\n' not in token and '\r' not in token, 'token_unavailable')
        self.token = token
        self.opener = opener or request.build_opener(NoRedirect())
        self.clock = clock
        self.deadline = clock() + 600
        self.remaining = TOTAL_BYTES
        self.requests = 0

    def _read(self, response, maximum):
        deadline = min(self.deadline, self.clock() + 60)
        body = bytearray()
        while True:
            require(self.clock() < deadline, 'response_time_limit')
            chunk = response.read(min(64 << 10, maximum + 1 - len(body)))
            if not chunk:
                return bytes(body)
            self.remaining -= len(chunk)
            body.extend(chunk)
            require(len(body) <= maximum and self.remaining >= 0, 'response_byte_limit')

    def get(self, route, maximum=JSON_BYTES, redirect=False):
        require(isinstance(route, str) and re.fullmatch(r'(?:runs\?head_sha=[a-f0-9]{40}&per_page=100|runs/[1-9][0-9]{0,17}/(?:jobs|artifacts)\?per_page=100|artifacts/[1-9][0-9]{0,17}/zip|jobs/[1-9][0-9]{0,17}/logs)', route), 'api_route')
        self.requests += 1
        require(self.requests <= 200 and self.clock() < self.deadline, 'request_limit')
        req = request.Request('https://api.github.com/repos/' + REPOSITORY + '/actions/' + route,
                              headers={'Authorization': 'Bearer ' + self.token,
                                       'Accept': 'application/vnd.github+json',
                                       'X-GitHub-Api-Version': '2022-11-28',
                                       'User-Agent': 'cratectl-campaign-acceptance'})
        try:
            try:
                response = self.opener.open(req, timeout=15)
            except error.HTTPError as exc:
                try:
                    require(redirect and exc.code == 302, 'api_request_failed')
                    location = exc.headers.get('Location', '')
                    require(len(location) <= 8192, 'download_redirect')
                    target = parse.urlsplit(location)
                    host = target.hostname or ''
                    require(target.scheme == 'https' and target.port in (None, 443)
                            and target.username is None and target.password is None
                            and not target.fragment and host.endswith(('.blob.core.windows.net', '.actions.githubusercontent.com')), 'download_redirect')
                finally:
                    exc.close()
                # A fresh request carries no Authorization/cookie/header from
                # the GitHub API, even though the API supplied the signed URL.
                self.requests += 1
                require(self.requests <= 200 and self.clock() < self.deadline, 'request_limit')
                response = self.opener.open(request.Request(location, headers={'User-Agent': 'cratectl-campaign-acceptance'}), timeout=15)
            with response:
                require(response.status == 200, 'api_status')
                return self._read(response, maximum)
        except EvidenceError:
            raise
        except error.HTTPError as exc:
            exc.close()
            raise EvidenceError('api_request_failed') from None
        except (OSError, ValueError, error.URLError):
            raise EvidenceError('api_request_failed') from None

    def listing(self, route, key):
        result = strict_json(self.get(route))
        require(isinstance(result, dict) and type(result.get('total_count')) is int
                and isinstance(result.get(key), list) and 0 <= result['total_count'] <= 100
                and result['total_count'] == len(result[key]), 'api_inventory_limit')
        return result[key]
