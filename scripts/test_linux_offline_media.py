#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1

import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from linux_offline_media import (ED25519_SPKI, IMAGE_FILES, MANIFEST, POSTGRES,
                                 PROFILE, SIGNATURE, aliases, contract, image_id, members,
                                 saved_image_configuration, verify_media)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class LinuxOfflineMediaTests(unittest.TestCase):
    def test_signed_media_has_exact_regular_inventory_and_independent_trust(self):
        with tempfile.TemporaryDirectory(prefix='cratectl-offline-media-test-') as root:
            root = Path(root)
            media = root / 'media'
            media.mkdir()
            key = root / 'key.pem'
            key_data = (b'-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(ED25519_SPKI + bytes(range(32)))
                        + b'\n-----END PUBLIC KEY-----\n')
            key.write_bytes(key_data)
            candidate = '1' * 40
            objects = {}
            for name in members('arm64'):
                data = ('owned test input ' + name).encode()
                (media / name).write_bytes(data)
                objects[name] = {'sha256': sha(data), 'bytes': len(data)}
            images = {name: {'tag': value, 'id': 'sha256:' + '0' * 64}
                      for name, value in aliases(candidate, 'arm64').items()}
            images['postgres']['source'] = POSTGRES
            manifest = {'schema': 1, 'profile': PROFILE, 'candidate': candidate,
                        'platform': 'linux/arm64', 'images': images, 'members': objects}
            (media / MANIFEST).write_bytes(json.dumps(manifest).encode())
            (media / SIGNATURE).write_bytes(bytes(64))
            with patch('linux_offline_media.command') as openssl:
                self.assertEqual(verify_media(media, 'arm64', key, sha(key_data)), manifest)
                self.assertEqual(openssl.call_args.args[:3], ('openssl', 'pkeyutl', '-verify'))
                with self.assertRaisesRegex(ValueError, 'approved public key digest differs'):
                    verify_media(media, 'arm64', key, '2' * 64)
                self.assertEqual(openssl.call_count, 1)
                with self.assertRaisesRegex(ValueError, 'closed media identity'):
                    verify_media(media, 'amd64', key, sha(key_data))
                extra = media / 'unreviewed'
                extra.touch()
                with self.assertRaisesRegex(ValueError, 'unexpected signed media'):
                    verify_media(media, 'arm64', key, sha(key_data))
                extra.unlink()
                image = media / IMAGE_FILES['registry']
                image.write_bytes(b'x' * objects[image.name]['bytes'])
                with self.assertRaisesRegex(ValueError, 'signed media bytes differ'):
                    verify_media(media, 'arm64', key, sha(key_data))
                image.unlink()
                image.symlink_to(key)
                with self.assertRaises(OSError):
                    verify_media(media, 'arm64', key, sha(key_data))

    def test_manifest_rejects_duplicate_fields_and_unknown_shape(self):
        for invalid in (b'{"schema":1,"schema":1}', b'[]', b'{"platform":"linux/amd64"}'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                contract(invalid, 'amd64')

    def test_image_inspection_accepts_legacy_cli_and_checks_returned_native_identity(self):
        digest = 'sha256:' + '1' * 64
        with patch('linux_offline_media.command', return_value=digest + ' linux/arm64') as docker:
            self.assertEqual(image_id(POSTGRES, 'linux/arm64'), digest)
            docker.assert_called_once_with('docker', 'image', 'inspect', '--format', '{{.Id}} {{.Os}}/{{.Architecture}}', POSTGRES)
            with self.assertRaisesRegex(ValueError, 'reviewed Linux platform'):
                image_id(POSTGRES, 'linux/amd64')
            docker.return_value += '\n' + digest + ' linux/arm64'
            with self.assertRaisesRegex(ValueError, 'reviewed Linux platform'):
                image_id(POSTGRES, 'linux/arm64')

    def test_saved_configuration_binds_native_bytes_and_one_tag(self):
        config = b'{"os":"linux","architecture":"arm64"}'
        checksum = sha(config)
        tag = 'cratectl-offline-postgres:fixture'
        with tempfile.TemporaryDirectory(prefix='cratectl-offline-inspection-test-') as folder:
            path = Path(folder) / 'image.tar'
            for name in ('blobs/sha256/' + checksum, checksum + '.json'):
                manifest = {'RepoTags': [tag], 'Config': name}

                def write_archive(config_body):
                    with tarfile.open(path, 'w:') as saved:
                        for key, data in [('manifest.json', json.dumps([manifest]).encode()), (name, config_body)]:
                            member = tarfile.TarInfo(key)
                            member.size = len(data)
                            saved.addfile(member, io.BytesIO(data))

                write_archive(config)
                self.assertEqual(saved_image_configuration(path, tag, 'linux/arm64'), 'sha256:' + checksum)
                with self.assertRaisesRegex(ValueError, 'exact tag'):
                    saved_image_configuration(path, tag + 'other', 'linux/arm64')
                with self.assertRaisesRegex(ValueError, 'digest or platform'):
                    saved_image_configuration(path, tag, 'linux/amd64')
                write_archive(config + b' ')
                with self.assertRaisesRegex(ValueError, 'digest or platform'):
                    saved_image_configuration(path, tag, 'linux/arm64')


if __name__ == '__main__':
    unittest.main()
