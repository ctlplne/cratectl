# SPDX-License-Identifier: BUSL-1.1
import copy
import unittest
from journal_evidence import HASHES, STAGES, safe_journal_checkpoint_contract

def complete():
    return {'profile':'journal-checkpoint-openssl-v1', 'openssl_version':'3.0.16', 'completed':STAGES[:], **dict.fromkeys(HASHES, 'a'*64)}

class JournalEvidenceTest(unittest.TestCase):
    def test_complete_only_and_failed_prefix_distinct(self):
        self.assertEqual(safe_journal_checkpoint_contract(complete(), 'passed'), complete())
        incomplete = {**complete(), 'completed':STAGES[:-1]}
        self.assertEqual(safe_journal_checkpoint_contract(incomplete, 'failed'), incomplete)
        with self.assertRaises(ValueError):safe_journal_checkpoint_contract(incomplete, 'passed')
    def test_private_context_unknown_keys_and_unbounded_version_refused(self):
        for change in [{'private_key':'owned-private-standin'}, {'openssl_version':'3.0.16 private-context'}, {'openssl_version':'OpenSSL 3.0.16'}, {'openssl_version':'3.0.16\n'}, {'profile':'arbitrary'}, {'completed':STAGES[::-1]}, {'completed':STAGES+[STAGES[-1]]}]:
            with self.subTest(change=change), self.assertRaises(ValueError):safe_journal_checkpoint_contract({**complete(), **change}, 'passed')
        with self.assertRaises(ValueError):safe_journal_checkpoint_contract(complete(), 'unknown')
    def test_every_hash_and_control_is_required_for_pass(self):
        for key in HASHES:
            value = copy.deepcopy(complete());del value[key]
            with self.assertRaises(ValueError):safe_journal_checkpoint_contract(value, 'passed')
            with self.assertRaises(ValueError):safe_journal_checkpoint_contract({**complete(), key:'not-a-hash'}, 'passed')
        for n in range(len(STAGES)):
            with self.assertRaises(ValueError):safe_journal_checkpoint_contract({**complete(), 'completed':STAGES[:n]}, 'passed')

if __name__ == '__main__':unittest.main()
