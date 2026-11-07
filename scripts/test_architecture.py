# SPDX-License-Identifier: BUSL-1.1
"""Actual source fixtures retain the production exec boundary and narrow test exception."""
import pathlib,tempfile,unittest
from check_architecture import architecture_errors,TENANT_TABLES

class ArchitectureBoundary(unittest.TestCase):
 def setUp(self):
  self.temporary=tempfile.TemporaryDirectory(prefix='cratectl-architecture-')
  self.addCleanup(self.temporary.cleanup);self.root=pathlib.Path(self.temporary.name)
  self.write('internal/store/store.go','// SPDX-License-Identifier: BUSL-1.1\n'+','.join('"'+name+'"'for name in TENANT_TABLES))
 def write(self,name,text):
  p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
 def test_owned_integration_fixture_is_excluded_from_product_and_keeps_crypto_boundary(self):
  p='internal/server/go_module_export_collect_integration_test.go'
  self.write(p,'//go:build integration\n\n// SPDX-License-Identifier: BUSL-1.1\npackage server\nimport "os/exec"\n')
  self.assertEqual(architecture_errors(self.root),[])
  self.write(p,'//go:build integration\n\n// SPDX-License-Identifier: BUSL-1.1\npackage server\nimport "crypto/sha256"\n')
  self.assertTrue(any('crypto outside boundary'in e for e in architecture_errors(self.root)))
 def test_test_filename_or_tags_cannot_broaden_the_production_execution_exception(self):
  for name,tag in [('server.go','//go:build integration'),('other_integration_test.go','//go:build integration'),('go_module_export_collect_integration_test.go',''),('go_module_export_collect_integration_test.go','//go:build integration || production')]:
   with self.subTest(name=name,tag=tag):
    p=self.root/'internal/server';p.mkdir(exist_ok=True)
    for old in p.glob('*.go'):old.unlink()
    self.write('internal/server/'+name,tag+'\n\n// SPDX-License-Identifier: BUSL-1.1\npackage server\nimport "os/exec"\n')
    self.assertTrue(any('registry HTTP process may not invoke'in e for e in architecture_errors(self.root)))
 def test_core_ee_and_required_rls_checks_still_reject_real_source_fixtures(self):
  self.write('cmd/cratectl/main.go','package main\nimport "ctlplne.dev/cratectl/ee/authority"\n')
  self.write('internal/store/store.go','// SPDX-License-Identifier: BUSL-1.1\npackage store\n')
  errors=architecture_errors(self.root)
  self.assertTrue(any('core imports ee'in e for e in errors))
  self.assertTrue(any('missing license'in e for e in errors))
  self.assertTrue(any('missing forced RLS'in e for e in errors))

if __name__=='__main__':unittest.main()
