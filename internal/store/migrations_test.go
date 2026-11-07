// SPDX-License-Identifier: BUSL-1.1
package store

import "testing"

func TestAppliedMigrationDefinitionsStayImmutable(t *testing.T) {
	// Appending a step is allowed. Changing one of these requires a separate new
	// migration, rather than invalidating the receipts of deployed databases.
	expected := []string{
		"1e0f7b93d872f8ab83f85742000a6282f2722a0a338d8f2bc81755345ba66d16",
		"9e023c96c8cf33549ce81f1eac22551b5cdb6267d146f65d430ec254dc8b10b5",
		"44527dcd4be5177203e2b0eb93e5886a4dae437fbebf4cec14f7737ecb2f15d3",
		"8b287dda8e78324c44275d31850418d7e7166d9d6fe49c71d539dbd44a52d209",
		"0e835ed82b84cdd3d85858b0a76611b3ed6d387bbf55fee76d2abdf7c7f313a9",
		"557b3f6612a403e24d0c9726c9b048d62188b3e1a93bcb3f158616da30b1fe6c",
		"596eed6ab2287c8fd4b332d53f4d4867ceda7a1cebaf78e215da70b7eac6ff12",
		"fddb52ee509a46ce949d6c879feb47fc4603b7cb4de986b300e6f2b5243ae7dc",
		"5794b2b9420d489ce0530c22174047b0a608a14d45d5ea1fb4c563585af0ab04",
		"f8c9da14c14a2f18575ce1583a8cc94bd0b424740b96cc4367dcd016e96db0ba",
		"9fadadf954d8c0cdc5c905c367e49e1cffc31c82e72205f21a0e690653802feb",
		"2ba151f1b80253fbca009c157f5c72dbb68481ffdefe9dacf18f9e14a3069f71",
		"40eaf4d68b7cb6b867dba8451e001401a942014acf478bd03d5f4264cecb7daa",
		"b1900b2f1e3fd96955b5a40e52e9dd0f37eb0303bfda513dd77f518dac25bcb5",
		"e09da69fe6a5c3a653a3d3e86d85c2a08250b05fd099ac9bef73e11d74d9d325",
		"f455d6cc50784d62a3c8f14841d70462b116fa071e762294e78cba1c83d6f645",
		"7d786d8f03fa6ba8b75b2c114ff13ac2f288a1792856b94fc7e3e57a769ffead",
		"6c60ac3e1228e57b54cdd99397ef4bccfb91cbd942b3437e41a63441b9ad1035",
	}
	steps := currentMigrations()
	t.Logf("current schema %d checksum %s", steps[len(steps)-1].Version, hashMigration(steps[len(steps)-1]))
	for n, checksum := range expected {
		if len(steps) <= n || steps[n].Version != n+1 || hashMigration(steps[n]) != checksum {
			t.Fatalf("applied migration %d changed; append a new immutable step", n+1)
		}
	}
	steps[0].SQL = "modified by caller"
	if hashMigration(currentMigrations()[0]) != expected[0] {
		t.Fatal("caller changed the immutable plan")
	}
}
